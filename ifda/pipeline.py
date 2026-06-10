"""Orchestrates RE + VUL over a target (a single binary or an extracted tree).

This is the Python-core entrypoint the Go service layer calls per artifact. It
assumes ingestion/extraction (FR-ING/FR-EXT) already produced files on disk.
"""

from __future__ import annotations

import datetime
import os

from . import __version__
from .model import AnalysisReport, BinaryInfo
from .loader import is_elf, load_elf
from .re import detect_mitigations, disassemble
from .vuln import (
    detect_dangerous_functions,
    detect_taint_paths,
    correlate_cves,
    prioritize,
    TriageStore,
)
from .vuln.crossbinary import detect_cross_binary_taint
from .inventory import scan_secrets
from .scripts import scan_scripts, scan_lang_scripts
from .fs import scan_filesystem


def analyze_binary(path: str) -> tuple[BinaryInfo, list]:
    """Run per-binary RE + VUL on one ELF. Returns (info, findings)."""
    info, findings, _disasm = _analyze_unit(path)
    return info, findings


def _analyze_unit(path: str):
    """Internal: like analyze_binary but also returns the DisasmResult so the
    global cross-binary pass can reuse it instead of disassembling twice."""
    from .re.disasm import DisasmResult

    info = load_elf(path)
    if not info.arch:
        return info, [], DisasmResult()

    try:
        info.mitigations = detect_mitigations(path)
    except Exception as e:  # never let one stage sink the binary (NFR-USE-1)
        info.warnings.append(f"mitigation detection failed: {e}")

    try:
        disasm = disassemble(path, info)
    except Exception as e:
        info.warnings.append(f"disassembly failed: {e}")
        disasm = DisasmResult()

    info.functions = disasm.functions

    findings = []
    for stage in (
        lambda: detect_dangerous_functions(info, disasm),
        lambda: detect_taint_paths(info, disasm),
        lambda: correlate_cves(info),
    ):
        try:
            findings.extend(stage())
        except Exception as e:
            info.warnings.append(f"vuln stage failed: {e}")
    return info, findings, disasm


def iter_binaries(target: str):
    """Yield ELF file paths under a target file or directory."""
    if os.path.isfile(target):
        if is_elf(target):
            yield target
        return
    for root, _dirs, names in os.walk(target):
        for n in names:
            p = os.path.join(root, n)
            if os.path.islink(p):
                continue
            if is_elf(p):
                yield p


def analyze(target: str, triage_path: str | None = None, progress=None,
            decompile: bool = False) -> AnalysisReport:
    """Analyze a binary or extracted tree.

    ``progress`` is an optional callable receiving dicts
    ``{"stage", "pct", "detail"}`` so a service layer can stream task progress
    (the Go orchestrator passes one through ``--progress``).

    ``decompile`` opts into Ghidra pseudocode enrichment of findings (FR-RE-2);
    slow and degrades to a no-op if Ghidra is not installed.
    """

    def emit(stage: str, pct: float, detail: str = "") -> None:
        if progress:
            try:
                progress({"stage": stage, "pct": int(round(pct)), "detail": detail})
            except Exception:
                pass

    report = AnalysisReport(
        target=target,
        tool_version=__version__,
        generated_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    )

    emit("scan", 0, "enumerating binaries")
    paths = list(iter_binaries(target))
    total = len(paths) or 1

    units = []
    for i, path in enumerate(paths):
        emit("disassemble", 5 + 70.0 * i / total, path)
        info, findings, disasm = _analyze_unit(path)
        report.binaries.append(info)
        report.findings.extend(findings)
        units.append((info, disasm))

    # Global cross-binary taint over the whole set (FR-VUL-5).
    if len(units) > 1:
        emit("cross-binary", 78, "linking call graphs")
        try:
            report.findings.extend(detect_cross_binary_taint(units))
        except Exception as e:
            report.binaries[0].warnings.append(f"cross-binary stage failed: {e}")

    # Embedded secrets / credentials across the whole tree (FR-INV-4).
    emit("secrets", 84, "scanning for keys/credentials")
    try:
        report.findings.extend(scan_secrets(target))
    except Exception:
        pass

    # Shell / CGI script command-injection analysis (FR-INV-3 + FR-VUL).
    emit("scripts", 90, "shell/CGI command injection")
    try:
        report.findings.extend(scan_scripts(target))
    except Exception:
        pass

    # PHP / Python / Lua script injection (FR-INV-3 + FR-VUL).
    emit("scripts-lang", 92, "php/python/lua injection")
    try:
        report.findings.extend(scan_lang_scripts(target))
    except Exception:
        pass

    # Filesystem hardening / config checks (FR-INV / attack surface).
    emit("filesystem", 95, "hardening checks")
    try:
        report.findings.extend(scan_filesystem(target))
    except Exception:
        pass

    # Apply persisted triage, then drop muted, then prioritize (FR-VUL-7/8).
    if triage_path:
        store = TriageStore(triage_path)
        store.apply(report.findings)
        report.findings = store.active(report.findings)

    report.findings = prioritize(report.findings)

    # Optional Ghidra pseudocode enrichment of surviving findings (FR-RE-2).
    if decompile:
        emit("decompile", 97, "ghidra pseudocode")
        try:
            from .re.decompile import ghidra_available, enrich_findings

            if ghidra_available():
                for info in report.binaries:
                    enrich_findings(info.path, report.findings)
            elif report.binaries:
                report.binaries[0].warnings.append(
                    "decompilation requested but Ghidra not found (set GHIDRA_HOME)")
        except Exception as e:
            if report.binaries:
                report.binaries[0].warnings.append(f"decompile stage failed: {e}")

    emit("done", 100, f"{len(report.findings)} findings")
    return report
