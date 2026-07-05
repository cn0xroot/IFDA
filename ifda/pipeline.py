"""Orchestrates RE + VUL over a target (a single binary or an extracted tree).

This is the Python-core entrypoint the Go service layer calls per artifact. It
assumes ingestion/extraction (FR-ING/FR-EXT) already produced files on disk.
"""

from __future__ import annotations

import datetime
import os

from . import __version__
from .model import AnalysisReport, BinaryInfo, ScriptInfo, ComponentInfo
from .loader import is_elf, load_elf
from .re import detect_mitigations, disassemble
from .vuln import (
    detect_dangerous_functions,
    detect_taint_paths,
    correlate_cves,
    cve_bin_tool_available,
    scan_target as cve_bin_tool_scan,
    prioritize,
    TriageStore,
)
from .vuln.cve import extract_sbom
from .vuln.crossbinary import detect_cross_binary_taint
from .inventory import scan_secrets
from .scripts import scan_scripts, scan_lang_scripts, list_scripts, list_lang_scripts
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
            # Real firmware trees carry device nodes (e.g. dev/console),
            # FIFOs, and sockets. is_elf() opens+reads the path unconditionally;
            # opening a character device like /dev/console with no controlling
            # terminal blocks forever on read(), silently wedging the whole
            # scan at "enumerating binaries" with zero progress. Every other
            # tree-walker in this codebase (secrets.py, shell.py, langs.py)
            # already guards with isfile() — this one was missing it.
            if not os.path.isfile(p):
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

    # Broad CVE coverage via cve-bin-tool (FR-VUL-1), a required dependency
    # (see README.md) providing EMBA-equivalent NVD/OSV/RedHat/GitLab
    # Advisory/Curl correlation across 350+ components — one tree-level pass,
    # not per binary, since cve-bin-tool has its own checkers/version sniffers
    # and manages its own local CVE database.
    emit("cve-scan", 80, "cve-bin-tool component/CVE scan")
    cvebin_components: list[ComponentInfo] = []
    if cve_bin_tool_available():
        try:
            cvebin_findings, cvebin_components = cve_bin_tool_scan(target)
            report.findings.extend(cvebin_findings)
        except Exception as e:
            if report.binaries:
                report.binaries[0].warnings.append(f"cve-bin-tool scan failed: {e}")
    elif report.binaries:
        report.binaries[0].warnings.append(
            "cve-bin-tool not installed (required dependency; pip install cve-bin-tool) — "
            "CVE coverage limited to the small built-in banner DB")

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
        for p in list_scripts(target):
            report.scripts.append(ScriptInfo(path=p, kind="shell"))
    except Exception:
        pass

    # PHP / Python / Lua script injection (FR-INV-3 + FR-VUL).
    emit("scripts-lang", 92, "php/python/lua injection")
    try:
        report.findings.extend(scan_lang_scripts(target))
        for p, lang in list_lang_scripts(target):
            report.scripts.append(ScriptInfo(path=p, kind=lang))
    except Exception:
        pass

    # Filesystem hardening / config checks (FR-INV / attack surface).
    emit("filesystem", 95, "hardening checks")
    try:
        report.findings.extend(scan_filesystem(target))
    except Exception:
        pass

    # Tally each script's own finding count now that every stage that can
    # produce a script-attributed finding (secrets, cmd-injection, hardening)
    # has run, so a clean script is still listed (with findings=0) instead of
    # being invisible whenever nothing was wrong with it.
    if report.scripts:
        counts: dict[str, int] = {}
        script_paths = {s.path for s in report.scripts}
        for f in report.findings:
            if f.component in script_paths:
                counts[f.component] = counts.get(f.component, 0) + 1
        for s in report.scripts:
            s.findings = counts.get(s.path, 0)

    # Software component inventory (FR-INV-5), the same extractor that feeds
    # the CycloneDX SBOM export — surfaced live so components without a
    # correlated CVE are still visible, not just reachable via a download.
    comps: dict[tuple[str, str], ComponentInfo] = {}
    for info in report.binaries:
        for comp in extract_sbom(info):
            key = (comp.name, comp.version)
            c = comps.setdefault(key, ComponentInfo(name=comp.name, version=comp.version))
            if info.path not in c.binaries:
                c.binaries.append(info.path)
    # Fold in cve-bin-tool's broader component coverage — it finds far more
    # components than the small banner-regex extractor above (e.g. curl,
    # libpng, wpa_supplicant, ...), not just the ones it also flagged a CVE
    # for. cve_ids is derived uniformly below from report.findings either way.
    for c in cvebin_components:
        key = (c.name, c.version)
        existing = comps.setdefault(key, ComponentInfo(name=c.name, version=c.version))
        for b in c.binaries:
            if b not in existing.binaries:
                existing.binaries.append(b)
    cves_by_component: dict[str, list[str]] = {}
    for f in report.findings:
        if f.cve_ids:
            cves_by_component.setdefault(f.component, []).extend(f.cve_ids)
    for c in comps.values():
        c.cve_ids = sorted(set(cves_by_component.get(f"{c.name}@{c.version}", [])))
    report.components = list(comps.values())

    # Apply persisted triage, then drop muted, then prioritize (FR-VUL-7/8).
    if triage_path:
        store = TriageStore(triage_path)
        store.apply(report.findings)
        report.findings = store.active(report.findings)

    report.findings = prioritize(report.findings)

    # Optional Ghidra pseudocode enrichment of surviving findings (FR-RE-2).
    # Ghidra's own default auto-analysis (not our targeted decompile) is what
    # makes this slow for real firmware binaries, so two things bound the
    # wall-clock cost: enrich_findings/decompile() cap Ghidra's per-file
    # analysis time internally, and here binaries are processed in parallel
    # (each is an independent subprocess, so this is a straight wall-time win)
    # and skipped entirely if nothing in them needs decompiling.
    if decompile:
        try:
            from .re.decompile import ghidra_available, enrich_findings

            if ghidra_available():
                target_paths = {ev.binary for f in report.findings for ev in f.evidence if ev.function}
                targets = [info for info in report.binaries if info.path in target_paths]
                if targets:
                    import concurrent.futures

                    workers = min(4, len(targets))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                        futures = {pool.submit(enrich_findings, info.path, report.findings): info
                                   for info in targets}
                        done = 0
                        for fut in concurrent.futures.as_completed(futures):
                            done += 1
                            info = futures[fut]
                            emit("decompile", 97 + 3.0 * done / len(targets),
                                 f"{done}/{len(targets)} {info.path}")
                            try:
                                fut.result()
                            except Exception as e:
                                info.warnings.append(f"decompile failed: {e}")
                else:
                    emit("decompile", 97, "no findings need decompilation")
            elif report.binaries:
                emit("decompile", 97, "ghidra not found")
                report.binaries[0].warnings.append(
                    "decompilation requested but Ghidra not found (set GHIDRA_HOME)")
        except Exception as e:
            if report.binaries:
                report.binaries[0].warnings.append(f"decompile stage failed: {e}")

    emit("done", 100, f"{len(report.findings)} findings")
    return report
