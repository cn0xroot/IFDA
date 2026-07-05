"""Shared data model for the analysis core.

These dataclasses are the contract between stages (loader -> RE -> VUL ->
report). They are plain and JSON-serializable via :func:`to_dict` so the Go
service layer and the JSON report writer consume the same shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordering used for prioritization (higher = more severe).
SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class TriageState(str, Enum):
    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


@dataclass
class Symbol:
    name: str
    address: int
    size: int = 0
    kind: str = ""          # FUNC, OBJECT, ...
    imported: bool = False  # resolved via PLT/dynamic symbol, not defined here


@dataclass
class Function:
    name: str
    address: int
    size: int = 0
    # Addresses this function calls directly (resolved where possible to names).
    calls: list[str] = field(default_factory=list)
    # Imported/library calls reached from this function (e.g. "strcpy").
    callees_imported: list[str] = field(default_factory=list)


@dataclass
class Mitigations:
    """FR-RE-5: per-binary exploit mitigation posture."""
    nx: Optional[bool] = None
    canary: Optional[bool] = None
    relro: str = "none"      # "none" | "partial" | "full"
    pie: Optional[bool] = None
    fortify: Optional[bool] = None
    stripped: Optional[bool] = None


@dataclass
class BinaryInfo:
    """Result of loading + reverse engineering a single executable/library."""
    path: str
    sha256: str
    format: str = "elf"
    arch: str = ""           # arm, aarch64, mips, x86, x86_64, ...
    endian: str = ""         # little | big
    bits: int = 0            # 32 | 64
    abi: str = ""            # e.g. "System V", "gnueabi"
    libc: str = ""           # uclibc | musl | glibc | ""
    is_library: bool = False
    mitigations: Mitigations = field(default_factory=Mitigations)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    functions: list[Function] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)
    # Non-fatal problems encountered while analyzing this binary.
    warnings: list[str] = field(default_factory=list)


@dataclass
class Evidence:
    """Backing for a finding: a code location plus optional snippet/path."""
    binary: str
    function: str = ""
    address: int = 0
    snippet: str = ""              # disassembly / decompiled excerpt
    taint_path: list[str] = field(default_factory=list)  # source -> ... -> sink


@dataclass
class Finding:
    """FR-VUL-7: a single prioritized result."""
    id: str
    title: str
    vuln_class: str                # e.g. "buffer_overflow", "command_injection"
    severity: Severity
    confidence: float              # 0.0 - 1.0
    component: str                 # binary path or SBOM component
    rule: str                      # rule/detector id that produced this
    description: str = ""
    remediation: str = ""
    cve_ids: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    triage: TriageState = TriageState.NEW
    pseudocode: str = ""           # FR-RE-2: decompiled function (opt-in, Ghidra)

    def fingerprint(self) -> str:
        """Stable identity for triage persistence across re-scans (FR-VUL-8).

        Deliberately independent of severity/description so re-tuning detectors
        doesn't orphan an analyst's triage decision. Snippet and cve_ids *are*
        included: several detectors (secrets, import-presence dangerous-funcs,
        CVE correlation) don't have a function/address to pin the location to,
        so without the matched content itself every distinct hit in the same
        file collapses onto one id — corrupting both triage (one decision
        silently applies to unrelated findings) and the web UI's `x-for :key`
        (duplicate keys make list items appear/disappear on re-render).
        """
        import hashlib

        loc = ";".join(
            f"{e.binary}:{e.function}:{e.address:#x}:{e.snippet}" for e in self.evidence
        )
        cves = ",".join(sorted(self.cve_ids))
        h = hashlib.sha256(f"{self.rule}|{self.vuln_class}|{loc}|{cves}".encode())
        return h.hexdigest()[:16]


@dataclass
class ScriptInfo:
    """A non-ELF script file that was scanned (FR-INV-3), independent of
    whether anything was found in it — so a clean script is still visible
    somewhere, the way a clean binary still shows up in ``binaries``."""
    path: str
    kind: str            # "shell" | "php" | "python" | "lua"
    findings: int = 0


@dataclass
class ComponentInfo:
    """A software component detected in the firmware (FR-INV-5), the same
    extractor that feeds the CycloneDX SBOM (report/sbom.py) — surfaced live
    in the report too, so components without a correlated CVE are still
    visible instead of only reachable via a downloaded SBOM."""
    name: str
    version: str
    binaries: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)


@dataclass
class AnalysisReport:
    target: str
    binaries: list[BinaryInfo] = field(default_factory=list)
    scripts: list[ScriptInfo] = field(default_factory=list)
    components: list[ComponentInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    tool_version: str = ""
    generated_at: str = ""


def to_dict(obj) -> dict:
    """JSON-friendly dict, converting Enums to their values."""

    def convert(v):
        if isinstance(v, Enum):
            return v.value
        if isinstance(v, list):
            return [convert(x) for x in v]
        if isinstance(v, dict):
            return {k: convert(x) for k, x in v.items()}
        return v

    return convert(asdict(obj))
