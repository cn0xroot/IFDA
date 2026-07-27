"""FR-VUL-1: known-vulnerability correlation.

Extracts a coarse SBOM (component + version) from binary strings, then matches
it against an offline vulnerability DB. Offline by design (NFR-DEP-1: no
mandatory third-party calls); the DB file is replaceable independently of code
(NFR-USE-2). The same component list feeds the SBOM output (FR-INV-5/FR-REP-2).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files

from ..model import BinaryInfo, Finding, Evidence, Severity

RULE = "known-cve"

# Banner patterns -> component key in the DB. Order matters (first match wins).
_BANNERS: list[tuple[str, re.Pattern]] = [
    ("busybox",  re.compile(r"BusyBox v([0-9]+\.[0-9]+(?:\.[0-9]+)?)")),
    ("dropbear", re.compile(r"[Dd]ropbear[ _]v?([0-9]{4}\.[0-9]+)")),
    ("openssl",  re.compile(r"OpenSSL ([0-9]+\.[0-9]+\.[0-9]+[a-z]?)")),
    ("uclibc",   re.compile(r"uClibc(?:-ng)?[ -]?([0-9]+\.[0-9]+\.[0-9]+)")),
    ("lighttpd", re.compile(r"lighttpd/([0-9]+\.[0-9]+\.[0-9]+)")),
]


@dataclass
class Component:
    name: str
    version: str
    evidence: str


def extract_sbom(info: BinaryInfo) -> list[Component]:
    comps: dict[tuple[str, str], Component] = {}
    for s in info.strings:
        for key, pat in _BANNERS:
            m = pat.search(s)
            if m:
                comps[(key, m.group(1))] = Component(key, m.group(1), s.strip())
    return list(comps.values())


def load_db() -> dict:
    raw = files("ifda.data").joinpath("vuln_db.json").read_text()
    db = json.loads(raw)
    db.pop("_meta", None)
    return db


def _ver_tuple(v: str) -> tuple:
    # Split into numeric + optional alpha suffix, comparable lexicographically.
    parts = re.findall(r"\d+|[a-z]+", v)
    return tuple(int(p) if p.isdigit() else p for p in parts)


def _vulnerable(version: str, entry: dict) -> bool:
    if "versions" in entry:
        return version in entry["versions"]
    if "version_lt" not in entry and "version_ge" not in entry:
        return False
    try:
        v = _ver_tuple(version)
        if "version_lt" in entry and not v < _ver_tuple(entry["version_lt"]):
            return False
        if "version_ge" in entry and not v >= _ver_tuple(entry["version_ge"]):
            return False
        return True
    except Exception:
        return False


def correlate_kernel_cve(kernel_version: str, db: dict | None = None) -> list[Finding]:
    """FR-VUL-1 for the kernel itself.

    `report.kernel_version` comes from inventory/firmware_meta.py's own
    banner/vermagic scan, which is decoupled from (and more robust on real
    firmware than) cve-bin-tool's per-binary linux_kernel checker: that
    checker's version regex requires the compiler string right after the
    kernel version to match a narrow character class, which real toolchain
    banners routinely violate (e.g. Ubuntu's package suffix
    "13.3.0-6ubuntu2~24.04" has a '~', so the whole banner silently fails to
    match). This is a separate, small curated correlation against the same
    `versions`/`version_lt`/`version_ge` schema `correlate_cves` uses, kept
    intentionally short (headline, broadly-applicable kernel CVEs) rather
    than trying to replicate a full kernel CVE feed offline.
    """
    if not kernel_version:
        return []
    db = db if db is not None else load_db()
    findings: list[Finding] = []
    for entry in db.get("linux_kernel", []):
        if not _vulnerable(kernel_version, entry):
            continue
        ev = Evidence(binary="", snippet=f"kernel version {kernel_version}")
        f = Finding(
            id="",
            title=f"linux_kernel {kernel_version}: {entry['cve']}",
            vuln_class="known_cve",
            severity=Severity(entry.get("severity", "medium")),
            confidence=0.6,
            component=f"linux_kernel@{kernel_version}",
            rule=RULE,
            description=entry.get("summary", ""),
            remediation=f"Upgrade the kernel to a release with {entry['cve']} fixed.",
            cve_ids=[entry["cve"]],
            evidence=[ev],
        )
        f.id = f.fingerprint()
        findings.append(f)
    return findings


def correlate_cves(info: BinaryInfo, db: dict | None = None) -> list[Finding]:
    db = db if db is not None else load_db()
    findings: list[Finding] = []
    for comp in extract_sbom(info):
        for entry in db.get(comp.name, []):
            if not _vulnerable(comp.version, entry):
                continue
            ev = Evidence(binary=info.path, snippet=comp.evidence)
            f = Finding(
                id="",
                title=f"{comp.name} {comp.version}: {entry['cve']}",
                vuln_class="known_cve",
                severity=Severity(entry.get("severity", "medium")),
                confidence=0.7,
                component=f"{comp.name}@{comp.version}",
                rule=RULE,
                description=entry.get("summary", ""),
                remediation=f"Upgrade {comp.name} to a fixed release.",
                cve_ids=[entry["cve"]],
                evidence=[ev],
            )
            f.id = f.fingerprint()
            findings.append(f)
    return findings
