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
    if "version_lt" in entry:
        try:
            return _ver_tuple(version) < _ver_tuple(entry["version_lt"])
        except Exception:
            return False
    return False


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
