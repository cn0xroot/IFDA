"""FR-VUL-1 (broad coverage): correlates the whole target tree against
cve-bin-tool's aggregated NVD/OSV/RedHat/GitLab-Advisory/Curl feeds.

This is a required dependency (see README.md/ENVIRONMENT.md) providing the
broad, EMBA-equivalent CVE coverage (350+ component checkers) that the small
curated `data/vuln_db.json` (cve.py's `correlate_cves`) never aimed to be. It
is a *tree-level* pass — one subprocess per `analyze()` call, not per binary —
because cve-bin-tool ships its own checkers and version sniffers and manages
its own local CVE database; running it per file would be redundant and slow.

It supplements rather than replaces `cve.py`'s fast, offline, deterministic
`correlate_cves()`, which stays in place for the unit test suite (no network
or multi-GB database needed) and for components outside cve-bin-tool's
checker set (e.g. uclibc).

If cve-bin-tool is missing (it is a required dependency but the analysis
pipeline still degrades to a *visible warning* rather than crashing the whole
job per NFR-USE-1 — a stale/offline machine shouldn't lose every other
finding) `cve_bin_tool_available()` returns False and callers should surface
that prominently rather than silently continuing as if nothing were missing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from ..model import ComponentInfo, Evidence, Finding, Severity

RULE = "cve-bin-tool"

_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.MEDIUM,  # unrated CVEs default to medium rather than being hidden
}

# cve-bin-tool remarks that mean "not actually a live issue here" when they
# show up unprompted (normally set via --triage-input-file, but some data
# sources annotate them directly).
_SKIP_REMARKS = {"FalsePositive", "NotAffected", "Mitigated"}

# First run per machine downloads/updates a multi-GB CVE database (NVD + OSV +
# RedHat + GitLab Advisory + Curl); subsequent runs just query the local cache.
_DEFAULT_TIMEOUT = 1800


def cve_bin_tool_available() -> bool:
    # IFDA_DISABLE_CVE_BIN_TOOL lets the unit test suite opt out of shelling
    # out to the real binary + multi-GB CVE database for every seeded fixture
    # (tests/conftest.py sets it); scan_target's own entry-parsing logic is
    # covered by a fixture-driven test instead, mirroring how the live Ghidra
    # test is opt-in via IFDA_GHIDRA_TEST rather than always-on.
    if os.environ.get("IFDA_DISABLE_CVE_BIN_TOOL") == "1":
        return False
    return shutil.which("cve-bin-tool") is not None


def list_checkers() -> list[str]:
    """Component checker names cve-bin-tool ships (350+), for display only.

    Returns [] if cve-bin-tool isn't installed rather than raising, so callers
    (e.g. the `ifda vulndb` CLI surface) can report availability + coverage in
    one shot without a separate try/except at every call site.
    """
    try:
        from cve_bin_tool.checkers import BUILTIN_CHECKERS
    except ImportError:
        return []
    return sorted(BUILTIN_CHECKERS.keys())


_SOURCE_LABELS = {
    "NVD": "NVD", "OSV": "OSV", "REDHAT": "RedHat", "GAD": "GitLab Advisory",
    "CURL": "Curl", "PURL2CPE": "PURL2CPE", "EPSS": "EPSS", "RSD": "RSD",
}


def db_stats() -> dict[str, int]:
    """Live per-data-source CVE entry counts from the local synced database
    (e.g. {"NVD": 287543, "RedHat": 23779, ...}).

    This is what actually answers "how many CVEs does this cover" — the
    number is typically in the tens/hundreds of thousands per source, which
    is why the web UI shows these counts rather than trying to render every
    individual CVE as a browsable table row. Returns {} if cve-bin-tool isn't
    installed or the local database hasn't been synced yet.
    """
    try:
        from cve_bin_tool.output_engine.json_output import db_entries_count
    except ImportError:
        return {}
    try:
        raw = db_entries_count()
    except Exception:
        return {}
    return {_SOURCE_LABELS.get(k, k): v for k, v in raw.items()}


def _run(target: str, timeout: int) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="ifda-cvebin-") as tmp:
        out_file = os.path.join(tmp, "report.json")
        cmd = [
            "cve-bin-tool", "-f", "json", "--detailed", "-o", out_file,
            "-u", "daily", "--disable-version-check", target,
        ]
        # Deliberately no -q: in cve-bin-tool 3.4, -q suppresses the JSON
        # report write itself (not just console logging), silently leaving
        # out_file missing. We capture_output below so this doesn't leak to
        # our own stdout/stderr anyway. Also note cve-bin-tool's own exit
        # code is 1 whenever it finds *any* CVE (a CI-friendly "fail the
        # build" convention) — success is judged by out_file existing, not
        # by the return code.
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return []
        if not os.path.isfile(out_file):
            return []
        try:
            with open(out_file) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return []


def scan_target(target: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[list[Finding], list[ComponentInfo]]:
    """Scan `target` with cve-bin-tool. Returns (findings, components).

    Empty on any failure (missing binary, timeout, bad output) — the caller
    decides whether/how to warn; this never raises.
    """
    if not cve_bin_tool_available():
        return [], []
    try:
        entries = _run(target, timeout)
    except Exception:
        return [], []

    findings: list[Finding] = []
    comps: dict[tuple[str, str], ComponentInfo] = {}
    for e in entries:
        product, version = e.get("product", ""), e.get("version", "")
        if not product or not version:
            continue
        if e.get("remarks") in _SKIP_REMARKS:
            continue
        key = (product, version)
        comp = comps.setdefault(key, ComponentInfo(name=product, version=version))
        location = e.get("location", "") or target
        if location not in comp.binaries:
            comp.binaries.append(location)

        cve = e.get("cve_number", "")
        if not cve:
            continue
        sev = _SEVERITY_MAP.get((e.get("severity") or "UNKNOWN").upper(), Severity.MEDIUM)
        f = Finding(
            id="",
            title=f"{product} {version}: {cve}",
            vuln_class="known_cve",
            severity=sev,
            confidence=0.7,
            component=f"{product}@{version}",
            rule=RULE,
            description=e.get("description", "") or e.get("comments", ""),
            remediation=f"Upgrade {product} to a fixed release.",
            cve_ids=[cve],
            evidence=[Evidence(binary=location)],
        )
        f.id = f.fingerprint()
        findings.append(f)

    return findings, list(comps.values())
