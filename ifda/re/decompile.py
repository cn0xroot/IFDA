"""FR-RE-2: decompiled pseudocode by wrapping Ghidra headless.

Decompilation is an optional, heavyweight enrichment: it is opt-in
(`analyze(..., decompile=True)` / `--decompile`) and used narrowly — we only
ever ask the post-script (ghidra_scripts/ifda_decompile.py) to decompile the
specific functions a finding already points at.

The real cost is Ghidra's *default auto-analysis* on `-import`, which walks the
whole binary (reference/data-type/switch analyzers, ...) before our post-script
ever runs — for a large real-world firmware binary (thousands of functions,
heavy C++ template instantiation) that can be many minutes, not the "tens of
seconds" a small test binary sees. Two bounds keep one file from stalling a
whole job: `-analysisTimeoutPerFile` caps Ghidra's *own* analysis phase (it
still runs the post-script afterward with whatever got recovered — ELF symbol
tables mean function boundaries are typically found in the first, cheapest
analyzer pass, so a capped analysis usually still finds our target functions);
`timeout` is the outer subprocess kill as a last resort if Ghidra itself hangs.
pipeline.py additionally runs this across binaries in parallel.

If Ghidra is not installed the wrapper degrades gracefully (returns nothing,
records a warning) per NFR-USE-1; the rest of the pipeline is unaffected.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

_SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "ghidra_scripts")
_SCRIPT_NAME = "ifda_decompile.py"

_COMMON_HOMES = ("/opt/ghidra", "/usr/share/ghidra", "/usr/local/ghidra")


def ghidra_home() -> str | None:
    """Locate a Ghidra install via $GHIDRA_HOME, common paths, or PATH."""
    env = os.environ.get("GHIDRA_HOME")
    candidates = [env] if env else []
    candidates += list(_COMMON_HOMES)
    for c in candidates:
        if c and os.path.isfile(os.path.join(c, "support", "analyzeHeadless")):
            return c
    onpath = shutil.which("analyzeHeadless")
    if onpath:  # .../ghidra/support/analyzeHeadless
        return os.path.dirname(os.path.dirname(onpath))
    return None


def ghidra_available() -> bool:
    return ghidra_home() is not None


def _parse_output(data: str) -> dict[str, dict]:
    """Parse the post-script's JSON into {function_name: {pseudocode, ...}}.

    Kept separate so it can be unit-tested against a captured fixture without
    needing Ghidra installed.
    """
    doc = json.loads(data)
    out: dict[str, dict] = {}
    for fn in doc.get("functions", []):
        name = fn.get("name")
        if name:
            out[name] = {
                "address": fn.get("address", ""),
                "signature": fn.get("signature", ""),
                "pseudocode": fn.get("pseudocode", ""),
            }
    return out


# Ghidra's own analysis-phase budget per file. Kept well under `timeout` so
# Ghidra has room to still run the post-script (with whatever analysis
# completed) instead of the outer subprocess kill discarding everything.
_DEFAULT_ANALYSIS_TIMEOUT = 120
_DEFAULT_TIMEOUT = 300


def decompile(path: str, functions: list[str] | None = None,
              timeout: int = _DEFAULT_TIMEOUT,
              analysis_timeout: int = _DEFAULT_ANALYSIS_TIMEOUT) -> dict[str, dict]:
    """Decompile a binary (optionally only `functions`) to pseudocode.

    Returns {function_name: {address, signature, pseudocode}}. Empty dict if
    Ghidra is unavailable or the run fails.
    """
    home = ghidra_home()
    if not home:
        return {}
    headless = os.path.join(home, "support", "analyzeHeadless")

    proj = tempfile.mkdtemp(prefix="ifda-ghidra-")
    try:
        out_file = os.path.join(proj, "decomp.json")
        func_arg = ",".join(functions) if functions else ""
        cmd = [
            headless, proj, "ifda_proj",
            "-import", os.path.abspath(path),
            "-analysisTimeoutPerFile", str(analysis_timeout),
            "-scriptPath", _SCRIPT_DIR,
            "-postScript", _SCRIPT_NAME, out_file, func_arg,
            "-deleteProject",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return {}
        if not os.path.isfile(out_file):
            return {}
        try:
            with open(out_file, "r") as fh:
                return _parse_output(fh.read())
        except (OSError, ValueError):
            return {}
    finally:
        shutil.rmtree(proj, ignore_errors=True)


def enrich_findings(binary_path: str, findings: list,
                     timeout: int = _DEFAULT_TIMEOUT,
                     analysis_timeout: int = _DEFAULT_ANALYSIS_TIMEOUT) -> int:
    """Attach decompiled pseudocode to findings whose evidence lives in
    `binary_path`. Returns the number of findings enriched."""
    targets: set[str] = set()
    for f in findings:
        for ev in f.evidence:
            if ev.binary == binary_path and ev.function:
                targets.add(ev.function)
    if not targets:
        return 0
    code = decompile(binary_path, sorted(targets), timeout=timeout, analysis_timeout=analysis_timeout)
    if not code:
        return 0
    n = 0
    for f in findings:
        if f.pseudocode:
            continue
        for ev in f.evidence:
            if ev.binary == binary_path and ev.function in code:
                f.pseudocode = code[ev.function]["pseudocode"]
                n += 1
                break
    return n
