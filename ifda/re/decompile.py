"""FR-RE-2: decompiled pseudocode by wrapping Ghidra headless.

Decompilation is an optional, heavyweight enrichment: Ghidra auto-analysis plus
the decompiler is slow (tens of seconds of JVM startup + analysis per binary), so
it is opt-in (`analyze(..., decompile=True)` / `--decompile`) and used narrowly —
we decompile only the functions a finding already points at, to give the analyst
C-like pseudocode next to the evidence.

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


def decompile(path: str, functions: list[str] | None = None,
              timeout: int = 900) -> dict[str, dict]:
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


def enrich_findings(binary_path: str, findings: list, timeout: int = 900) -> int:
    """Attach decompiled pseudocode to findings whose evidence lives in
    `binary_path`. Returns the number of findings enriched."""
    targets: set[str] = set()
    for f in findings:
        for ev in f.evidence:
            if ev.binary == binary_path and ev.function:
                targets.add(ev.function)
    if not targets:
        return 0
    code = decompile(binary_path, sorted(targets), timeout=timeout)
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
