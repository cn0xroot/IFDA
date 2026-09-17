"""FR-ING/FR-EXT: firmware identification and extraction, via `moria`
(https://github.com/nmatt0/moria) -- an external, opt-in tool, same posture as
Ghidra/cve-bin-tool elsewhere in this codebase (NFR-USE-1: missing tool means
a visible "not available" rather than a crash).

This module never runs the deep RE/VUL pipeline itself -- it only turns a raw
firmware image (a single file: a flash dump, a partition image, a vendor
update package) into a set of candidate extracted directory trees, each
tagged with what moria found there and whether the extraction actually
produced usable content. Picking which of those trees (if more than one) is
"the" rootfs to hand to `ifda.cli analyze` is a human decision, deliberately
not automated here: real multi-partition firmware (dual-bank A/B images,
bootloader + kernel + rootfs in one dump) routinely has more than one
filesystem region, and guessing wrong (e.g. picking an inactive backup bank)
would silently analyze the wrong thing.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

_DEFAULT_TIMEOUT = 20 * 60  # generous: moria is format-aware unpacking, not
# disassembly, but a multi-GB flash dump with many nested containers can
# still take a while; this is a safety net against a truly hung run, same
# role as job.go's -analyze-timeout for the analyze subprocess.

# The repo carries moria's source as a git submodule at <repo>/moria, built
# out-of-source into <repo>/moria/build (see scripts/build-moria.sh). Nothing
# requires that build to exist -- a system-wide install on PATH works exactly
# as before -- but when it does exist it wins, so a checkout that pinned a
# particular moria commit actually runs that commit rather than whatever
# version happens to be installed on the host.
_REPO_ROOT = Path(__file__).resolve().parents[2]
_VENDORED = _REPO_ROOT / "moria" / "build" / "moria"


def moria_path() -> str | None:
    """Absolute path to the moria binary to use, or None if there isn't one.

    Resolution order, first hit wins:

    1. ``$IFDA_MORIA`` -- an explicit override, for pointing at a build
       somewhere else entirely (a release download, a second checkout).
    2. ``<repo>/moria/build/moria`` -- the in-tree build of the pinned
       submodule.
    3. ``moria`` on ``PATH`` -- a system or user install.
    """
    env = os.environ.get("IFDA_MORIA", "").strip()
    if env:
        # An override that points at nothing is a configuration mistake worth
        # surfacing as "not available" rather than silently falling through to
        # a different binary than the one that was asked for.
        return env if os.path.isfile(env) and os.access(env, os.X_OK) else None
    if _VENDORED.is_file() and os.access(_VENDORED, os.X_OK):
        return str(_VENDORED)
    return shutil.which("moria")


def moria_version() -> str:
    """``moria --version`` output, or "" when it can't be determined.

    Used for the "which moria is this actually running" line in the service
    log and the extract job's metadata -- with three possible sources for the
    binary, "moria is available" on its own is not enough to reproduce a run.
    """
    exe = moria_path()
    if not exe:
        return ""
    try:
        proc = subprocess.run([exe, "--version"], capture_output=True, timeout=10, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return proc.stdout.decode(errors="replace").strip()


def moria_available() -> bool:
    return moria_path() is not None


def identify_and_extract(target: str, out_dir: str, timeout: int = _DEFAULT_TIMEOUT) -> dict:
    """Runs `moria -j -e` against `target`, extracting into `out_dir`.

    Returns {"source", "size", "summary", "regions": [...]}, where each
    region merges moria's identification metadata (type, category,
    confidence, description) with its extraction outcome (status, extracted
    path, file/dir counts). `usable` is true iff the region actually
    extracted (status "ok" or "partial" -- moria's own vocabulary for
    "some content recovered", partial meaning truncated by a size/depth
    guard, not corrupt) and has a path underneath `out_dir` worth exposing
    for a human to pick as an analyze target.

    Never raises: any failure (moria missing, timeout, bad output) returns
    an empty regions list with an "error" key set, same NFR-USE-1 posture as
    every other optional external tool here.
    """
    exe = moria_path()
    if not exe:
        return {"source": target, "regions": [], "error": "moria not installed"}

    os.makedirs(out_dir, exist_ok=True)
    cmd = [exe, "-j", "-e", target, "-C", out_dir]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"source": target, "regions": [], "error": f"moria failed to run: {e}"}

    try:
        doc = json.loads(proc.stdout)
    except ValueError:
        # moria writes a plain-text reason to stderr for a usage error (e.g.
        # "--extract takes a single file, not a directory" -- it only
        # unpacks a raw image, not an already-extracted tree) rather than
        # JSON on stdout; surface that reason directly instead of wrapping
        # it behind a generic "no valid JSON" preamble.
        stderr_tail = proc.stderr.decode(errors="replace").strip()[-500:] if proc.stderr else ""
        return {"source": target, "regions": [], "error": stderr_tail or "moria produced no output"}

    return {
        "source": doc.get("path", target),
        "size": doc.get("size", 0),
        "summary": doc.get("summary", ""),
        "regions": _merge_regions(doc, out_dir),
    }


def _merge_regions(doc: dict, out_dir: str) -> list[dict]:
    findings_by_offset = {f["offset"]: f for f in doc.get("findings", [])}
    extracted = doc.get("extraction", {}).get("extracted", [])

    regions = []
    for e in extracted:
        finding = findings_by_offset.get(e["offset"], {})
        status = e.get("status", "")
        usable = status in ("ok", "partial") and (e.get("files", 0) or e.get("dirs", 0))
        regions.append({
            "offset": e["offset"],
            "type": e.get("type", finding.get("type", "?")),
            "category": finding.get("category", ""),
            "confidence": finding.get("confidence"),
            "description": finding.get("description", ""),
            "status": status,
            "usable": bool(usable),
            "path": os.path.join(out_dir, e["root"]) if usable else "",
            # region_size: how big this region is *in the source image*
            # (the compressed/on-disk footprint moria's identify pass
            # measured at this offset). bytes: total size of the content
            # moria actually decompressed/wrote out -- a squashfs's region_size
            # is its compressed size, its bytes is the sum of every file it
            # unpacked, and these are legitimately different numbers (usually
            # bytes > region_size for a compressed filesystem). Keep both,
            # clearly separate -- collapsing them into one "size" is what
            # made the extracted-content total look like a wrong region size.
            "region_size": finding.get("size", 0),
            "files": e.get("files", 0),
            "dirs": e.get("dirs", 0),
            "bytes": e.get("bytes", 0),
            "warnings": e.get("warnings", []),
        })
    regions.sort(key=lambda r: r["offset"])
    return regions
