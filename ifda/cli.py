"""CLI entrypoint (FR-RE-7 scriptable surface / FR-INT-1 precursor).

    ifda analyze <path> [--json out.json] [--md out.md] [--triage triage.json]
    ifda triage <triage.json> <finding_id> <state>
"""

from __future__ import annotations

import argparse
import json
import sys

from .pipeline import analyze
from .report import write_json, render_markdown, render_cyclonedx
from .report.json_report import to_json_str
from .model import TriageState
from .vuln import TriageStore
from .vuln.cve import load_db
from .vuln.cve_bin_tool import cve_bin_tool_available, list_checkers, db_stats


def _cmd_analyze(args) -> int:
    progress = None
    if args.progress:
        # Machine-readable progress for the service layer: one JSON object per
        # line on stderr, prefixed so it is trivially separable from other logs.
        def progress(ev):
            sys.stderr.write("@@IFDA@@" + json.dumps(ev) + "\n")
            sys.stderr.flush()

    report = analyze(args.target, triage_path=args.triage, progress=progress,
                     decompile=args.decompile)

    if args.json:
        write_json(report, args.json)
    if args.md:
        with open(args.md, "w") as fh:
            fh.write(render_markdown(report))
    if args.sbom:
        with open(args.sbom, "w") as fh:
            fh.write(render_cyclonedx(report))

    if not args.json and not args.md and not args.sbom:
        # Default: JSON to stdout for piping / API parity.
        print(to_json_str(report))
    else:
        crit = sum(1 for f in report.findings if f.severity.value in ("critical", "high"))
        print(
            f"Analyzed {len(report.binaries)} binaries, "
            f"{len(report.findings)} findings ({crit} high/critical).",
            file=sys.stderr,
        )
    return 0


def _cmd_triage(args) -> int:
    store = TriageStore(args.store)
    store.set(args.finding_id, TriageState(args.state))
    print(f"Set {args.finding_id} -> {args.state}")
    return 0


def _cmd_vulndb(args) -> int:
    """Report what the CVE-correlation stages actually cover: the small
    curated fallback DB (offline, always available) plus cve-bin-tool's much
    broader checker set (FR-VUL-1), if installed. Consumed by the Go
    service's GET /api/vulndb so the web UI doesn't imply coverage is only
    the curated DB's handful of components."""
    checkers = list_checkers()
    counts = db_stats()
    doc = {
        "curated": load_db(),
        "cve_bin_tool": {
            "available": cve_bin_tool_available(),
            "checkers": checkers,
            "checker_count": len(checkers),
            "data_sources": ["NVD", "OSV", "RedHat", "GitLab Advisory", "Curl"],
            "cve_counts": counts,
            "cve_count_total": sum(counts.values()),
        },
    }
    print(json.dumps(doc))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="ifda", description="Firmware RE + vuln analysis core")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze a binary or extracted tree")
    a.add_argument("target")
    a.add_argument("--json", help="write JSON report to this path")
    a.add_argument("--md", help="write Markdown report to this path")
    a.add_argument("--sbom", help="write CycloneDX SBOM JSON to this path")
    a.add_argument("--triage", help="triage state JSON (read + apply)")
    a.add_argument("--progress", action="store_true",
                   help="emit @@IFDA@@<json> progress events on stderr")
    a.add_argument("--decompile", action="store_true",
                   help="enrich findings with Ghidra pseudocode (slow; needs Ghidra)")
    a.set_defaults(func=_cmd_analyze)

    t = sub.add_parser("triage", help="set triage state for a finding")
    t.add_argument("store", help="triage state JSON file")
    t.add_argument("finding_id")
    t.add_argument("state", choices=[s.value for s in TriageState])
    t.set_defaults(func=_cmd_triage)

    v = sub.add_parser("vulndb", help="report CVE-correlation coverage (curated DB + cve-bin-tool)")
    v.set_defaults(func=_cmd_vulndb)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
