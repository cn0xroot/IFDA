"""FR-REP-1/4: human-readable Markdown report with an executive summary and
per-finding detail with evidence.
"""

from __future__ import annotations

from collections import Counter

from ..model import AnalysisReport, Finding, SEVERITY_RANK


def _sev_badge(f: Finding) -> str:
    return f.severity.value.upper()


def render_markdown(report: AnalysisReport) -> str:
    lines: list[str] = []
    a = lines.append

    a(f"# Firmware analysis report: {report.target}")
    a("")
    a(f"*Generated {report.generated_at} by ifda {report.tool_version}*")
    a("")

    # Executive summary (FR-REP-4).
    a("## Executive summary")
    a("")
    counts = Counter(f.severity.value for f in report.findings)
    a(f"- Binaries analyzed: **{len(report.binaries)}**")
    a(f"- Findings: **{len(report.findings)}** "
      f"(critical {counts.get('critical',0)}, high {counts.get('high',0)}, "
      f"medium {counts.get('medium',0)}, low {counts.get('low',0)})")
    cves = sorted({c for f in report.findings for c in f.cve_ids})
    if cves:
        a(f"- Known CVEs correlated: {', '.join(cves)}")
    a("")

    # Binary inventory.
    a("## Binaries")
    a("")
    a("| Path | Arch | Bits | Endian | NX | Canary | RELRO | PIE | Stripped |")
    a("|------|------|------|--------|----|--------|-------|-----|----------|")
    for b in report.binaries:
        m = b.mitigations
        a(f"| `{b.path}` | {b.arch} | {b.bits} | {b.endian} | "
          f"{_yn(m.nx)} | {_yn(m.canary)} | {m.relro} | {_yn(m.pie)} | {_yn(m.stripped)} |")
    a("")

    # Findings detail, already prioritized.
    a("## Findings")
    a("")
    if not report.findings:
        a("_No findings._")
        return "\n".join(lines)

    for i, f in enumerate(report.findings, 1):
        a(f"### {i}. [{_sev_badge(f)}] {f.title}")
        a("")
        a(f"- **Class:** {f.vuln_class}  ")
        a(f"- **Confidence:** {f.confidence:.0%}  ")
        a(f"- **Component:** `{f.component}`  ")
        a(f"- **Rule:** `{f.rule}`  ")
        a(f"- **Finding ID:** `{f.id}` (triage: {f.triage.value})  ")
        if f.cve_ids:
            a(f"- **CVE:** {', '.join(f.cve_ids)}  ")
        if f.description:
            a("")
            a(f.description)
        for ev in f.evidence:
            a("")
            loc = ev.function or "(module)"
            a(f"Evidence — `{ev.binary}` @ `{loc}`"
              + (f" `{ev.address:#x}`" if ev.address else "") + ":")
            if ev.taint_path:
                a("")
                a("```")
                a(" -> ".join(ev.taint_path))
                a("```")
            elif ev.snippet:
                a("")
                a("```asm")
                a(ev.snippet)
                a("```")
        if f.pseudocode:
            a("")
            a("<details><summary>Decompiled pseudocode (Ghidra)</summary>")
            a("")
            a("```c")
            a(f.pseudocode.rstrip())
            a("```")
            a("</details>")
        if f.remediation:
            a("")
            a(f"**Remediation:** {f.remediation}")
        a("")

    return "\n".join(lines)


def _yn(v) -> str:
    if v is None:
        return "?"
    return "yes" if v else "**no**"
