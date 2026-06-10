"""FR-VUL-3: taint / reachability analysis (lightweight, call-graph based).

A full data-flow taint engine (angr/symbolic) is an optional heavy dependency.
This iteration ships a call-graph reachability approximation: if a function pulls
data from a known untrusted *source* and a *sink* is reachable from that function
through the local call graph, we report a candidate source->sink path. Per the
requirements' constraints, these are heuristic leads for analyst validation, so
confidence is capped accordingly.

The interface is intentionally the same shape a precise engine would produce, so
swapping in angr later doesn't change downstream code.
"""

from __future__ import annotations

from ..model import BinaryInfo, Finding, Evidence, Severity
from ..re.disasm import DisasmResult
from .catalog import SOURCES, SINKS, REMEDIATION

RULE = "taint-reachability"

_SEVERITY = {
    "command_injection": Severity.HIGH,
    "buffer_overflow": Severity.HIGH,
    "format_string": Severity.MEDIUM,
}


def detect_taint_paths(info: BinaryInfo, disasm: DisasmResult) -> list[Finding]:
    by_name = {fn.name: fn for fn in disasm.functions}
    findings: list[Finding] = []

    for fn in disasm.functions:
        sources_here = [c for c in fn.calls if c in SOURCES]
        if not sources_here:
            continue
        reachable = _reachable_sinks(fn, by_name)
        if not reachable:
            continue
        for source in sorted(set(sources_here)):
            for sink, (sink_class, hops) in reachable.items():
                path = [source, fn.name] + hops + [f"{sink}()"]
                ev = Evidence(
                    binary=info.path,
                    function=fn.name,
                    address=fn.address,
                    snippet=f"{source}() -> ... -> {sink}()",
                    taint_path=path,
                )
                f = Finding(
                    id="",
                    title=f"Untrusted input from {source}() may reach {sink}()",
                    vuln_class=sink_class,
                    severity=_SEVERITY.get(sink_class, Severity.MEDIUM),
                    confidence=0.5,
                    component=info.path,
                    rule=RULE,
                    description=(
                        f"In {fn.name}, data from source {source}() can reach sink "
                        f"{sink}() via the call graph. Heuristic; verify the data "
                        f"actually flows into the sink argument."
                    ),
                    remediation=REMEDIATION.get(sink_class, ""),
                    evidence=[ev],
                )
                f.id = f.fingerprint()
                findings.append(f)

    return findings


def _reachable_sinks(start, by_name, max_depth: int = 6):
    """BFS over local call graph from `start`; return {sink: (class, hop_names)}."""
    found: dict[str, tuple[str, list[str]]] = {}
    seen = {start.name}
    # queue items: (function, path_of_local_hops_so_far)
    queue = [(start, [])]
    depth = 0
    while queue and depth <= max_depth:
        nxt = []
        for fn, hops in queue:
            for callee in fn.calls:
                if callee in SINKS and callee not in found:
                    found[callee] = (SINKS[callee], hops)
                target = by_name.get(callee)
                if target and target.name not in seen:
                    seen.add(target.name)
                    nxt.append((target, hops + [target.name]))
        queue = nxt
        depth += 1
    return found
