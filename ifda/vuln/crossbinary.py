"""FR-VUL-5: cross-binary taint / call-graph analysis.

Per-binary taint (`taint.py`) misses the most common router RCE shape: a CGI
handler reads untrusted input and passes it into a shared library, where the
sink (`system`, `sprintf`, ...) actually lives. This pass builds a *global* call
graph across every analyzed binary — linking an imported call in one binary to
the matching exported function in another — and reports source->sink paths that
cross at least one binary boundary.

Resolution is name-based (import symbol == export symbol), which is how the
dynamic linker itself binds them, so it works for any architecture whose call
sites we resolved (and falls back to nothing rather than guessing).
"""

from __future__ import annotations

from ..model import BinaryInfo, Finding, Evidence, Severity
from ..re.disasm import DisasmResult
from .catalog import SOURCES, SINKS, REMEDIATION

RULE = "cross-binary-taint"

_SEVERITY = {
    "command_injection": Severity.HIGH,
    "buffer_overflow": Severity.HIGH,
    "format_string": Severity.MEDIUM,
}

# (binary_path, function_name) identifies a node in the global graph.
Node = tuple[str, str]


def detect_cross_binary_taint(
    units: list[tuple[BinaryInfo, DisasmResult]], max_depth: int = 8
) -> list[Finding]:
    func_index: dict[Node, "Function"] = {}
    export_owner: dict[str, list[Node]] = {}

    for info, dis in units:
        exports = set(info.exports)
        for fn in dis.functions:
            func_index[(info.path, fn.name)] = fn
            if fn.name in exports:
                export_owner.setdefault(fn.name, []).append((info.path, fn.name))

    findings: list[Finding] = []
    seen_results: set[tuple] = set()

    for info, dis in units:
        for fn in dis.functions:
            sources_here = [c for c in fn.calls if c in SOURCES]
            if not sources_here:
                continue
            for source in sorted(set(sources_here)):
                for hit in _search(
                    (info.path, fn.name), func_index, export_owner, max_depth
                ):
                    sink, sink_class, label_path, sink_binary = hit
                    key = (source, sink, info.path, sink_binary)
                    if key in seen_results:
                        continue
                    seen_results.add(key)
                    findings.append(
                        _make_finding(info, fn, source, sink, sink_class, label_path)
                    )
    return findings


def _search(start: Node, func_index, export_owner, max_depth):
    """BFS over the global graph from `start`.

    Yields (sink_name, sink_class, label_path, sink_binary) for sinks reachable
    via a path that crosses at least one binary boundary.
    """
    start_bin, start_fn = start
    # queue items: (node, crossed_boundary, label_path)
    queue = [(start, False, [f"{start_fn} @ {_short(start_bin)}"])]
    seen = {start}
    depth = 0
    while queue and depth <= max_depth:
        nxt = []
        for (binpath, name), crossed, labels in queue:
            fn = func_index.get((binpath, name))
            if fn is None:
                continue
            # Sinks realized in this function (only count if we've crossed).
            if crossed:
                for callee in fn.calls:
                    if callee in SINKS:
                        yield (callee, SINKS[callee], labels + [f"{callee}()"], binpath)
            for callee in fn.calls:
                # Local edge.
                local = (binpath, callee)
                if local in func_index and local not in seen:
                    seen.add(local)
                    nxt.append((local, crossed, labels + [f"{callee} @ {_short(binpath)}"]))
                # Cross-binary edge: callee is exported by another binary.
                for owner in export_owner.get(callee, []):
                    if owner[0] != binpath and owner not in seen:
                        seen.add(owner)
                        nxt.append(
                            (owner, True, labels + [f"{callee} @ {_short(owner[0])} (cross)"])
                        )
        queue = nxt
        depth += 1


def _make_finding(info, fn, source, sink, sink_class, label_path) -> Finding:
    path = [f"{source}()"] + label_path
    ev = Evidence(
        binary=info.path,
        function=fn.name,
        address=fn.address,
        snippet=f"{source}() in {fn.name} -> ... -> {sink}() across binaries",
        taint_path=path,
    )
    f = Finding(
        id="",
        title=f"Cross-binary: {source}() in {_short(info.path)} may reach {sink}()",
        vuln_class=sink_class,
        severity=_SEVERITY.get(sink_class, Severity.MEDIUM),
        confidence=0.45,
        component=info.path,
        rule=RULE,
        description=(
            f"Untrusted data from {source}() enters {fn.name} and can reach sink "
            f"{sink}() in another binary via the global call graph. Heuristic; "
            f"verify the argument actually flows across the boundary."
        ),
        remediation=REMEDIATION.get(sink_class, ""),
        evidence=[ev],
    )
    f.id = f.fingerprint()
    return f


def _short(path: str) -> str:
    import os

    return os.path.basename(path) or path
