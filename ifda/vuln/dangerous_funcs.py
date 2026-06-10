"""FR-VUL-2: locate uses of unsafe APIs.

Two complementary signals:
  1. Call-site evidence (precise): a resolved call to a dangerous function,
     with the enclosing function and instruction as evidence. High confidence.
  2. Import-presence (coarse): the dangerous function appears in the import
     table but call sites could not be resolved (e.g. unsupported arch). Lower
     confidence, so analysts still see MIPS/ARM binaries flagged.
"""

from __future__ import annotations

from ..model import BinaryInfo, Finding, Evidence, Severity
from ..re.disasm import DisasmResult
from .catalog import DANGEROUS_FUNCTIONS, REMEDIATION

RULE = "unsafe-api"


def detect_dangerous_functions(
    info: BinaryInfo, disasm: DisasmResult
) -> list[Finding]:
    findings: list[Finding] = []

    resolved_callees = {cs.callee for cs in disasm.call_sites if cs.callee}

    # 1. Precise call-site findings.
    for cs in disasm.call_sites:
        meta = DANGEROUS_FUNCTIONS.get(cs.callee)
        if not meta:
            continue
        vuln_class, severity, note = meta
        ev = Evidence(
            binary=info.path,
            function=cs.caller,
            address=cs.address,
            snippet=cs.snippet,
        )
        f = Finding(
            id="",
            title=f"Call to unsafe function {cs.callee}() in {cs.caller}",
            vuln_class=vuln_class,
            severity=severity,
            confidence=0.8,
            component=info.path,
            rule=RULE,
            description=f"{cs.callee}: {note}.",
            remediation=REMEDIATION.get(vuln_class, ""),
            evidence=[ev],
        )
        f.id = f.fingerprint()
        findings.append(f)

    # 2. Import-presence fallback for functions we couldn't pin to a call site.
    for name in info.imports:
        meta = DANGEROUS_FUNCTIONS.get(name)
        if not meta or name in resolved_callees:
            continue
        vuln_class, severity, note = meta
        # Demote: presence-only is weaker than a located call.
        demoted = _demote(severity)
        ev = Evidence(binary=info.path, function="", address=0,
                      snippet=f"imports {name}")
        f = Finding(
            id="",
            title=f"Imports unsafe function {name}()",
            vuln_class=vuln_class,
            severity=demoted,
            confidence=0.4,
            component=info.path,
            rule=RULE + ":import",
            description=f"{name} is imported ({note}); call sites not resolved on this arch.",
            remediation=REMEDIATION.get(vuln_class, ""),
            evidence=[ev],
        )
        f.id = f.fingerprint()
        findings.append(f)

    return findings


def _demote(sev: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    i = order.index(sev)
    return order[max(0, i - 1)]
