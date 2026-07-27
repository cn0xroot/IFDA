"""FR-VUL-4: authentication logic weaknesses (binary side).

Heuristic: a function whose name looks auth-related (login/passwd/auth/
credential/verify/checkpw...) that compares data with a non-constant-time
string/memory comparison (strcmp/strncmp/memcmp/strcasecmp/strncasecmp) is a
known IoT firmware anti-pattern -- these compare byte-by-byte and return as
soon as they find a mismatch, so a network-observable server can use the
response-time difference to recover a secret one byte at a time. Real router/
camera firmware has shipped exactly this pattern (plain strcmp against a
hardcoded or user-supplied password/token).

This is name+call-pattern based, not a data-flow proof, so it sits at the
same heuristic tier as the other detectors here (FR-VUL-3's taint
reachability, FR-VUL-2's import-presence fallback) -- flagged for analyst
confirmation, not treated as proven.
"""

from __future__ import annotations

from ..model import BinaryInfo, Finding, Evidence, Severity
from ..re.disasm import DisasmResult
from .catalog import REMEDIATION

RULE = "auth-logic-weak"

_AUTH_NAME_HINTS = (
    "auth", "login", "logon", "passwd", "password", "credential",
    "verify", "checkpw", "checkpass", "chkpwd", "chk_pwd",
)

_WEAK_COMPARE = {"strcmp", "strncmp", "memcmp", "strcasecmp", "strncasecmp"}


def detect_auth_weaknesses(info: BinaryInfo, disasm: DisasmResult) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()  # one finding per (caller, callee) pair
    for cs in disasm.call_sites:
        if cs.callee not in _WEAK_COMPARE:
            continue
        caller_lower = cs.caller.lower()
        if not any(hint in caller_lower for hint in _AUTH_NAME_HINTS):
            continue
        key = (cs.caller, cs.callee)
        if key in seen:
            continue
        seen.add(key)
        ev = Evidence(
            binary=info.path,
            function=cs.caller,
            address=cs.address,
            snippet=cs.snippet,
        )
        f = Finding(
            id="",
            title=f"Non-constant-time comparison ({cs.callee}) in auth-related function {cs.caller}",
            vuln_class="auth_logic_weakness",
            severity=Severity.MEDIUM,
            confidence=0.45,
            component=info.path,
            rule=RULE,
            description=(
                f"{cs.caller} looks authentication-related by name and calls "
                f"{cs.callee}(), a byte-by-byte comparison that short-circuits "
                f"on the first mismatch. If either operand is attacker-supplied "
                f"(a password/token from the network), the response-time "
                f"difference can leak the correct value one byte at a time; "
                f"verify whether the compared value is actually secret."
            ),
            remediation=REMEDIATION.get("auth_logic_weakness", ""),
            evidence=[ev],
        )
        f.id = f.fingerprint()
        findings.append(f)
    return findings
