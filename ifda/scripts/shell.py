"""Shell / CGI script command-injection analysis (EMBA S20-style).

A lightweight intra-file taint pass: collect variables fed from untrusted
sources (CGI environment, nvram, `read`, positional params), then flag command
sinks (`eval`, command substitution, `sh -c`, executing a variable, piping a
download into a shell) that consume them. Tainted-source hits are high
confidence; generic dangerous constructs are reported at lower confidence.

Heuristic by nature (no full shell parser); findings are analyst leads.
"""

from __future__ import annotations

import os
import re

from ..model import Finding, Evidence, Severity

RULE = "script-cmd-injection"

_SHEBANG = re.compile(rb"^#!\s*\S*/(?:ba|a|da|k)?sh\b")
_SCRIPT_EXT = (".sh", ".cgi", ".bash")
_MAX_BYTES = 2 * 1024 * 1024

# Tokens that introduce untrusted data (CGI/web, nvram, config readers).
_UNTRUSTED = re.compile(
    r"\b(QUERY_STRING|REQUEST_METHOD|REQUEST_URI|CONTENT_LENGTH|CONTENT_TYPE|"
    r"REMOTE_ADDR|REMOTE_HOST|HTTP_[A-Z_]+|FORM_[A-Za-z0-9_]+|POST_[A-Za-z0-9_]+)\b"
    r"|nvram(?:_get|\s+get)\b|websGetVar\b|getValue\b|\bhttpGet\b"
)
# Untrusted environment variable names that are themselves tainted references.
_UNTRUSTED_VARS = {
    "QUERY_STRING", "REQUEST_METHOD", "REQUEST_URI", "CONTENT_LENGTH",
    "CONTENT_TYPE", "REMOTE_ADDR", "REMOTE_HOST",
}

_ASSIGN = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
_READ = re.compile(r"^\s*read\b(?:\s+-\w+)*\s+(.+)$")
_VARREF = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")

# Sinks.
_EVAL = re.compile(r"(?:^|;|&|\||\bthen\b|\bdo\b)\s*eval\b(.*)")
_SH_C = re.compile(r"\b(?:sh|bash|ash)\s+-c\b(.*)")
_PIPE_SHELL = re.compile(r"\|\s*(?:sh|bash|ash)\b")
_CMD_SUBST = re.compile(r"`[^`]*`|\$\([^)]*\)")
_DOWNLOAD = re.compile(r"\b(?:wget|curl|tftp)\b")


def scan_scripts(target: str, max_files: int = 20000) -> list[Finding]:
    findings: list[Finding] = []
    n = 0
    for path in _iter_files(target):
        if n >= max_files:
            break
        n += 1
        if not _is_shell(path):
            continue
        try:
            with open(path, "rb") as fh:
                text = fh.read(_MAX_BYTES).decode("latin-1", errors="replace")
        except OSError:
            continue
        findings.extend(_analyze(path, text))
    return findings


def _iter_files(target: str):
    if os.path.isfile(target):
        yield target
        return
    for root, _dirs, names in os.walk(target):
        for name in names:
            p = os.path.join(root, name)
            if not os.path.islink(p) and os.path.isfile(p):
                yield p


def _is_shell(path: str) -> bool:
    if path.endswith(_SCRIPT_EXT):
        return True
    try:
        with open(path, "rb") as fh:
            return bool(_SHEBANG.match(fh.read(64)))
    except OSError:
        return False


def _analyze(path: str, text: str) -> list[Finding]:
    lines = text.splitlines()
    tainted: set[str] = set(_UNTRUSTED_VARS)

    # Pass 1: propagate taint through assignments and `read`.
    for line in lines:
        m = _ASSIGN.match(line)
        if m:
            var, rhs = m.group(1), m.group(2)
            if _UNTRUSTED.search(rhs) or _refs_tainted(rhs, tainted) or _refs_positional(rhs):
                tainted.add(var)
            continue
        r = _READ.match(line)
        if r:
            for var in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", r.group(1)):
                tainted.add(var)

    # Pass 2: sinks. Severity reflects real shell semantics: re-parsing contexts
    # (eval, sh -c, command-name position) are injection; an unquoted variable as
    # a mere *argument* does not re-parse `;`/`|`, so it is a weaker lead.
    out: list[Finding] = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        assign = _ASSIGN.match(line)
        body = assign.group(2) if assign else line
        ev_tainted = _refs_tainted(body, tainted) or _refs_positional(body)

        m = _EVAL.search(body)
        if m and _VARREF.search(m.group(1)):
            sev, conf = (Severity.HIGH, 0.7) if ev_tainted else (Severity.MEDIUM, 0.45)
            out.append(_mk(path, i, line, sev, conf, "eval on dynamic data",
                           "eval re-parses and executes a constructed string; if any "
                           "part is attacker-influenced this is command injection."))
            continue

        m = _SH_C.search(body)
        if m and ev_tainted and _VARREF.search(m.group(1)):
            out.append(_mk(path, i, line, Severity.HIGH, 0.7, "sh -c with untrusted data",
                           "Untrusted variable interpolated into a `sh -c` command "
                           "string, which re-parses shell metacharacters."))
            continue

        if _DOWNLOAD.search(body) and _PIPE_SHELL.search(body):
            out.append(_mk(path, i, line, Severity.HIGH, 0.7, "download piped into shell",
                           "Remote content is fetched and executed directly (no "
                           "integrity check); a MITM yields code execution."))
            continue
        if _PIPE_SHELL.search(body) and ev_tainted:
            out.append(_mk(path, i, line, Severity.HIGH, 0.6,
                           "untrusted data piped into shell",
                           "Untrusted data is piped into a shell interpreter."))
            continue

        if not ev_tainted:
            continue

        # Tainted variable as the command name -> arbitrary command execution.
        if not assign and _tainted_command_name(line, tainted):
            out.append(_mk(path, i, line, Severity.HIGH, 0.65,
                           "untrusted variable executed as command",
                           "An attacker-influenced variable is used as the command "
                           "name, allowing arbitrary command execution."))
            continue

        # Command substitution that embeds untrusted data.
        subst = "".join(_CMD_SUBST.findall(body))
        if subst and _refs_tainted(subst, tainted):
            out.append(_mk(path, i, line, Severity.MEDIUM, 0.5,
                           "untrusted data in command substitution",
                           "Command substitution incorporates untrusted data; verify "
                           "it cannot alter the executed command."))
            continue

        # Unquoted tainted argument: weaker (arg/word-split, may reach a wrapper
        # that calls system()), reported as a low-confidence lead.
        if not assign and _unquoted_tainted_arg(line, tainted):
            out.append(_mk(path, i, line, Severity.LOW, 0.35,
                           "untrusted data as command argument",
                           "Unquoted untrusted variable passed as a command argument; "
                           "review whether it reaches a shell/system() wrapper."))
            continue
    return out


def _refs_tainted(s: str, tainted: set[str]) -> bool:
    return any(v in tainted for v in _VARREF.findall(s))


def _refs_positional(s: str) -> bool:
    return bool(re.search(r"\$(?:[1-9]|[@*])", s))


def _command_name(line: str) -> str:
    """First command word, skipping leading `VAR=value` assignment prefixes."""
    s = line.strip()
    while True:
        m = re.match(r"[A-Za-z_]\w*=\S*\s+", s)
        if not m:
            break
        s = s[m.end():]
    parts = s.split()
    return parts[0] if parts else ""


def _tainted_command_name(line: str, tainted: set[str]) -> bool:
    return any(v in tainted for v in _VARREF.findall(_command_name(line)))


def _unquoted_tainted_arg(line: str, tainted: set[str]) -> bool:
    """A tainted `$var`/`${var}` reference not wrapped in double quotes."""
    for v in tainted:
        if re.search(r'(?<!")\$\{?' + re.escape(v) + r"\}?(?!\w)(?!\")", line):
            return True
    return False


def _mk(path, lineno, line, sev, conf, title, desc) -> Finding:
    ev = Evidence(binary=path, function=f"line {lineno}", snippet=line.strip()[:160])
    f = Finding(
        id="",
        title=title,
        vuln_class="command_injection",
        severity=sev,
        confidence=conf,
        component=path,
        rule=RULE,
        description=desc,
        remediation="Validate/allowlist inputs; avoid eval and shell interpolation; "
                    "quote variables; use fixed argument vectors.",
        evidence=[ev],
    )
    f.id = f.fingerprint()
    return f
