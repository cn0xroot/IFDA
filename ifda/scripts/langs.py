"""Command/code-injection analysis for PHP, Python and Lua CGI scripts.

Extends the shell analyzer's approach (EMBA S20-series) to the other languages
that show up in IoT web interfaces: PHP (the dominant CGI language), Python
(Flask/cgi handlers), and Lua (OpenWrt/LuCI). Same two-pass, taint-lite design:

  pass 1 — mark variables assigned from an untrusted source (request params,
           environment, argv, stdin);
  pass 2 — flag command/code/inclusion sinks whose argument is tainted (HIGH) or
           merely dynamic, i.e. built from variables we can't prove safe (MEDIUM).

Static-literal sink calls are ignored. Heuristic, single-line, no full parser —
findings are analyst leads, consistent with the shell module.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from ..model import Finding, Evidence, Severity

RULE = "script-cmd-injection"

_MAX_BYTES = 2 * 1024 * 1024


@dataclass
class _Sink:
    pattern: "re.Pattern[str]"   # captures the argument region in group 1
    vuln_class: str
    title: str
    desc: str


@dataclass
class _Lang:
    name: str
    exts: tuple
    shebang: "re.Pattern[str] | None"
    content_hint: "re.Pattern[str] | None"
    dollar_vars: bool                 # True => variables are written $name (PHP)
    assign: "re.Pattern[str]"         # captures (var, rhs)
    sources: "re.Pattern[str]"        # untrusted-source tokens
    sinks: list = field(default_factory=list)


# --- string-literal stripping so "dynamic" means "has a non-literal part" ----
_STRLIT = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"")
# Identifiers that are not really "dynamic" data when left after stripping.
_NOISE_WORDS = re.compile(r"\b(?:True|False|None|shell|nil|true|false|self|os|subprocess)\b")


def _strip_strings(s: str) -> str:
    return _STRLIT.sub("", s)


def _is_dynamic(arg: str) -> bool:
    rest = _NOISE_WORDS.sub("", _strip_strings(arg))
    return bool(re.search(r"[A-Za-z_$]", rest))


_PHP = _Lang(
    name="php",
    exts=(".php", ".php3", ".php5", ".phtml", ".inc"),
    shebang=re.compile(rb"^#!.*\bphp\b"),
    content_hint=re.compile(r"<\?php"),
    dollar_vars=True,
    assign=re.compile(r"^\s*\$([A-Za-z_]\w*)\s*=\s*(.+?);?\s*$"),
    sources=re.compile(
        r"\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES|ENV)\b|"
        r"\bgetenv\s*\(|php://input|\bfilter_input\s*\(|\bapache_request_headers\b"
    ),
    sinks=[
        _Sink(re.compile(r"\b(?:system|exec|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(([^;]*)"),
              "command_injection", "PHP command execution on dynamic data",
              "Untrusted/dynamic data reaches a PHP shell-exec sink; shell "
              "metacharacters in the input yield command injection."),
        _Sink(re.compile(r"`([^`]+)`"),
              "command_injection", "PHP backtick shell execution",
              "Backtick operator executes a shell command built at runtime."),
        _Sink(re.compile(r"\b(?:eval|assert|create_function)\s*\(([^;]*)"),
              "code_injection", "PHP dynamic code evaluation",
              "eval/assert/create_function executes a constructed string as PHP "
              "code; attacker-influenced input is remote code execution."),
        _Sink(re.compile(r"^\s*(?:include|require)(?:_once)?\s*\(?\s*([^;]*)"),
              "file_inclusion", "PHP dynamic file inclusion",
              "include/require with a runtime-built path enables local/remote "
              "file inclusion (LFI/RFI)."),
    ],
)

_PY = _Lang(
    name="python",
    exts=(".py",),
    shebang=re.compile(rb"^#!.*\bpython"),
    content_hint=None,
    dollar_vars=False,
    assign=re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$"),
    sources=re.compile(
        r"\brequest\.(?:args|form|values|GET|POST|data|json|cookies|headers)\b|"
        r"\bos\.environ\b|\bsys\.argv\b|\b(?:cgi\.)?FieldStorage\b|\binput\s*\(|"
        r"\bflask\.request\b|\bself\.(?:get_argument|request)\b"
    ),
    sinks=[
        _Sink(re.compile(r"\bos\.(?:system|popen)\s*\(([^)]*)\)"),
              "command_injection", "Python os.system/os.popen on dynamic data",
              "Dynamic data passed to os.system/os.popen runs through the shell."),
        _Sink(re.compile(r"\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\(([^)]*shell\s*=\s*True[^)]*)\)"),
              "command_injection", "Python subprocess shell=True on dynamic data",
              "subprocess with shell=True and a runtime-built command re-parses "
              "shell metacharacters; use a fixed argument list instead."),
        _Sink(re.compile(r"\b(?:eval|exec)\s*\(([^)]*)\)"),
              "code_injection", "Python eval/exec of dynamic data",
              "eval/exec executes a constructed string as Python code."),
        _Sink(re.compile(r"\b(?:pickle|cPickle)\.loads?\s*\(([^)]*)\)|\byaml\.load\s*\(([^)]*)\)"),
              "deserialization", "Python unsafe deserialization",
              "pickle.load(s) / yaml.load on untrusted data can execute arbitrary "
              "code during deserialization (use yaml.safe_load / signed data)."),
    ],
)

_LUA = _Lang(
    name="lua",
    exts=(".lua",),
    shebang=re.compile(rb"^#!.*\blua"),
    content_hint=None,
    dollar_vars=False,
    assign=re.compile(r"^\s*(?:local\s+)?([A-Za-z_]\w*)\s*=\s*(.+?)\s*$"),
    sources=re.compile(
        r"\bluci\.http\b|\bhttp\.formvalue\s*\(|\bhttp\.getenv\s*\(|"
        r"\bngx\.(?:var|req)\b|\bos\.getenv\s*\(|\bform\[(?:[^]]+)\]"
    ),
    sinks=[
        _Sink(re.compile(r"\bos\.execute\s*\(([^)]*)\)|\bio\.popen\s*\(([^)]*)\)"),
              "command_injection", "Lua os.execute/io.popen on dynamic data",
              "Dynamic data reaches a Lua shell-execution sink."),
        _Sink(re.compile(r"\b(?:loadstring|load|dofile)\s*\(([^)]*)\)"),
              "code_injection", "Lua dynamic code load",
              "loadstring/load/dofile compiles and runs a runtime-built string as "
              "Lua code."),
    ],
)

_LANGS = (_PHP, _PY, _LUA)


def scan_lang_scripts(target: str, max_files: int = 20000) -> list[Finding]:
    findings: list[Finding] = []
    n = 0
    for path in _iter_files(target):
        if n >= max_files:
            break
        n += 1
        lang = _detect_lang(path)
        if not lang:
            continue
        try:
            with open(path, "rb") as fh:
                text = fh.read(_MAX_BYTES).decode("latin-1", errors="replace")
        except OSError:
            continue
        findings.extend(_analyze(path, text, lang))
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


def _detect_lang(path: str) -> "_Lang | None":
    head = b""
    for lang in _LANGS:
        if path.endswith(lang.exts):
            return lang
    try:
        with open(path, "rb") as fh:
            head = fh.read(256)
    except OSError:
        return None
    for lang in _LANGS:
        if lang.shebang and lang.shebang.match(head):
            return lang
        if lang.content_hint and lang.content_hint.search(head.decode("latin-1", "replace")):
            return lang
    return None


def _refs(s: str, dollar: bool) -> list[str]:
    if dollar:
        return re.findall(r"\$([A-Za-z_]\w*)", s)
    return re.findall(r"\b([A-Za-z_]\w*)\b", s)


def _analyze(path: str, text: str, lang: _Lang) -> list[Finding]:
    lines = text.splitlines()
    tainted: set[str] = set()

    # Pass 1: propagate taint through assignments (fixed-point over a few passes
    # so var-to-var flows settle regardless of order).
    for _ in range(3):
        changed = False
        for line in lines:
            m = lang.assign.match(line)
            if not m:
                continue
            var, rhs = m.group(1), m.group(2)
            if var in tainted:
                continue
            if lang.sources.search(rhs) or any(v in tainted for v in _refs(rhs, lang.dollar_vars)):
                tainted.add(var)
                changed = True
        if not changed:
            break

    # Pass 2: sinks.
    out: list[Finding] = []
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("//"):
            continue
        for sink in lang.sinks:
            m = sink.pattern.search(line)
            if not m:
                continue
            arg = next((g for g in m.groups() if g), "") or ""
            has_source = bool(lang.sources.search(arg))
            has_tainted = has_source or any(v in tainted for v in _refs(arg, lang.dollar_vars))
            if has_tainted:
                sev, conf = Severity.HIGH, 0.7
            elif _is_dynamic(arg):
                sev, conf = Severity.MEDIUM, 0.4
            else:
                continue  # static literal argument: not a lead
            out.append(_mk(path, i, line, lang.name, sev, conf,
                           sink.vuln_class, sink.title, sink.desc))
            break  # one finding per line is enough
    return out


def _mk(path, lineno, line, lang, sev, conf, vclass, title, desc) -> Finding:
    ev = Evidence(binary=path, function=f"line {lineno}", snippet=line.strip()[:160])
    f = Finding(
        id="",
        title=title,
        vuln_class=vclass,
        severity=sev,
        confidence=conf,
        component=path,
        rule=f"{RULE}:{lang}",
        description=desc,
        remediation="Validate/allowlist inputs; avoid eval and shell interpolation; "
                    "use parameterized/argument-vector APIs; for includes use a "
                    "fixed allowlist of paths.",
        evidence=[ev],
    )
    f.id = f.fingerprint()
    return f
