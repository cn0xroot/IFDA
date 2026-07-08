"""Config-file content security checks (FR-VUL).

Distinct from the other two places a config file already gets looked at:
fs/hardening.py checks its *permission bits* (world-writable, setuid, ...),
and inventory/secrets.py checks for literal hardcoded credential *values*
inside it. Neither one notices a config file that carries no secret and has
perfectly sane permissions, yet still leaves an insecure service or setting
turned on by default (telnet, debug mode, a default SNMP community string,
disabled TLS verification, WPS, UPnP, ...) -- exactly the class of finding
this module exists to surface.

Patterns are a curated, deliberately narrow set of well-known IoT-firmware
insecure-by-default settings, not an exhaustive settings linter: broad
"anything that looks like a flag" matching would drown real hits in noise
from unrelated key names.
"""

from __future__ import annotations

import os
import re

from ..model import Finding, Evidence, Severity
from ..inventory.firmware_meta import is_config_file

RULE = "config-hardening"

# A config file this large is far more likely a data table/dictionary/locale
# file than something worth pattern-matching for security settings; keeps
# worst-case scan time bounded regardless of one huge outlier.
_MAX_BYTES = 2 * 1024 * 1024

_TRUTHY = r"['\"]?(?:1|true|on|yes|enabled?)['\"]?"
_FALSY = r"['\"]?(?:0|false|off|no|disabled?)['\"]?"
# "=value" (ini), ": value" (yaml-ish), or "option key value" (UCI, bare
# whitespace, no punctuation at all) -- but *some* separator is mandatory
# (at least one whitespace char, or a punctuation char with optional
# whitespace around it). Without that "at least one char" floor, a key name
# that itself contains a truthy word right where the value should start
# (e.g. "telnet_enable=0" backtracking to key="telnet_" + value="enable",
# ignoring the real "=0") would satisfy the pattern with zero characters
# between key and value -- exactly the false positive this guards against.
_SEP = r"(?:\s+|\s*[='\":]\s*)"

# Real firmware never spells a feature flag as the bare word "telnet"/"wps"/
# "upnp"/"debug" -- it's always part of a compound key (ENABLE_TELNET_ACCESS,
# enable_upnp, WPS_ACTIVE_IF, debug_level, ...). Matching the keyword
# anywhere inside the key (not the whole key) is what actually finds those
# in practice; the truthy-value requirement on the other side keeps it from
# also firing on an unrelated same-keyword key holding a port number or a
# verbosity level ("WAN_TELNET_ACCESS_PORT = 2323" doesn't satisfy _TRUTHY).
def _flag_pattern(keyword: str) -> re.Pattern:
    return re.compile(rf"(?im)^\s*(?:option\s+)?[\w]*{keyword}[\w]*{_SEP}{_TRUTHY}")


# (pattern, vuln_class, title, severity, confidence, remediation). Checked in
# order, first match per rule per file wins (see _scan_one) -- one finding
# per insecure setting per file is plenty; a file with the same flag repeated
# across several blocks doesn't need one finding per repetition.
_RULES: list[tuple[re.Pattern, str, str, Severity, float, str]] = [
    (_flag_pattern(r"telnet(?:d)?"),
     "insecure_service_enabled", "Telnet service enabled in config", Severity.HIGH, 0.6,
     "Disable telnet; use SSH with key auth or a local-only management interface instead."),

    (re.compile(r"(?im)^\s*config\s+telnet\b"),
     "insecure_service_enabled", "Telnet service block present in config", Severity.MEDIUM, 0.45,
     "Remove or disable the telnet service definition unless strictly required."),

    (_flag_pattern(r"(?:ftp[_-]?anonymous|anonymous[_-]?(?:ftp|enable))"),
     "insecure_service_enabled", "Anonymous FTP enabled in config", Severity.HIGH, 0.55,
     "Disable anonymous FTP access; require authentication or remove the FTP service."),

    (_flag_pattern("debug"),
     "debug_mode_enabled", "Debug/verbose mode enabled in config", Severity.LOW, 0.4,
     "Disable debug logging in production builds; it can leak internal state and credentials."),

    # net-snmp's own config style is "rocommunity"/"rwcommunity" (no
    # separator before "community"), not just bare "community" -- match both.
    (re.compile(r"(?i)\b(?:ro|rw)?community\s*[='\"]?\s*['\"]?(public|private)\b"),
     "default_credential", "Default SNMP community string", Severity.HIGH, 0.65,
     "Change the SNMP community string from the well-known default and restrict SNMP access."),

    (re.compile(rf"(?i)\b(?:ssl[_-]?verify|verify[_-]?peer|verify[_-]?cert)\s*[='\"]?\s*{_FALSY}"),
     "insecure_tls", "TLS/certificate verification disabled in config", Severity.HIGH, 0.6,
     "Enable certificate verification; disabling it allows MITM interception."),

    (re.compile(r"(?i)\bInsecureSkipVerify\s*[:=]?\s*true"),
     "insecure_tls", "TLS certificate verification disabled (InsecureSkipVerify)", Severity.HIGH, 0.6,
     "Remove InsecureSkipVerify; validate the server certificate."),

    (_flag_pattern("wps"),
     "weak_wifi_config", "WPS enabled in config", Severity.MEDIUM, 0.4,
     "Disable WPS; its PIN mechanism is brute-forceable and a common Wi-Fi compromise vector."),

    (_flag_pattern("upnp"),
     "expanded_attack_surface", "UPnP enabled in config", Severity.LOW, 0.35,
     "Disable UPnP unless required; it lets LAN devices open arbitrary ports on the WAN side."),
]


def scan_configs(target: str, max_entries: int = 200000) -> list[Finding]:
    """FR-VUL: insecure settings left enabled in config files. Applies to an
    extracted tree, same as fs/hardening.py and inventory/secrets.py -- a
    single-file target has no directory structure to walk."""
    if os.path.isfile(target):
        return []
    out: list[Finding] = []
    n = 0
    for root, _dirs, files in os.walk(target):
        for f in files:
            if n >= max_entries:
                return out
            n += 1
            path = os.path.join(root, f)
            # Path-only check (no head bytes) here: cheap and no I/O, so a
            # tree with thousands of non-config files never gets opened just
            # to find out it isn't one. Misses the content-sniff-only edge
            # case (extensionless file outside a recognized config path),
            # the same tradeoff list_all_files' classification doesn't make
            # (it already has the bytes in hand there) but scanning here
            # doesn't get for free.
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if not is_config_file(path):
                continue
            out.extend(_scan_one(path, target))
    return out


def _scan_one(path: str, target: str) -> list[Finding]:
    try:
        size = os.path.getsize(path)
        if size == 0 or size > _MAX_BYTES:
            return []
        with open(path, "rb") as fh:
            data = fh.read(_MAX_BYTES)
    except OSError:
        return []
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    rel = "/" + os.path.relpath(path, target)

    out: list[Finding] = []
    for pattern, vclass, title, sev, conf, remediation in _RULES:
        m = pattern.search(text)
        if not m:
            continue
        line_no = text[:m.start()].count("\n")
        snippet = lines[line_no].strip() if line_no < len(lines) else m.group(0)
        out.append(_mk(path, rel, vclass, title, sev, conf, remediation, snippet))
    return out


def _mk(path, rel, vclass, title, sev, conf, remediation, snippet) -> Finding:
    f = Finding(
        id="",
        title=title,
        vuln_class=vclass,
        severity=sev,
        confidence=conf,
        component=rel,
        rule=RULE,
        description=f"{rel}: {title} -- `{snippet}`",
        remediation=remediation,
        evidence=[Evidence(binary=path, snippet=snippet)],
    )
    f.id = f.fingerprint()
    return f
