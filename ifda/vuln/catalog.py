"""Catalog of unsafe APIs and the source/sink roles used by taint analysis.

Centralized so user-defined rules (FR-INT-3) can extend it later without
touching the detectors.
"""

from __future__ import annotations

from ..model import Severity

# name -> (vuln_class, base_severity, note)
DANGEROUS_FUNCTIONS: dict[str, tuple[str, Severity, str]] = {
    # Classic unbounded string ops -> buffer overflow.
    "strcpy":  ("buffer_overflow", Severity.HIGH,   "unbounded copy into fixed buffer"),
    "strcat":  ("buffer_overflow", Severity.HIGH,   "unbounded concatenation"),
    "gets":    ("buffer_overflow", Severity.CRITICAL, "no bound; never safe"),
    "sprintf": ("buffer_overflow", Severity.HIGH,   "unbounded formatted write"),
    "vsprintf":("buffer_overflow", Severity.HIGH,   "unbounded formatted write"),
    "scanf":   ("buffer_overflow", Severity.MEDIUM, "%s without width is unbounded"),
    "sscanf":  ("buffer_overflow", Severity.MEDIUM, "%s without width is unbounded"),
    # Bounded but error-prone.
    "strncpy": ("buffer_overflow", Severity.LOW,    "may leave string unterminated"),
    "memcpy":  ("buffer_overflow", Severity.MEDIUM, "overflow if length is attacker-influenced"),
    "memmove": ("buffer_overflow", Severity.MEDIUM, "overflow if length is attacker-influenced"),
    "alloca":  ("buffer_overflow", Severity.MEDIUM, "stack exhaustion with attacker size"),
    # Command execution sinks -> command injection.
    "system":  ("command_injection", Severity.HIGH, "shell command execution"),
    "popen":   ("command_injection", Severity.HIGH, "shell command execution"),
    "execve":  ("command_injection", Severity.MEDIUM, "process execution"),
    "execl":   ("command_injection", Severity.MEDIUM, "process execution"),
    "execlp":  ("command_injection", Severity.MEDIUM, "process execution via PATH"),
    "execvp":  ("command_injection", Severity.MEDIUM, "process execution via PATH"),
    "doSystemCmd": ("command_injection", Severity.HIGH, "vendor shell wrapper (common in routers)"),
    "twsystem":("command_injection", Severity.HIGH, "vendor shell wrapper (common in routers)"),
    # Format string.
    "printf":  ("format_string", Severity.LOW,  "format-string risk if arg is attacker-controlled"),
    "fprintf": ("format_string", Severity.LOW,  "format-string risk if arg is attacker-controlled"),
    "syslog":  ("format_string", Severity.LOW,  "format-string risk if arg is attacker-controlled"),
    # Weak crypto / RNG.
    "MD5":     ("weak_crypto", Severity.LOW, "weak hash"),
    "rand":    ("weak_crypto", Severity.LOW, "predictable PRNG"),
    "srand":   ("weak_crypto", Severity.LOW, "predictable PRNG seeding"),
    "DES_set_key": ("weak_crypto", Severity.MEDIUM, "weak cipher"),
}

# Taint sinks: callee -> vuln_class realized if tainted data reaches it.
SINKS: dict[str, str] = {
    "system": "command_injection",
    "popen": "command_injection",
    "execve": "command_injection",
    "execl": "command_injection",
    "execlp": "command_injection",
    "execvp": "command_injection",
    "doSystemCmd": "command_injection",
    "twsystem": "command_injection",
    "strcpy": "buffer_overflow",
    "strcat": "buffer_overflow",
    "sprintf": "buffer_overflow",
    "memcpy": "buffer_overflow",
    "printf": "format_string",
    "fprintf": "format_string",
    "syslog": "format_string",
}

# Taint sources: functions that return/produce attacker-influenced data.
SOURCES: set[str] = {
    "recv", "recvfrom", "read", "fread", "fgets",
    "getenv",
    "nvram_get", "nvram_safe_get", "nvram_bufget",
    "websGetVar", "websGetVarN", "GetValue", "cgiGetValue",
    "getValue", "get_cgi", "webGetVar",
    "scanf", "sscanf",
}

REMEDIATION = {
    "buffer_overflow": "Use bounded operations (strlcpy/snprintf), validate lengths, and enable FORTIFY_SOURCE.",
    "command_injection": "Avoid shell execution; use execve with a fixed argv and validate/allowlist inputs.",
    "format_string": "Pass a constant format string; never let untrusted data be the format argument.",
    "weak_crypto": "Replace with vetted primitives (SHA-256+, AES, CSPRNG) and rotate any hardcoded keys.",
}
