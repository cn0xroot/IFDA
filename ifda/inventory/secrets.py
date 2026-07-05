"""FR-INV-4: locate embedded secrets and credential material.

Inspired by EMBA's credential/key modules (private keys, password hashes in
passwd/shadow, hardcoded passwords/tokens). Scans the whole extracted tree —
config files and scripts, not just ELF binaries — since that is where most IoT
secrets live. Each finding carries a confidence level, as the requirement asks.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter

from ..model import Finding, Evidence, Severity
from ..rules import load_rules, apply_rules, run_yara, yara_available

RULE = "embedded-secret"

# Skip files larger than this for line-oriented scanning (decompression-bomb /
# performance guard, aligned with NFR-SEC-2).
_MAX_BYTES = 8 * 1024 * 1024

_PEM_PRIVATE = re.compile(
    # "PRIVATE KEY" covers RSA/EC/DSA/OpenSSH/PGP; "AES KEY" is a distinct PEM
    # header (raw AES key block) EMBA's deep_key_search.cfg also flags and our
    # own list didn't have.
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    r"|-----BEGIN .*AES KEY-----"
)
_CERT = re.compile(r"-----BEGIN CERTIFICATE-----")

# Unix password hash field: $id$...  (id: 1=MD5,2*=bcrypt,5=SHA256,6=SHA512,y=yescrypt)
_SHADOW = re.compile(
    r"^([A-Za-z0-9_.-]+):(\$(?P<id>1|2[abxy]?|5|6|y|gy|7)\$[^:\s]+|[A-Za-z0-9./]{13}):",
    re.MULTILINE,
)

# Hardcoded credential assignment in configs/scripts. The key word may carry an
# identifier prefix (db_password, user_passwd, x_api_key), so allow one.
_ASSIGN = re.compile(
    r"(?i)\b([a-z0-9_.-]{0,24}?"
    r"(?:password|passwd|pwd|api[_-]?key|secret|auth[_-]?token|access[_-]?token))"
    r"\s*[=:]\s*[\"']?([^\s\"'#;]{4,})"
)
# Obvious non-secrets to suppress (placeholders / variable references).
_PLACEHOLDER = re.compile(
    r"^(?:\$|%|\{|<|x{3,}|\*{3,}|none|null|true|false|changeme|example|your[_-]?|"
    r"password|passwd|to_be_|n/?a)$",
    re.IGNORECASE,
)

# Provider-token signatures (AWS/GitHub/OpenAI/Google/JWT/...) live in the
# externalized rule file (data/secret_rules.json) so they update without code
# changes (NFR-USE-2); loaded once per process.
_RULES, _RULES_VERSION = load_rules()

# Hash ids considered weak/fast (higher severity when found).
_WEAK_HASH_IDS = {"1"}          # MD5-crypt
_DES_HASH_LEN = 13              # legacy DES crypt (the bare 13-char alternative)

# --- Entropy fallback: catches prefix-less random secrets (hex/base64) -------
# A token must look secret-shaped before we measure entropy.
# Dot is in the boundary (not the body) so dotted structures like JWTs — already
# covered by a signature rule — aren't re-flagged piecewise as entropy hits.
_TOKEN = re.compile(r"(?<![A-Za-z0-9+/=_.-])[A-Za-z0-9+/=_-]{20,80}(?![A-Za-z0-9+/=_.-])")
_HEX = re.compile(r"^[0-9a-fA-F]+$")
# A secret-ish keyword within this many chars before a token raises confidence.
_KEYHINT = re.compile(
    r"(?i)(?:secret|token|api[_-]?key|passw|pwd|credential|private|"
    r"access[_-]?key|auth|session|cipher|aes|hmac|salt)[\"'\s]*[=:][\"'\s]*$"
)
_ENTROPY_B64_MIN = 4.0    # bits/char; random base64 ~5.0, English ~3.0
_ENTROPY_HEX_MIN = 3.2    # hex caps at 4.0; random hex ~3.9
_MAX_ENTROPY_HITS = 25    # per-file noise cap

# C++ Itanium-mangled symbol names (e.g. "_ZNSt14basic_ifstream...") are mixed
# alphanumeric with high character diversity and routinely clear the entropy
# bar, but they are compiler-generated identifiers, not secrets. Mangling
# grammar encodes each identifier segment as <decimal-length><that-many-chars>
# (e.g. "14basic_ifstream" = 14 chars of "basic_ifstream"); real random
# secrets satisfy that invariant more than once in the same token only by
# extreme coincidence, so it is a reliable discriminator without needing a
# demangler dependency.
_MANGLE_PREFIXES = ("_Z", "St", "NSt", "Ios_", "cxx11")


def _looks_mangled(tok: str) -> bool:
    if tok.startswith(_MANGLE_PREFIXES):
        return True
    hits = 0
    i, n = 0, len(tok)
    while i < n:
        if tok[i].isdigit():
            j = i
            while j < n and tok[j].isdigit():
                j += 1
            length = int(tok[i:j])
            ident = tok[j:j + length]
            if (1 <= length <= 40 and len(ident) == length and ident
                    and (ident[0].isalpha() or ident[0] == "_")
                    and all(c.isalnum() or c == "_" for c in ident)):
                hits += 1
                if hits >= 2:
                    return True
                i = j + length
                continue
        i += 1
    return False


def scan_secrets(target: str, max_files: int = 20000) -> list[Finding]:
    findings: list[Finding] = []
    count = 0
    for path in _iter_files(target):
        if count >= max_files:
            break
        count += 1
        try:
            with open(path, "rb") as fh:
                raw = fh.read(_MAX_BYTES)
        except OSError:
            continue
        text = raw.decode("latin-1", errors="replace")
        findings.extend(_scan_text(path, text))
        if _yara_on:
            findings.extend(run_yara(path))
    return findings


# Resolved once: the optional YARA stage only runs if yara-python + .yar files
# are present (FR-INT-3 / EMBA S110); otherwise the native rule engine carries it.
_yara_on = yara_available()


def _iter_files(target: str):
    if os.path.isfile(target):
        yield target
        return
    for root, _dirs, names in os.walk(target):
        for n in names:
            p = os.path.join(root, n)
            if not os.path.islink(p) and os.path.isfile(p):
                yield p


def _scan_text(path: str, text: str) -> list[Finding]:
    out: list[Finding] = []
    base = os.path.basename(path)

    if _PEM_PRIVATE.search(text):
        out.append(_mk(path, "private_key", Severity.CRITICAL, 0.95,
                       "Embedded private key",
                       "PEM private key material found in firmware.",
                       "Remove the key from the image; rotate it; provision per-device keys.",
                       _line_of(text, _PEM_PRIVATE)))

    # Externalized provider-token signatures (NFR-USE-2): AWS/GitHub/JWT/...
    out.extend(apply_rules(path, text, _RULES, _redact))

    # Password hashes (passwd/shadow style). Most credible in those files but we
    # scan every file since vendors copy hashes into scripts/configs too.
    for m in _SHADOW.finditer(text):
        hid = m.group("id")
        hash_field = m.group(2)
        is_des = hid is None and len(hash_field) == _DES_HASH_LEN
        weak = is_des or (hid in _WEAK_HASH_IDS)
        sev = Severity.HIGH if weak else Severity.MEDIUM
        kind = "DES" if is_des else (f"$ {hid} $" if hid else "?")
        out.append(_mk(path, "password_hash", sev, 0.7 if base in ("shadow", "passwd") else 0.5,
                       f"Password hash for user '{m.group(1)}'",
                       f"{'Weak ' if weak else ''}Unix password hash ({kind}) present.",
                       "Remove default credentials; use strong, per-device passwords.",
                       f"{m.group(1)}:{_redact(hash_field)}"))

    # The same literal assignment (e.g. a string constant baked into an ELF's
    # rodata from several translation units, or a shell script that sets and
    # later re-echoes the same variable) can appear more than once in one
    # file. Evidence carries no offset/line number, so two such matches are
    # indistinguishable and would otherwise become two Finding objects with
    # an identical fingerprint — corrupting the web UI's x-for :key (see
    # Finding.fingerprint's docstring) instead of just being one finding.
    seen_assign: set[tuple[str, str]] = set()
    for m in _ASSIGN.finditer(text):
        val = m.group(2).strip()
        if _PLACEHOLDER.match(val) or val.startswith("$(") or val.startswith("${"):
            continue
        key = (m.group(1).lower(), val)
        if key in seen_assign:
            continue
        seen_assign.add(key)
        out.append(_mk(path, "hardcoded_credential", Severity.HIGH, 0.6,
                       f"Hardcoded credential ({m.group(1).lower()})",
                       f"Assignment of {m.group(1).lower()} to a literal value.",
                       "Do not ship literal credentials; load from provisioned secure storage.",
                       f"{m.group(1)}={_redact(val)}"))

    out.extend(_entropy_findings(path, text, out))
    return out


def _shannon(s: str) -> float:
    n = len(s)
    if n == 0:
        return 0.0
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _entropy_findings(path: str, text: str, already: list[Finding]) -> list[Finding]:
    """Catch prefix-less random secrets the structured rules miss. Conservative:
    only mixed-charset/hex tokens above an entropy bar, deduped, capped. A
    nearby key-like name (``token=``) lifts confidence; standalone hits stay
    low-confidence candidates for analyst review."""
    out: list[Finding] = []
    # Don't re-flag tokens a structured rule already redacted into evidence.
    claimed = {e.snippet for f in already for e in f.evidence}
    seen: set[str] = set()
    for m in _TOKEN.finditer(text):
        if len(out) >= _MAX_ENTROPY_HITS:
            break
        tok = m.group(0)
        if tok in seen:
            continue
        is_hex = bool(_HEX.match(tok))
        # Mangled C++ symbols always contain letters outside a-f (s, t, c, i, …)
        # so a token that is purely hex can never be one; skip the (more
        # expensive) mangling check for it rather than risk a false skip.
        if not is_hex and _looks_mangled(tok):
            continue
        if is_hex:
            if len(tok) < 32:                 # short hex = ids/offsets, skip
                continue
            floor = _ENTROPY_HEX_MIN
        else:
            # require both letters and digits so words/paths/base64-of-text drop
            if not (re.search(r"[A-Za-z]", tok) and re.search(r"[0-9]", tok)):
                continue
            floor = _ENTROPY_B64_MIN
        ent = _shannon(tok)
        if ent < floor:
            continue
        seen.add(tok)
        red = _redact(tok)
        if red in claimed:
            continue
        hinted = bool(_KEYHINT.search(text[max(0, m.start() - 40):m.start()]))
        if hinted:
            sev, conf, why = Severity.MEDIUM, 0.5, "assigned to a secret-like key"
        elif ent >= 4.6 and not is_hex:
            sev, conf, why = Severity.LOW, 0.35, "very high entropy"
        else:
            continue  # standalone hex / mid-entropy: too noisy to report alone
        out.append(_mk(path, "high_entropy_secret", sev, conf,
                       "High-entropy string (possible secret)",
                       f"{len(tok)}-char token, entropy {ent:.1f} bits/char, {why}; "
                       "may be an embedded key, password, or token.",
                       "Verify; if a credential, remove it and provision per-device secrets.",
                       red))
    return out


def _line_of(text: str, pat: re.Pattern) -> str:
    m = pat.search(text)
    if not m:
        return ""
    start = text.rfind("\n", 0, m.start()) + 1
    end = text.find("\n", m.start())
    return text[start : end if end != -1 else len(text)].strip()[:120]


def _redact(s: str) -> str:
    s = s.strip()
    if len(s) <= 6:
        return s[0] + "***"
    return f"{s[:3]}…{s[-2:]} (len {len(s)})"


def _mk(path, vclass, sev, conf, title, desc, remediation, snippet) -> Finding:
    ev = Evidence(binary=path, snippet=snippet)
    f = Finding(
        id="",
        title=title,
        vuln_class=vclass,
        severity=sev,
        confidence=conf,
        component=path,
        rule=RULE,
        description=desc,
        remediation=remediation,
        evidence=[ev],
    )
    f.id = f.fingerprint()
    return f
