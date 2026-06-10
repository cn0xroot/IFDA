"""Native signature-rule engine + optional yara-python bridge.

Rules live in ``data/secret_rules.json`` (see schema ``ifda-secret-rules/1``)
so analysts can extend the signature surface without editing code — the
requirement that the signature/DB be independently updatable (NFR-USE-2). Each
rule is a regex that flags a structured token by shape; matched values are
redacted by the caller before they reach evidence.

If ``yara`` (yara-python) is importable and ``signatures/*.yar`` files exist
next to the data dir, those run too — a drop-in for the EMBA S110 YARA stage
(FR-INT-3). The bridge is a no-op when yara-python is absent.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from ..model import Finding, Evidence, Severity

RULE = "signature-rule"

_DATA = os.path.join(os.path.dirname(__file__), "..", "data")
_RULES_JSON = os.path.join(_DATA, "secret_rules.json")
_YARA_DIR = os.path.join(_DATA, "yara")

_SEV = {s.value: s for s in Severity}


@dataclass
class Rule:
    id: str
    name: str
    vuln_class: str
    severity: Severity
    confidence: float
    regex: "re.Pattern[str]"
    remediation: str


def load_rules(path: str | None = None) -> tuple[list[Rule], str]:
    """Load and compile signature rules. Bad rules are skipped, not fatal."""
    path = path or _RULES_JSON
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return [], ""

    rules: list[Rule] = []
    for r in doc.get("rules", []):
        try:
            rules.append(
                Rule(
                    id=str(r["id"]),
                    name=str(r["name"]),
                    vuln_class=str(r.get("vuln_class", "secret")),
                    severity=_SEV.get(str(r.get("severity", "medium")).lower(), Severity.MEDIUM),
                    confidence=float(r.get("confidence", 0.6)),
                    regex=re.compile(r["regex"]),
                    remediation=str(r.get("remediation", "")),
                )
            )
        except (KeyError, re.error, TypeError):
            continue
    return rules, str(doc.get("version", ""))


def rule_count(path: str | None = None) -> int:
    return len(load_rules(path)[0])


def apply_rules(path: str, text: str, rules: list[Rule], redact) -> list[Finding]:
    """Run every rule over one file's text. ``redact`` shields raw values."""
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for rule in rules:
        for m in rule.regex.finditer(text):
            # If the rule captured a group, the secret is the group; else the
            # whole match. Dedup per (rule, value) to avoid repeat noise.
            raw = m.group(m.lastindex) if m.lastindex else m.group(0)
            key = (rule.id, raw)
            if key in seen:
                continue
            seen.add(key)
            red = redact(raw)
            ev = Evidence(binary=path, snippet=red)
            f = Finding(
                id="",
                title=rule.name,
                vuln_class=rule.vuln_class,
                severity=rule.severity,
                confidence=rule.confidence,
                component=path,
                rule=f"{RULE}:{rule.id}",
                description=f"Signature '{rule.id}' matched a {rule.name}: {red}",
                remediation=rule.remediation,
                evidence=[ev],
            )
            f.id = f.fingerprint()
            out.append(f)
    return out


# --------------------------------------------------------------------------
# Optional yara-python bridge (FR-INT-3 / EMBA S110). Dormant unless installed.
# --------------------------------------------------------------------------

def yara_available() -> bool:
    try:
        import yara  # noqa: F401
    except Exception:
        return False
    return os.path.isdir(_YARA_DIR) and any(
        n.endswith((".yar", ".yara")) for n in os.listdir(_YARA_DIR)
    )


def run_yara(path: str, yara_dir: str | None = None) -> list[Finding]:
    """Match compiled YARA rules against one file. No-op if yara-python or the
    rules directory is unavailable."""
    yara_dir = yara_dir or _YARA_DIR
    try:
        import yara
    except Exception:
        return []
    if not os.path.isdir(yara_dir):
        return []
    sources = {
        os.path.splitext(n)[0]: os.path.join(yara_dir, n)
        for n in os.listdir(yara_dir)
        if n.endswith((".yar", ".yara"))
    }
    if not sources:
        return []
    try:
        rules = yara.compile(filepaths=sources)
        matches = rules.match(path)
    except Exception:
        return []

    out: list[Finding] = []
    for mt in matches:
        meta = getattr(mt, "meta", {}) or {}
        sev = _SEV.get(str(meta.get("severity", "medium")).lower(), Severity.MEDIUM)
        f = Finding(
            id="",
            title=f"YARA: {meta.get('description', mt.rule)}",
            vuln_class=str(meta.get("vuln_class", "yara_match")),
            severity=sev,
            confidence=float(meta.get("confidence", 0.6)),
            component=path,
            rule=f"yara:{mt.rule}",
            description=f"YARA rule '{mt.rule}' matched.",
            remediation=str(meta.get("remediation", "Review the flagged artifact.")),
            evidence=[Evidence(binary=path, snippet=str(mt.rule))],
        )
        f.id = f.fingerprint()
        out.append(f)
    return out
