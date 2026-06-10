"""Externalized, independently-updatable signature rules (NFR-USE-2).

A small native engine drives regex-based secret signatures loaded from
``data/secret_rules.json`` so the signature surface can be updated without
touching code. An optional yara-python bridge activates automatically if the
library and ``.yar`` files are present.
"""

from .engine import (
    Rule,
    load_rules,
    apply_rules,
    rule_count,
    yara_available,
    run_yara,
)

__all__ = [
    "Rule",
    "load_rules",
    "apply_rules",
    "rule_count",
    "yara_available",
    "run_yara",
]
