"""FR-REP-1: machine-readable JSON output (the canonical, API-facing form)."""

from __future__ import annotations

import json

from ..model import AnalysisReport, to_dict


def write_json(report: AnalysisReport, path: str) -> None:
    with open(path, "w") as fh:
        json.dump(to_dict(report), fh, indent=2)


def to_json_str(report: AnalysisReport) -> str:
    return json.dumps(to_dict(report), indent=2)
