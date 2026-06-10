"""FR-VUL-7 prioritization and FR-VUL-8 triage persistence."""

from __future__ import annotations

import json
import os

from ..model import Finding, Severity, SEVERITY_RANK, TriageState


def prioritize(findings: list[Finding]) -> list[Finding]:
    """Order by severity then confidence (highest first). Stable for diffing."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_RANK[f.severity], f.confidence),
        reverse=True,
    )


class TriageStore:
    """Persist analyst triage decisions keyed by finding fingerprint so they
    survive re-scans (FR-VUL-8). Backed by a simple JSON file; the Go service
    layer can swap this for a database via the same get/set interface.
    """

    def __init__(self, path: str):
        self.path = path
        self._states: dict[str, str] = {}
        if os.path.exists(path):
            with open(path) as fh:
                self._states = json.load(fh)

    def apply(self, findings: list[Finding]) -> None:
        for f in findings:
            state = self._states.get(f.id)
            if state:
                f.triage = TriageState(state)

    def set(self, finding_id: str, state: TriageState) -> None:
        self._states[finding_id] = state.value
        self._flush()

    def active(self, findings: list[Finding]) -> list[Finding]:
        """Drop findings the analyst marked false-positive/accepted-risk."""
        muted = {TriageState.FALSE_POSITIVE, TriageState.ACCEPTED_RISK}
        return [f for f in findings if f.triage not in muted]

    def _flush(self) -> None:
        with open(self.path, "w") as fh:
            json.dump(self._states, fh, indent=2)
