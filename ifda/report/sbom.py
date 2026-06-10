"""FR-REP-2 / FR-INV-5: software bill-of-materials in CycloneDX 1.5 JSON.

Aggregates the components detected across all analyzed binaries (same extractor
that feeds CVE correlation) and attaches any correlated CVEs as vulnerabilities.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from ..model import AnalysisReport
from ..vuln.cve import extract_sbom


def render_cyclonedx(report: AnalysisReport) -> str:
    # Deduplicate components across binaries by (name, version).
    components: dict[tuple[str, str], dict] = {}
    for b in report.binaries:
        for comp in extract_sbom(b):
            components.setdefault(
                (comp.name, comp.version),
                {
                    "type": "library",
                    "name": comp.name,
                    "version": comp.version,
                    "bom-ref": f"{comp.name}@{comp.version}",
                    "purl": f"pkg:generic/{comp.name}@{comp.version}",
                },
            )

    # Map correlated CVE findings onto the CycloneDX vulnerabilities array.
    vulns = []
    for f in report.findings:
        if not f.cve_ids:
            continue
        for cve in f.cve_ids:
            vulns.append(
                {
                    "id": cve,
                    "bom-ref": f.component,
                    "ratings": [{"severity": f.severity.value}],
                    "description": f.description,
                    "affects": [{"ref": f.component}],
                }
            )

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [{"vendor": "ifda", "name": "ifda", "version": report.tool_version}],
            "component": {"type": "firmware", "name": report.target},
        },
        "components": list(components.values()),
        "vulnerabilities": vulns,
    }
    return json.dumps(doc, indent=2)
