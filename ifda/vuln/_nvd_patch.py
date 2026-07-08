"""Runtime patch for a cve-bin-tool 3.4 bug: NVD_API.nvd_count_metadata()
(nvd_api.py) fetches a CVE-count estimate from nvd.nist.gov's public
dashboard, purely to size the initial pagination task list -- the real count
self-corrects from the first actual API page (services.nvd.nist.gov, a
different host) regardless. That dashboard host sits behind Cloudflare bot
protection and can 403 automated clients even when the real CVE API is
reachable fine, and the call has no fallback: a single 403 there aborts the
*entire* NVD sync (see upstream nvd_api.py:82-97, 143).

Also replaces NVD_Source.format_data_api2() (data_sources/nvd_source.py),
which has three independent bugs that all trigger on ordinary, common CVE
shapes -- not edge cases -- so a full sync is guaranteed to hit them
eventually:
  1. References `self.logger`, which NVD_Source never sets (only the
     uppercase `self.LOGGER` class attribute exists) -- AttributeError.
  2. Two debug-log lines key the local `cve` dict with `cve['id']`, but the
     dict is built with key "ID" (uppercase) a few lines above -- KeyError.
     Triggers on any CVE with a non-numeric score (e.g. "unknown", common
     for rejected/not-yet-scored entries) or non-alphanumeric severity.
  3. The CVSSv2 branch reads `cve_item["impact"]["baseMetricV4"]` (a
     copy-paste typo of "baseMetricV2") -- KeyError. Triggers on any older
     CVE that only has CVSSv2 data (pre-~2016 entries commonly do).
The fixed copy below is otherwise identical to upstream.

Imported for its side effect by _run() in cve_bin_tool.py, inside the
subprocess it spawns to invoke cve-bin-tool's own CLI in-process -- this
patches the installed package at runtime rather than editing it on disk, so
`pip install`/`conda update` of cve-bin-tool is unaffected.
"""
from __future__ import annotations

import re

from cve_bin_tool import nvd_api
from cve_bin_tool.data_sources import nvd_source

_orig_nvd_count_metadata = nvd_api.NVD_API.nvd_count_metadata


async def _nvd_count_metadata_with_fallback(session):
    try:
        return await _orig_nvd_count_metadata(session)
    except Exception:
        # Rough estimate only; load_nvd_request() overwrites this with the
        # real totalResults from the first page of actual CVE data.
        return {"Total": 300000, "Rejected": 0, "Received": 0}


nvd_api.NVD_API.nvd_count_metadata = staticmethod(_nvd_count_metadata_with_fallback)


def _format_data_api2_fixed(self, all_cve_entries):
    """Format CVE data for CVEDB (bug-fixed copy of NVD_Source.format_data_api2)."""
    cve_data = []
    affects_data = []

    self.LOGGER.debug(f"Process vuln data - {len(all_cve_entries)} entries")

    for cve_element in all_cve_entries:
        cve_item = cve_element["cve"]

        cve = {
            "ID": cve_item["id"],
            "description": cve_item["descriptions"][0]["value"],
            "severity": "unknown",
            "score": "unknown",
            "CVSS_version": "unknown",
            "CVSS_vector": "unknown",
            "last_modified": (
                cve_item["lastModified"]
                if cve_item.get("lastModified", None)
                else cve_item["published"]
            ),
        }
        if cve["description"].startswith("** REJECT **"):
            continue

        if "impact" in cve_item:
            if "baseMetricV3" in cve_item["impact"]:
                cve["CVSS_version"] = 3
                if "cvssV3" in cve_item["impact"]["baseMetricV3"]:
                    cve["severity"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get(
                        "baseSeverity", "UNKNOWN"
                    )
                    cve["score"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get(
                        "baseScore", 0
                    )
                    cve["CVSS_vector"] = cve_item["impact"]["baseMetricV3"]["cvssV3"].get(
                        "vectorString", ""
                    )
            elif "baseMetricV2" in cve_item["impact"]:
                cve["CVSS_version"] = 2
                cve["severity"] = cve_item["impact"]["baseMetricV2"].get(
                    "severity", "UNKNOWN"
                )
                if "cvssV2" in cve_item["impact"]["baseMetricV2"]:
                    cve["score"] = cve_item["impact"]["baseMetricV2"]["cvssV2"].get(
                        "baseScore", 0
                    )
                    cve["CVSS_vector"] = cve_item["impact"]["baseMetricV2"]["cvssV2"].get(
                        "vectorString", ""
                    )
        elif "metrics" in cve_item:
            cve_cvss = cve_item["metrics"]
            cvss_available = True
            if "cvssMetricV31" in cve_cvss:
                cvss_data = cve_cvss["cvssMetricV31"][0]["cvssData"]
                cve["CVSS_version"] = 3
            elif "cvssMetricV30" in cve_cvss:
                cvss_data = cve_cvss["cvssMetricV30"][0]["cvssData"]
                cve["CVSS_version"] = 3
            elif "cvssMetricV2" in cve_cvss:
                cvss_data = cve_cvss["cvssMetricV2"][0]["cvssData"]
                cve["CVSS_version"] = 2
            else:
                cvss_available = False
            if cvss_available:
                cve["severity"] = cvss_data.get("baseSeverity", "UNKNOWN")
                cve["score"] = cvss_data.get("baseScore", 0)
                cve["CVSS_vector"] = cvss_data.get("vectorString", "")

        if not cve["severity"].isalnum():
            self.LOGGER.debug(f"Severity for {cve['ID']} is invalid: {cve['severity']}")
            cve["severity"] = re.sub(r"[\W]", "", cve["severity"])

        try:
            cve["score"] = float(cve["score"])
        except ValueError:
            self.LOGGER.debug(f"Score for {cve['ID']} is invalid: {cve['score']}")
            cve["score"] = "invalid"

        cve["CVSS_vector"] = re.sub("[^A-Za-z0-9:/]", "", cve["CVSS_vector"])

        cve_data.append(cve)

        affects_list = []
        if "configurations" in cve_item:
            for configuration in cve_item["configurations"]:
                for node in configuration["nodes"]:
                    self.LOGGER.debug(f"Processing {node} for {cve_item['id']}")
                    affects_list.extend(self.parse_node_api2(node))
                    if "children" in node:
                        for child in node["children"]:
                            affects_list.extend(self.parse_node_api2(child))
        else:
            self.LOGGER.debug(f"No configuration information for {cve_item['id']}")
        for affects in affects_list:
            affects["cve_id"] = cve["ID"]

        affects_data.extend(affects_list)

    return cve_data, affects_data


nvd_source.NVD_Source.format_data_api2 = _format_data_api2_fixed
