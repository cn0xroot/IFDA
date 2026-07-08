#!/usr/bin/env python3
"""Bootstrap cve-bin-tool's local NVD cache from a GitHub mirror instead of
NVD's own live API.

Why this exists: cve-bin-tool's `-n api2` NVD sync works, but a full
historical backfill (~280k CVEs) can take the better part of a day from some
networks -- NVD's own API appears to throttle/slow generation of large
paginated (resultsPerPage=2000) responses independent of API key or client
bandwidth (observed 3-80 KB/s, wildly inconsistent, across many samples).
cve-bin-tool's own default `-n json-mirror` fallback (mirror.cveb.in) is also
unreliable -- as of writing its legacy `nvd/json/cve/1.1` path is an empty,
untouched-since-2025-05 directory.

fkie-cad/nvd-json-data-feeds (Fraunhofer FKIE) republishes the same NVD API
2.0 JSON verbatim -- each record has the same `cpeMatch`/`criteria` shape
cve-bin-tool's own NVD_Source.parse_node_api2() expects -- reorganized into a
single downloadable snapshot on GitHub Releases, synced bi-hourly:
https://github.com/fkie-cad/nvd-json-data-feeds

This script downloads that snapshot (~100MB compressed) from GitHub's CDN
(seconds to low minutes, vs. hours from NVD directly), then feeds it through
cve-bin-tool's own NVD_Source.format_data_api2() and CVEDB.populate_db(), so
the resulting local sqlite cache (~/.cache/cve-bin-tool/cve.db) is exactly
what a live NVD sync would have produced -- just without the wait. All
inserts are `INSERT OR REPLACE`, so this is safe to re-run and safe to run
alongside a cache that already has GAD/RedHat/OSV data from other sources.

Usage:
    python3 scripts/bootstrap_nvd_cache.py
"""
from __future__ import annotations

import json
import lzma
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

FEED_URL = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/CVE-all.json.xz"


def main() -> int:
    print(f"Downloading {FEED_URL} ...")
    with urllib.request.urlopen(FEED_URL, timeout=300) as resp:
        compressed = resp.read()
    print(f"Downloaded {len(compressed):,} bytes, decompressing...")
    raw = lzma.decompress(compressed)
    data = json.loads(raw)
    cve_items = data["cve_items"]
    print(
        f"Feed timestamp {data['timestamp']}, {len(cve_items):,} CVE records "
        f"(feed reports cve_count={data['cve_count']:,})"
    )

    import ifda.vuln._nvd_patch  # noqa: F401 -- side-effect patch, see that module
    from cve_bin_tool.cvedb import CVEDB
    from cve_bin_tool.data_sources.nvd_source import NVD_Source

    # format_data_api2() expects the same {"cve": {...}} wrapper the live NVD
    # API 2.0 "vulnerabilities" array uses; fkie-cad's cve_items are the bare
    # inner objects.
    all_cve_entries = [{"cve": item} for item in cve_items]
    severity_data, affected_data = NVD_Source().format_data_api2(all_cve_entries)
    print(
        f"Formatted {len(severity_data):,} severity rows, "
        f"{len(affected_data):,} affected-version rows"
    )

    db = CVEDB()
    db.init_database()
    db.data = [((severity_data, affected_data), "NVD")]
    db.populate_db()
    print("Done. NVD data merged into", db.dbpath)
    return 0


if __name__ == "__main__":
    sys.exit(main())
