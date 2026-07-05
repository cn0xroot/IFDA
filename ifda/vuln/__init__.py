"""Vulnerability discovery (FR-VUL): unsafe APIs, taint reachability, CVE correlation."""

from .dangerous_funcs import detect_dangerous_functions
from .taint import detect_taint_paths
from .cve import correlate_cves
from .cve_bin_tool import cve_bin_tool_available, scan_target
from .findings import prioritize, TriageStore

__all__ = [
    "detect_dangerous_functions",
    "detect_taint_paths",
    "correlate_cves",
    "cve_bin_tool_available",
    "scan_target",
    "prioritize",
    "TriageStore",
]
