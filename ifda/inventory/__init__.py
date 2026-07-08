"""Inventory & classification (FR-INV): embedded secrets/credentials plus
firmware-level metadata (kernel version, file count/size, arch/endian summary)."""

from .secrets import scan_secrets, count_certificates
from .firmware_meta import (
    detect_kernel_version, scan_tree_stats, summarize_arch_endian, list_all_files, is_config_file,
)
from .busybox_audit import audit_busybox

__all__ = ["scan_secrets", "count_certificates", "detect_kernel_version", "scan_tree_stats",
           "summarize_arch_endian", "list_all_files", "audit_busybox", "is_config_file"]
