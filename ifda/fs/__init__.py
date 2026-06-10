"""Filesystem configuration & hardening checks (FR-INV / attack surface)."""

from .hardening import scan_filesystem

__all__ = ["scan_filesystem"]
