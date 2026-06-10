"""Inventory & classification (FR-INV). Currently: embedded secrets/credentials."""

from .secrets import scan_secrets

__all__ = ["scan_secrets"]
