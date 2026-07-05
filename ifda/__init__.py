"""ifda — automated IoT firmware binary analysis core.

First iteration scope (per requirements doc): binary reverse engineering (FR-RE)
and vulnerability discovery (FR-VUL). Ingestion/extraction (FR-ING/FR-EXT) are
assumed to have already produced extracted artifacts on disk; this core analyzes
the binaries within them.

Design: Python analysis core wrapping existing tooling (capstone, pyelftools,
binutils). A separate service/orchestration layer (Go) is intended to drive this
core for batch/corpus work — see README.
"""

__version__ = "1.3.0"
