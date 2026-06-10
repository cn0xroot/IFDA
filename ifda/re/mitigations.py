"""FR-RE-5: detect enabled exploit mitigations per binary.

Implemented with pyelftools by reading program headers, dynamic tags, and the
symbol table — the same signals `checksec` uses — so we avoid an external
dependency.
"""

from __future__ import annotations

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.sections import SymbolTableSection

from ..model import Mitigations

# Functions whose presence indicates _FORTIFY_SOURCE instrumentation.
_FORTIFY_MARKERS = ("__memcpy_chk", "__strcpy_chk", "__sprintf_chk",
                    "__printf_chk", "__snprintf_chk", "__strcat_chk")
_CANARY_MARKERS = ("__stack_chk_fail", "__stack_chk_guard")


def detect_mitigations(path: str) -> Mitigations:
    m = Mitigations()
    with open(path, "rb") as fh:
        elf = ELFFile(fh)

        m.nx = _nx(elf)
        m.pie = elf["e_type"] == "ET_DYN"
        m.relro = _relro(elf)

        sym_names = _all_symbol_names(elf)
        m.canary = any(s in sym_names for s in _CANARY_MARKERS)
        m.fortify = any(s in sym_names for s in _FORTIFY_MARKERS)
        m.stripped = not _has_symtab(elf)

    return m


def _nx(elf: ELFFile) -> bool:
    # NX enabled when GNU_STACK is present and lacks the executable flag.
    for seg in elf.iter_segments():
        if seg["p_type"] == "PT_GNU_STACK":
            return not bool(seg["p_flags"] & 0x1)  # PF_X
    # No GNU_STACK header -> executable stack (NX off) on most loaders.
    return False


def _relro(elf: ELFFile) -> str:
    has_relro = any(seg["p_type"] == "PT_GNU_RELRO" for seg in elf.iter_segments())
    if not has_relro:
        return "none"
    # Full RELRO additionally sets BIND_NOW (or DF_BIND_NOW flag).
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW":
                    return "full"
                if tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 0x8:  # DF_BIND_NOW
                    return "full"
    return "partial"


def _all_symbol_names(elf: ELFFile) -> set[str]:
    names: set[str] = set()
    for sec in elf.iter_sections():
        if isinstance(sec, (SymbolTableSection, DynamicSection)) and hasattr(
            sec, "iter_symbols"
        ):
            for sym in sec.iter_symbols():
                if sym.name:
                    names.add(sym.name)
    return names


def _has_symtab(elf: ELFFile) -> bool:
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection) and sec.name == ".symtab":
            return sec.num_symbols() > 1
    return False
