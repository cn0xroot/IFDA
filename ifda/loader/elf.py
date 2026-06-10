"""ELF loading via pyelftools.

Covers the reverse-engineering metadata the later stages need: architecture,
endianness, bitness, ABI, imports/exports, defined symbols, and embedded
strings. Most IoT firmware binaries are ELF (ARM/MIPS), so this is the priority
format; other formats slot in as sibling loaders.
"""

from __future__ import annotations

import hashlib

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.dynamic import DynamicSection
from elftools.common.exceptions import ELFError

from ..model import BinaryInfo, Symbol

# EI_DATA -> endianness
_ENDIAN = {"ELFDATA2LSB": "little", "ELFDATA2MSB": "big"}

# e_machine -> (canonical arch name, default capstone-friendly key)
_MACHINE = {
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_ARM": "arm",
    "EM_AARCH64": "aarch64",
    "EM_MIPS": "mips",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_RISCV": "riscv",
    "EM_SH": "superh",
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"\x7fELF"
    except OSError:
        return False


def _detect_libc(imports: list[str], strings: list[str]) -> str:
    blob = "\n".join(strings)
    if "__uClibc" in blob or any("uClibc" in s for s in strings):
        return "uclibc"
    if "musl" in blob or "__libc_start_main" not in imports and "musl libc" in blob:
        return "musl"
    if "GLIBC_" in blob or "__libc_start_main" in imports:
        return "glibc"
    return ""


def _extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Printable-ASCII run extraction (FR-RE-6 backing for string xrefs)."""
    out: list[str] = []
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return out


def load_elf(path: str, max_strings: int = 5000) -> BinaryInfo:
    info = BinaryInfo(path=path, sha256=sha256_file(path))

    with open(path, "rb") as fh:
        try:
            elf = ELFFile(fh)
        except ELFError as e:
            info.warnings.append(f"not a valid ELF: {e}")
            return info

        info.format = "elf"
        info.bits = elf.elfclass
        info.endian = _ENDIAN.get(elf.header["e_ident"]["EI_DATA"], "")
        info.arch = _MACHINE.get(elf["e_machine"], elf["e_machine"])
        info.is_library = elf["e_type"] == "ET_DYN" and not _has_entry_main(elf)
        info.abi = _abi(elf)

        imports, exports = _symbols(elf)
        info.imports = sorted(imports)
        info.exports = sorted(exports)

        # Strings: pull from the whole file (cheap, catches .rodata + data).
        fh.seek(0)
        data = fh.read()
        info.strings = _extract_strings(data)[:max_strings]
        info.libc = _detect_libc(info.imports, info.strings)

    return info


def _has_entry_main(elf: ELFFile) -> bool:
    # Heuristic: ET_DYN with a defined `main` is a PIE executable, not a lib.
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if sym.name == "main" and sym["st_shndx"] != "SHN_UNDEF":
                    return True
    return False


def _abi(elf: ELFFile) -> str:
    osabi = elf.header["e_ident"]["EI_OSABI"]
    flags = elf["e_flags"]
    abi = osabi.replace("ELFOSABI_", "").lower() or "sysv"
    # ARM EABI hard/soft float hint lives in e_flags.
    if elf["e_machine"] == "EM_ARM":
        if flags & 0x400:
            abi += "+hardfloat"
        elif flags & 0x200:
            abi += "+softfloat"
    return abi


def _symbols(elf: ELFFile) -> tuple[set[str], set[str]]:
    """Return (imports, exports).

    Imports = undefined symbols (resolved at runtime from other objects).
    Exports = globally-defined function/object symbols.
    """
    imports: set[str] = set()
    exports: set[str] = set()

    for sec in elf.iter_sections():
        if not isinstance(sec, (SymbolTableSection, DynamicSection)):
            continue
        if not hasattr(sec, "iter_symbols"):
            continue
        for sym in sec.iter_symbols():
            name = sym.name
            if not name:
                continue
            stype = sym["st_info"]["type"]
            bind = sym["st_info"]["bind"]
            if sym["st_shndx"] == "SHN_UNDEF":
                if stype in ("STT_FUNC", "STT_NOTYPE"):
                    imports.add(name)
            elif bind in ("STB_GLOBAL", "STB_WEAK") and stype in (
                "STT_FUNC",
                "STT_OBJECT",
            ):
                exports.add(name)
    return imports, exports
