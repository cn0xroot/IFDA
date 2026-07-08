"""Binary loaders. Currently ELF; PE/Mach-O can be added as separate modules."""

from .elf import is_elf, load_elf, file_hashes, extract_strings

__all__ = ["is_elf", "load_elf", "file_hashes", "extract_strings"]
