"""Binary loaders. Currently ELF; PE/Mach-O can be added as separate modules."""

from .elf import is_elf, load_elf

__all__ = ["is_elf", "load_elf"]
