"""FR-RE-1/3/6: disassembly, function/call-graph reconstruction, call-site xrefs.

capstone is used as the disassembly engine because it decodes every target
architecture independent of the host (most IoT firmware is MIPS/ARM, analyzed on
x86 hosts). Call targets are resolved to imported function names via the symbol
table and PLT relocations; resolution is precise for x86/x86_64 and best-effort
elsewhere (a warning is recorded on the BinaryInfo when limited).
"""

from __future__ import annotations

from dataclasses import dataclass, field

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection

from ..model import BinaryInfo, Function


@dataclass
class CallSite:
    caller: str          # enclosing function name
    address: int         # address of the call instruction
    callee: str          # resolved callee name (imported or local) or ""
    is_imported: bool
    snippet: str         # the call instruction text (evidence)


@dataclass
class DisasmResult:
    functions: list[Function] = field(default_factory=list)
    call_sites: list[CallSite] = field(default_factory=list)


# (arch, bits) -> (CS_ARCH, base CS_MODE). Endianness OR'd in at build time.
def _cs_for(info: BinaryInfo):
    a, bits = info.arch, info.bits
    big = info.endian == "big"
    CS = capstone
    table = {
        ("x86", 32): (CS.CS_ARCH_X86, CS.CS_MODE_32),
        ("x86_64", 64): (CS.CS_ARCH_X86, CS.CS_MODE_64),
        ("arm", 32): (CS.CS_ARCH_ARM, CS.CS_MODE_ARM),
        ("aarch64", 64): (CS.CS_ARCH_ARM64, CS.CS_MODE_ARM),
        ("mips", 32): (CS.CS_ARCH_MIPS, CS.CS_MODE_MIPS32),
        ("mips", 64): (CS.CS_ARCH_MIPS, CS.CS_MODE_MIPS64),
        ("ppc", 32): (CS.CS_ARCH_PPC, CS.CS_MODE_32),
        ("ppc64", 64): (CS.CS_ARCH_PPC, CS.CS_MODE_64),
    }
    key = (a, bits)
    if key not in table:
        return None
    arch, mode = table[key]
    if big:
        mode |= CS.CS_MODE_BIG_ENDIAN
    else:
        mode |= CS.CS_MODE_LITTLE_ENDIAN
    return arch, mode


def disassemble(path: str, info: BinaryInfo, max_funcs: int = 4000) -> DisasmResult:
    cs_cfg = _cs_for(info)
    if cs_cfg is None:
        info.warnings.append(f"disassembly unsupported for arch={info.arch}/{info.bits}")
        return DisasmResult()

    md = capstone.Cs(*cs_cfg)
    md.detail = True

    is_arm = info.arch == "arm"
    # ARM binaries mix ARM and Thumb code; keep a second decoder + the data
    # needed to choose per region (see _iter_arm_insns).
    md_thumb = None
    arm_mapping: list[tuple[int, str]] = []
    thumb_funcs: set[int] = set()

    result = DisasmResult()
    with open(path, "rb") as fh:
        elf = ELFFile(fh)

        arm_res = None
        if is_arm:
            big = info.endian == "big"
            mode = capstone.CS_MODE_THUMB | (
                capstone.CS_MODE_BIG_ENDIAN if big else capstone.CS_MODE_LITTLE_ENDIAN
            )
            md_thumb = capstone.Cs(capstone.CS_ARCH_ARM, mode)
            md_thumb.detail = True
            arm_mapping = _arm_mapping(elf)
            thumb_funcs = _thumb_functions(elf)

        addr_to_name = _defined_functions(elf, mask_thumb=is_arm)
        if is_arm:
            arm_res = _ArmResolver(elf, addr_to_name, info.endian == "big")
        plt_map = _plt_map(elf, info)
        # MIPS resolves external calls through the GOT, not a PLT; build the
        # GOT-address -> symbol map and use a register tracker (see _MipsResolver).
        mips = _MipsResolver(elf, info, md) if info.arch == "mips" else None

        if not plt_map and mips is None and info.arch not in ("x86", "x86_64"):
            info.warnings.append(
                f"import call-site resolution limited for arch={info.arch}; "
                "relying on import list for unsafe-API detection"
            )
        imports = set(info.imports)

        # Function ranges: prefer symbols; fall back to executable sections.
        ranges = _function_ranges(elf, addr_to_name, mask_thumb=is_arm)
        if not ranges:
            ranges = _linear_ranges(elf)

        for (start, size, name) in ranges[:max_funcs]:
            code = _read_vaddr(elf, start, size)
            if not code:
                continue
            fn = Function(name=name, address=start, size=size)
            if mips:
                mips.reset(start)
            if arm_res:
                arm_res.reset(start)
            if is_arm:
                insns = _iter_arm_insns(
                    md, md_thumb, code, start, arm_mapping, start in thumb_funcs
                )
            else:
                insns = ((i, False) for i in md.disasm(code, start))
            for insn, is_thumb in insns:
                indirect = mips.feed(insn) if mips else None
                # ARM tail-calls / interworking veneers (b.w / bx <reg>) become
                # call edges so the call graph stays connected through veneers.
                tail = arm_res.feed(insn, is_thumb) if arm_res else None
                is_c = _is_call(insn)
                if not is_c and tail is None:
                    continue
                target = _branch_target(insn) if is_c else None
                if target is None and tail is not None:
                    target = tail
                callee, imported = _resolve(target, addr_to_name, plt_map, imports)
                # Fall back to the MIPS indirect-call resolver (jalr $t9).
                if not callee and indirect:
                    callee = indirect
                    imported = callee in imports
                text = f"{insn.mnemonic} {insn.op_str}".strip()
                if callee:
                    text += f"  <{callee}>"
                result.call_sites.append(
                    CallSite(name, insn.address, callee, imported, text)
                )
                if callee:
                    fn.calls.append(callee)
                    if imported:
                        fn.callees_imported.append(callee)
            result.functions.append(fn)

    return result


# capstone exposes call membership via instruction groups when detail is on.
def _is_call(insn) -> bool:
    try:
        if capstone.CS_GRP_CALL in insn.groups:
            return True
    except Exception:
        pass
    # MIPS has no CALL group; jal/jalr/bal are its call forms.
    return insn.mnemonic in ("jal", "jalr", "bal", "bl", "blx")


def _branch_target(insn) -> int | None:
    for op in insn.operands:
        if op.type == capstone.CS_OP_IMM:
            return op.imm
    return None


def _resolve(target, addr_to_name, plt_map, imports):
    """Return (callee_name, is_imported)."""
    if target is None:
        return "", False
    if target in plt_map:
        return plt_map[target], True
    if target in addr_to_name:
        nm = addr_to_name[target]
        return nm, nm in imports
    return "", False


def _defined_functions(elf: ELFFile, mask_thumb: bool = False) -> dict[int, str]:
    out: dict[int, str] = {}
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if (
                    sym.name
                    and sym["st_info"]["type"] == "STT_FUNC"
                    and sym["st_shndx"] != "SHN_UNDEF"
                    and sym["st_value"]
                ):
                    # ARM Thumb function symbols carry a set LSB; the real
                    # instruction address is even.
                    addr = sym["st_value"] & ~1 if mask_thumb else sym["st_value"]
                    out.setdefault(addr, sym.name)
    return out


def _function_ranges(elf, addr_to_name, mask_thumb: bool = False) -> list[tuple[int, int, str]]:
    syms = []
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if (
                    sym.name
                    and sym["st_info"]["type"] == "STT_FUNC"
                    and sym["st_shndx"] != "SHN_UNDEF"
                    and sym["st_value"]
                ):
                    addr = sym["st_value"] & ~1 if mask_thumb else sym["st_value"]
                    syms.append((addr, sym["st_size"], sym.name))
    syms.sort()
    # Fill in zero sizes from the gap to the next symbol.
    ranges = []
    for i, (addr, size, name) in enumerate(syms):
        if size == 0 and i + 1 < len(syms):
            size = max(0, syms[i + 1][0] - addr)
        if size:
            ranges.append((addr, size, name))
    return ranges


def _linear_ranges(elf) -> list[tuple[int, int, str]]:
    """Stripped fallback: one pseudo-function per executable section."""
    ranges = []
    for sec in elf.iter_sections():
        if sec["sh_flags"] & 0x4 and sec["sh_size"]:  # SHF_EXECINSTR
            ranges.append((sec["sh_addr"], sec["sh_size"], f"sub_{sec['sh_addr']:x}"))
    return ranges


class _ArmResolver:
    """Resolve ARM/Thumb tail-calls and interworking veneers.

    The linker forwards a public symbol to a Thumb body through a veneer
    (`ldr ip,[pc,#k]; add ip,ip,pc; bx ip`) or a direct `b.w <target>`. Tracking
    pc-relative literal loads lets us follow the veneer so the call graph reaches
    the real function body (important for cross-binary taint through libraries).
    """

    def __init__(self, elf: ELFFile, addr_to_name: dict[int, str], big: bool):
        self.elf = elf
        self.a2n = addr_to_name
        self.little = not big
        self.reset(0)

    def reset(self, start: int) -> None:
        self.start = start
        self.regval: dict[str, int] = {}

    def _word(self, addr: int) -> int | None:
        data = _read_vaddr(self.elf, addr, 4)
        if len(data) < 4:
            return None
        return int.from_bytes(data, "little" if self.little else "big")

    def feed(self, insn, is_thumb: bool) -> int | None:
        mn, ops = insn.mnemonic, insn.operands
        REG, IMM, MEM = capstone.CS_OP_REG, capstone.CS_OP_IMM, capstone.CS_OP_MEM
        rn = insn.reg_name

        if mn.startswith("ldr") and len(ops) >= 2 and ops[1].type == MEM \
                and rn(ops[1].mem.base) == "pc":
            pc = ((insn.address + 4) & ~3) if is_thumb else (insn.address + 8)
            w = self._word(pc + ops[1].mem.disp)
            if w is not None:
                self.regval[rn(ops[0].reg)] = w
        elif mn.startswith("add") and len(ops) >= 2:
            rd = rn(ops[0].reg)
            if any(o.type == REG and rn(o.reg) == "pc" for o in ops[1:]) and rd in self.regval:
                pc = (insn.address + 4) if is_thumb else (insn.address + 8)
                self.regval[rd] = (self.regval[rd] + pc) & 0xFFFFFFFF
        elif mn.startswith("mov") and len(ops) >= 2 and ops[1].type == REG:
            src = rn(ops[1].reg)
            if src in self.regval:
                self.regval[rn(ops[0].reg)] = self.regval[src]

        # Tail-call / veneer targets.
        tgt = None
        if mn in ("b", "b.w", "b.n"):
            imm = [o.imm for o in ops if o.type == IMM]
            tgt = imm[0] if imm else None
        elif mn in ("bx", "blx") and ops and ops[0].type == REG:
            tgt = self.regval.get(rn(ops[0].reg))

        if tgt is None:
            return None
        masked = tgt & ~1
        # Only treat as an edge when it lands on a *different* known function.
        if masked in self.a2n and masked != self.start:
            return masked
        return None


def _arm_mapping(elf: ELFFile) -> list[tuple[int, str]]:
    """ARM mapping symbols: $a (ARM code), $t (Thumb code), $d (data).

    Returns a sorted [(address, kind)] list marking where each region starts.
    """
    pts: list[tuple[int, str]] = []
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                n = sym.name
                # Names are "$a"/"$t"/"$d", some toolchains append ".N".
                if n and n[0] == "$" and len(n) >= 2 and n[1] in "atd":
                    pts.append((sym["st_value"], n[1]))
    pts.sort()
    return pts


def _thumb_functions(elf: ELFFile) -> set[int]:
    """Even addresses of functions whose symbol has the Thumb LSB set."""
    out: set[int] = set()
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection):
            for sym in sec.iter_symbols():
                if (
                    sym["st_info"]["type"] == "STT_FUNC"
                    and sym["st_shndx"] != "SHN_UNDEF"
                    and sym["st_value"] & 1
                ):
                    out.add(sym["st_value"] & ~1)
    return out


def _iter_arm_insns(md_arm, md_thumb, code: bytes, start: int,
                    mapping: list[tuple[int, str]], default_thumb: bool):
    """Disassemble an ARM function, switching ARM/Thumb mode and skipping data
    regions per the mapping symbols (falling back to the function's Thumb bit
    when a region has no mapping symbol)."""
    import bisect

    end = start + len(code)
    addrs = [a for a, _ in mapping]

    # Mode in effect at `start`: nearest mapping symbol at or before it.
    i = bisect.bisect_right(addrs, start) - 1
    cur = mapping[i][1] if i >= 0 else ("t" if default_thumb else "a")

    pos = start
    j = bisect.bisect_right(addrs, start)
    segments: list[tuple[int, int, str]] = []
    while j < len(mapping) and mapping[j][0] < end:
        a, k = mapping[j]
        if a > pos:
            segments.append((pos, a, cur))
        pos, cur = a, k
        j += 1
    if pos < end:
        segments.append((pos, end, cur))

    for seg_start, seg_end, kind in segments:
        if kind == "d":  # literal pool / data — never code
            continue
        engine = md_thumb if kind == "t" else md_arm
        is_thumb = kind == "t"
        chunk = code[seg_start - start : seg_end - start]
        for insn in engine.disasm(chunk, seg_start):
            yield insn, is_thumb


def _read_vaddr(elf: ELFFile, vaddr: int, size: int) -> bytes:
    for sec in elf.iter_sections():
        sh_addr = sec["sh_addr"]
        sh_size = sec["sh_size"]
        if sh_addr and sh_addr <= vaddr < sh_addr + sh_size and sec["sh_type"] != "SHT_NOBITS":
            off = vaddr - sh_addr
            data = sec.data()
            return data[off : off + size]
    return b""


def _sx16(v: int) -> int:
    """Sign-extend a 16-bit immediate."""
    v &= 0xFFFF
    return v - 0x10000 if v & 0x8000 else v


class _MipsResolver:
    """Resolve MIPS external calls (`lw $t9, off($gp); jalr $t9`).

    MIPS o32/n32 PIC code calls externals indirectly: $gp is set up in the
    prologue, the callee address is loaded from a $gp-relative GOT slot into a
    register (usually $t9), and `jalr` jumps through it. We track register
    contents linearly within a function and map the GOT slot address back to a
    dynamic symbol via the MIPS-specific GOT layout.
    """

    def __init__(self, elf: ELFFile, info: BinaryInfo, md: "capstone.Cs"):
        self.md = md
        self.got_map = _mips_got_map(elf, info)
        self.reset()

    def reset(self, func_start: int = 0) -> None:
        self.func_start = func_start
        self.gp: int | None = None
        self.reghi: dict[str, int] = {}   # reg -> value loaded by lui
        self.regsym: dict[str, str] = {}  # reg -> resolved symbol name

    def _rn(self, reg_id: int) -> str:
        return self.md.reg_name(reg_id) or ""

    def feed(self, insn) -> str | None:
        """Update tracking; return a callee name if `insn` is a resolved jalr."""
        mn = insn.mnemonic
        ops = insn.operands
        REG, IMM, MEM = capstone.CS_OP_REG, capstone.CS_OP_IMM, capstone.CS_OP_MEM

        if mn == "lui" and len(ops) >= 2 and ops[0].type == REG and ops[1].type == IMM:
            rd = self._rn(ops[0].reg)
            self.reghi[rd] = (ops[1].imm & 0xFFFF) << 16
            self.regsym.pop(rd, None)
        elif mn in ("addiu", "daddiu") and len(ops) >= 3 and ops[2].type == IMM:
            rd, rs = self._rn(ops[0].reg), self._rn(ops[1].reg)
            hi = self.reghi.get(rs)
            if hi is not None:
                val = hi + _sx16(ops[2].imm)
                if rd == "gp":
                    self.gp = val
                self.reghi[rd] = val & 0xFFFF0000  # keep partial chains usable
        elif mn in ("lw", "ld") and len(ops) >= 2 and ops[1].type == MEM:
            rd = self._rn(ops[0].reg)
            base = self._rn(ops[1].mem.base)
            if base == "gp" and self.gp is not None:
                name = self.got_map.get(self.gp + ops[1].mem.disp)
                if name:
                    self.regsym[rd] = name
                else:
                    self.regsym.pop(rd, None)
            else:
                self.regsym.pop(rd, None)
        elif mn in ("addu", "daddu") and len(ops) >= 3 and self._rn(ops[0].reg) == "gp":
            # PIC prologue: `addu gp, gp, t9` makes gp = _gp_disp + entry addr,
            # where t9 holds the function's own address by MIPS calling convention.
            srcs = {self._rn(o.reg) for o in ops[1:] if o.type == REG}
            if "t9" in srcs and self.gp is not None:
                self.gp += self.func_start
        elif mn in ("move", "or", "addu", "daddu", "ori"):
            rd = self._rn(ops[0].reg)
            srcs = [self._rn(o.reg) for o in ops[1:]
                    if o.type == REG and self._rn(o.reg) != "zero"]
            if len(srcs) == 1 and srcs[0] in self.regsym:
                self.regsym[rd] = self.regsym[srcs[0]]
            else:
                self.regsym.pop(rd, None)

        if mn in ("jalr", "jalrc"):
            tgt = next((self._rn(o.reg) for o in reversed(ops) if o.type == REG), "")
            return self.regsym.get(tgt)
        return None


def _mips_got_map(elf: ELFFile, info: BinaryInfo) -> dict[int, str]:
    """Map GOT slot addresses to dynamic symbol names using MIPS dynamic tags.

    Global GOT entries start at index DT_MIPS_LOCAL_GOTNO and correspond to
    dynamic symbols from index DT_MIPS_GOTSYM onward.
    """
    from elftools.elf.dynamic import DynamicSection

    tags: dict[str, int] = {}
    for sec in elf.iter_sections():
        if isinstance(sec, DynamicSection):
            for tag in sec.iter_tags():
                tags[tag.entry.d_tag] = tag.entry.d_val
            break

    got_base = tags.get("DT_PLTGOT")
    local_gotno = tags.get("DT_MIPS_LOCAL_GOTNO")
    gotsym = tags.get("DT_MIPS_GOTSYM")
    symtabno = tags.get("DT_MIPS_SYMTABNO")
    if None in (got_base, local_gotno, gotsym, symtabno):
        return {}

    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is None:
        return {}

    entsize = 8 if info.bits == 64 else 4
    out: dict[int, str] = {}
    for j in range(symtabno - gotsym):
        sym_index = gotsym + j
        if sym_index >= dynsym.num_symbols():
            break
        name = dynsym.get_symbol(sym_index).name
        if name:
            out[got_base + (local_gotno + j) * entsize] = name
    return out


def _plt_reloc_names(elf: ELFFile) -> list[str]:
    """Imported symbol names in PLT-relocation order (the order PLT stubs follow)."""
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection) and sec.name in (".rela.plt", ".rel.plt"):
            symtab = elf.get_section(sec["sh_link"])
            return [symtab.get_symbol(r["r_info_sym"]).name for r in sec.iter_relocations()]
    return []


def _plt_map(elf: ELFFile, info: BinaryInfo) -> dict[int, str]:
    """Map PLT stub addresses to imported symbol names.

    Each architecture lays out `.plt` differently; `bl`/`call <stub>` lands on
    the stub address, which we map back to the relocation's symbol by index.
    """
    names = _plt_reloc_names(elf)
    if not names:
        return {}

    if info.arch in ("x86", "x86_64"):
        return _plt_map_x86(elf, names)
    if info.arch == "arm":
        # ARM PLT entry sizes vary (Thumb interworking veneers), so resolve each
        # stub by the GOT slot it loads rather than by a fixed stride.
        return _arm_plt_map(elf, info)
    if info.arch == "aarch64":
        # AArch64 PLT0 is 32 bytes; each subsequent stub is a uniform 16 bytes.
        return _plt_map_linear(elf, names, first_bytes=32, stub_bytes=16)
    return {}


def _plt_map_x86(elf: ELFFile, names: list[str]) -> dict[int, str]:
    out: dict[int, str] = {}
    for plt_name in (".plt", ".plt.sec"):
        plt = elf.get_section_by_name(plt_name)
        if plt is None:
            continue
        base = plt["sh_addr"]
        ent = plt["sh_entsize"] or 16
        # .plt has a reserved PLT0 first entry; .plt.sec does not.
        first = 1 if plt_name == ".plt" else 0
        for i, name in enumerate(names):
            out[base + (i + first) * ent] = name
    return out


def _arm_plt_map(elf: ELFFile, info: BinaryInfo) -> dict[int, str]:
    """Resolve ARM PLT stubs by the GOT slot each one loads.

    Every stub ends with `add ip, pc, #x; add ip, ip, #y; ldr pc, [ip, #z]!`,
    targeting GOT address (add_pc + x + y + z). The .rel.plt relocation whose
    r_offset equals that address names the symbol. This is robust to the varying
    entry sizes the linker emits when Thumb callers require interworking veneers.
    """
    # GOT slot address -> symbol name, from the jump-slot relocations.
    got2sym: dict[int, str] = {}
    for sec in elf.iter_sections():
        if isinstance(sec, RelocationSection) and sec.name in (".rel.plt", ".rela.plt"):
            symtab = elf.get_section(sec["sh_link"])
            for r in sec.iter_relocations():
                got2sym[r["r_offset"]] = symtab.get_symbol(r["r_info_sym"]).name
            break
    plt = elf.get_section_by_name(".plt")
    if not got2sym or plt is None:
        return {}

    base, data = plt["sh_addr"], plt.data()
    big = info.endian == "big"
    mode = capstone.CS_MODE_ARM | (
        capstone.CS_MODE_BIG_ENDIAN if big else capstone.CS_MODE_LITTLE_ENDIAN
    )
    md = capstone.Cs(capstone.CS_ARCH_ARM, mode)
    md.detail = True

    # Decode each 4-byte word independently (veneers are 2-byte Thumb and simply
    # fail to decode as ARM here, which is fine — we only need the add/ldr trio).
    decoded: dict[int, "capstone.CsInsn"] = {}
    for off in range(0, len(data) - 3, 4):
        for insn in md.disasm(data[off : off + 4], base + off):
            decoded[base + off] = insn
            break

    def last_imm(insn) -> int:
        for op in insn.operands:
            if op.type == capstone.CS_OP_IMM:
                return op.imm
        return 0

    out: dict[int, str] = {}
    for addr, insn in decoded.items():
        if insn.mnemonic != "ldr" or not insn.operands:
            continue
        ops = insn.operands
        # ldr pc, [ip, #z]!
        if not (ops[0].type == capstone.CS_OP_REG and md.reg_name(ops[0].reg) == "pc"):
            continue
        if not (ops[1].type == capstone.CS_OP_MEM and md.reg_name(ops[1].mem.base) == "ip"):
            continue
        a0, a1 = addr - 8, addr - 4
        i0, i1 = decoded.get(a0), decoded.get(a1)
        if not (i0 and i1 and i0.mnemonic == "add" and i1.mnemonic == "add"):
            continue
        got = (a0 + 8) + last_imm(i0) + last_imm(i1) + ops[1].mem.disp
        name = got2sym.get(got)
        if name:
            out[a0] = name        # ARM-mode entry point
            out[a0 - 4] = name    # Thumb interworking veneer (bx pc; b.n)
    return out


def _plt_map_linear(
    elf: ELFFile, names: list[str], first_bytes: int, stub_bytes: int
) -> dict[int, str]:
    """ARM/AArch64: a fixed-size PLT0 header followed by equal-size stubs, one
    per relocation in order."""
    plt = elf.get_section_by_name(".plt")
    if plt is None:
        return {}
    base = plt["sh_addr"]
    return {base + first_bytes + i * stub_bytes: name for i, name in enumerate(names)}
