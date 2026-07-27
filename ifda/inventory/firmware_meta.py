"""Firmware-level metadata: kernel version banner, scanned file count, and
on-disk size (FR-INV) -- surfaced on the report dashboard alongside the
per-binary detail that's already there.

Kernel version detection is independent of the ELF loader (BinaryInfo.strings
only covers ELF files that were actually loaded as such) since a kernel image
is just as often a compressed zImage/uImage blob as a bare vmlinux ELF --
either way, the classic "Linux version x.y.z ..." banner sits somewhere in
the raw bytes, which is exactly the binwalk/EMBA-style technique this mirrors.
"""

from __future__ import annotations

import os
import re
from collections import Counter

from ..loader import file_hashes, extract_strings

# Files larger than this skip MD5 computation (still listed, with size but no
# hash): a full firmware tree can include multi-hundred-MB blobs (data
# partition images, uncompressed initrds), and hashing every one of those in
# full would noticeably slow the scan for a "just let me see the file" list.
_HASH_SIZE_CAP = 64 * 1024 * 1024

_KERNEL_VERSION_RE = re.compile(rb"Linux version ([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s\x00]*)")

# Loadable-module "vermagic" carries the exact kernel a .ko was built for,
# e.g. "4.4.60 SMP preempt mod_unload ...". Present in a rootfs even when the
# kernel image itself lives in a separate partition (the common case for
# split boot/rootfs firmware) and there is no "Linux version" banner to find.
_VERMAGIC_RE = re.compile(rb"vermagic=([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s\x00]*)")

# A well-formed kernel version for the lib/modules/<version>/ fallback:
# starts x.y[.z], optionally with a local suffix (e.g. 4.4.60, 5.10.110-foo).
_MODULES_DIR_RE = re.compile(r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?[\w.+-]*$")

# Capping the read bounds worst-case scan time against a firmware with one
# huge blob (a full flash dump, an uncompressed initrd, ...). NOT "early in
# the file": a real 35MB aarch64 Image built with a modern toolchain was
# measured with its "Linux version ..." banner sitting at the ~17MB mark, well
# past a previous 8MB cap that silently missed it -- so this is sized to match
# _HASH_SIZE_CAP above rather than assume any particular offset.
_SCAN_CAP = 64 * 1024 * 1024

# Extensions/basenames that make something a config file almost by
# definition -- checked before any content sniff, so it still works for an
# oversized or otherwise-unreadable file.
_CONFIG_EXTENSIONS = {
    ".conf", ".cfg", ".config", ".ini", ".toml", ".yaml", ".yml",
    ".xml", ".properties", ".rc",
}
_CONFIG_BASENAMES = {
    "passwd", "shadow", "group", "hosts", "resolv.conf", "fstab", "inittab",
    "hostapd.conf", "dnsmasq.conf", "smb.conf", "sshd_config", "sysctl.conf",
    "services", "nsswitch.conf",
}
# UCI (OpenWrt-style) configs are extensionless but always live under a
# directory literally named "config" -- extremely common in real IoT
# firmware (e.g. /etc/config/dhcp), so a path marker catches them where the
# extension list can't.
_CONFIG_PATH_MARKER = "/config/"


def is_config_file(path: str, head: bytes | None = None) -> bool:
    """True if `path` looks like a hand-authored configuration file rather
    than a binary/data blob. Path/extension/basename heuristics run first
    (cheap, no I/O, and still correct for a file too large or unreadable to
    sniff); `head` (the file's first bytes, if the caller already has them
    in hand from its own read -- never opened again just for this) adds an
    ini "[section]" / OpenWrt-UCI "config " content sniff as a fallback for
    extensionless files outside a recognized config directory.
    """
    base = os.path.basename(path)
    ext = os.path.splitext(base)[1].lower()
    if ext in _CONFIG_EXTENSIONS or base in _CONFIG_BASENAMES:
        return True
    if _CONFIG_PATH_MARKER in path.replace(os.sep, "/"):
        return True
    if not head:
        return False
    text = head[:200].decode("utf-8", "replace").lstrip()
    return text.startswith("config ") or text.startswith("[")


def detect_kernel_version(target: str, max_entries: int = 200000) -> str:
    """Returns the kernel version for `target`, or "" if undetermined.

    Tries, in order: the classic "Linux version X.Y.Z ..." banner anywhere in
    the tree (a full kernel image); a loadable module's vermagic string; and
    finally the lib/modules/<version>/ directory name. The latter two matter
    for split boot/rootfs firmware, where the rootfs being scanned carries the
    modules but not the kernel image itself, so no banner exists to find.
    """
    if os.path.isfile(target):
        return _scan_file(target)

    modules_dir_version = ""
    n = 0
    for root, dirs, files in os.walk(target):
        # lib/modules/<version>/ -- record it as a last-resort fallback.
        if os.path.basename(root) == "modules":
            for d in dirs:
                if _MODULES_DIR_RE.match(d):
                    modules_dir_version = modules_dir_version or d
        for f in files:
            if n >= max_entries:
                return modules_dir_version
            n += 1
            path = os.path.join(root, f)
            # A firmware's extracted /dev often preserves character/block
            # device nodes (e.g. /dev/console) with their real major/minor
            # numbers. open()+read() on one of those blocks forever waiting
            # for I/O that will never come, hanging the whole analysis --
            # os.path.isfile() (like every other tree-walker in this
            # codebase: secrets.py, scripts/shell.py, scripts/langs.py)
            # returns False for anything that isn't a regular file, so this
            # skips device nodes/FIFOs/sockets without ever opening them.
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            found = _scan_file(path)
            if found:
                return found
    return modules_dir_version


def _scan_file(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            data = fh.read(_SCAN_CAP)
    except OSError:
        return ""
    m = _KERNEL_VERSION_RE.search(data)
    if m:
        return m.group(1).decode("ascii", "replace")
    # No full banner (typical of a rootfs without the kernel image), but a
    # loadable module built for this kernel carries the version in vermagic.
    m = _VERMAGIC_RE.search(data)
    if m:
        return m.group(1).decode("ascii", "replace")
    return ""


def list_all_files(
    target: str, max_entries: int = 200000, binary_paths: frozenset[str] | None = None
) -> list[dict]:
    """Every file under `target` (or `target` itself, if it's a single file):
    path, size, md5, and (for non-ELF entries) extracted strings -- the full
    listing that the Binaries/Scripts tabs can't give on their own, since
    those only cover ELF binaries and recognized shell/php/python/lua scripts
    respectively. Everything else in a real firmware tree (configs, web
    assets, data files, symlinks) only shows up here, which is what actually
    answers "did the scan cover this whole directory" for a human looking at
    the results.

    Strings are extracted for everything except `binary_paths` (already
    covered by BinaryInfo.strings from the ELF loader -- no need to pay for
    it twice) so that config files and scripts feed the same
    Strings/Sensitive-strings hunting the UI otherwise limits to ELF binaries
    -- IoT vendors leave default creds in init scripts and .conf files just as
    often as in binaries.

    Symlinks and anything that isn't a regular file (device nodes, FIFOs,
    sockets) are listed with a size but no md5/strings -- never opened, for
    the same reason detect_kernel_version() never opens them (see its
    comment: reading a device node like /dev/console blocks forever).
    """
    binary_paths = binary_paths or frozenset()
    if os.path.isfile(target):
        try:
            size = os.path.getsize(target)
        except OSError:
            return []
        data = b"" if target in binary_paths else _read_capped(target, size)
        strings = extract_strings(data)[:_STRINGS_MAX_PER_FILE] if data else []
        is_cfg = target not in binary_paths and is_config_file(target, data or None)
        return [{"path": target, "size": size, "md5": _hash_if_worth_it(target, size),
                 "is_symlink": False, "strings": strings, "is_config": is_cfg}]

    out: list[dict] = []
    n = 0
    for root, _dirs, files in os.walk(target):
        for f in files:
            if n >= max_entries:
                return out
            n += 1
            path = os.path.join(root, f)
            is_link = os.path.islink(path)
            if is_link or not os.path.isfile(path):
                try:
                    size = os.lstat(path).st_size
                except OSError:
                    size = 0
                out.append({"path": path, "size": size, "md5": "", "is_symlink": is_link,
                            "strings": [], "is_config": False})
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            # Read once, reused for both string extraction and the config
            # content-sniff fallback -- avoids opening the same file twice.
            data = b"" if path in binary_paths else _read_capped(path, size)
            strings = extract_strings(data)[:_STRINGS_MAX_PER_FILE] if data else []
            is_cfg = path not in binary_paths and is_config_file(path, data or None)
            out.append({"path": path, "size": size, "md5": _hash_if_worth_it(path, size),
                        "is_symlink": False, "strings": strings, "is_config": is_cfg})
    return out


def _hash_if_worth_it(path: str, size: int) -> str:
    if size > _HASH_SIZE_CAP:
        return ""
    try:
        _, md5 = file_hashes(path)
    except OSError:
        return ""
    return md5


# Config files are almost always tiny; a regular file this large under
# "other"/"script" is far more likely a data blob (web assets, a factory
# image) than hand-authored config, so skip string extraction rather than pay
# to scan it -- structured secret detection (scan_secrets) still covers it via
# its own (higher, 8 MiB) cap regardless.
_STRINGS_SIZE_CAP = 2 * 1024 * 1024
# Caps report size across a tree with thousands of these entries.
_STRINGS_MAX_PER_FILE = 500


def _read_capped(path: str, size: int) -> bytes:
    """Read up to _STRINGS_SIZE_CAP bytes of `path`, or b"" if it's empty,
    oversized, or unreadable. Shared by string extraction and the config
    content-sniff fallback (is_config_file) so a file is never opened twice
    just to classify it two different ways."""
    if size == 0 or size > _STRINGS_SIZE_CAP:
        return b""
    try:
        with open(path, "rb") as fh:
            return fh.read(_STRINGS_SIZE_CAP)
    except OSError:
        return b""


def scan_tree_stats(target: str, max_entries: int = 200000) -> tuple[int, int]:
    """Returns (file_count, total_bytes) for `target` -- a single file counts
    as one file of its own size."""
    if os.path.isfile(target):
        try:
            return 1, os.path.getsize(target)
        except OSError:
            return 1, 0
    count = 0
    total = 0
    for root, _dirs, files in os.walk(target):
        for f in files:
            if count >= max_entries:
                return count, total
            path = os.path.join(root, f)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            count += 1
            total += st.st_size
    return count, total


def summarize_arch_endian(archs: list[str], endians: list[str]) -> tuple[str, str]:
    """Majority architecture/endianness across a report's binaries -- a
    single overall label for the dashboard, not a per-binary breakdown
    (already available in the Binaries tab). Empty strings (unknown/failed
    to load) are excluded from the vote."""

    def majority(values: list[str]) -> str:
        counted = Counter(v for v in values if v)
        return counted.most_common(1)[0][0] if counted else ""

    return majority(archs), majority(endians)
