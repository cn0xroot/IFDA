"""BusyBox applet audit + /etc/init.d script dump (FR-INV).

Embedded Linux firmware conventionally implements most standard utilities as
busybox applets rather than standalone binaries (see ../vuln/backdoor.py for
the security angle on that). This module answers two different questions an
analyst asks about that setup:

  - which applets did this *particular* busybox build actually compile in,
    versus a reference list of known BusyBox applets -- the ones missing
    could be a deliberate hardening choice (no telnetd/ftpd) or something an
    attacker stripped for their own reasons, but either way it's worth a
    human look ("crippled" busybox);
  - what else lives in bin/sbin beyond busybox -- standalone vendor tools
    and daemons genuinely additional to what busybox provides, across every
    bin/sbin directory in the tree (not just the top-level /bin, /sbin --
    real firmware often has several, e.g. /bin, /usr/bin, /usr/sbin, plus
    vendor-specific ones).

Applet detection is string-based, not execution-based: firmware binaries are
foreign-arch and can't be safely run here. BusyBox's applet table stores each
compiled-in applet's name as its own NUL-terminated string, which lines up
exactly with how extract_strings() tokenizes printable runs -- so "applet
name is an exact element of this binary's string set" is a reliable signal,
unlike a substring search that could false-positive on unrelated text. The
busybox binary(ies) are read directly here (not reused from BinaryInfo.strings)
to avoid load_elf's max_strings cap silently truncating away real applet
names in a busybox build with thousands of unrelated strings.

Also collects every /etc/init.d (or vendor equivalent) script's source, since
"what does this init script actually do" is a very common firmware-audit
question and there was previously no way to see script content without
downloading the extracted tree yourself.
"""

from __future__ import annotations

import os
import stat

from ..loader import extract_strings, is_elf
from ..model import BusyboxAudit, ExtraCommand, InitScript

_BIN_DIR_NAMES = {"bin", "sbin"}
_INITD_DIR_NAME = "init.d"

_MAX_EXTRA_COMMANDS = 2000
_MAX_INIT_SCRIPTS = 500
_INIT_SCRIPT_SIZE_CAP = 512 * 1024  # displayed source per script

# Reference list of known BusyBox applet names (union across recent versions;
# not exhaustive -- BusyBox has ~380 -- but broad enough that "missing from
# this build" is a meaningful signal rather than noise from an obscure applet
# nobody would expect anyway).
REFERENCE_APPLETS = frozenset({
    "[", "[[", "acpid", "add-shell", "addgroup", "adduser", "adjtimex", "ar", "arp", "arping",
    "ash", "awk", "base32", "base64", "basename", "beep", "blkdiscard", "blkid", "blockdev",
    "bootchartd", "brctl", "bunzip2", "bzcat", "bzip2", "cal", "cat", "catv", "chat", "chattr",
    "chgrp", "chmod", "chown", "chpasswd", "chpst", "chroot", "chrt", "chvt", "cksum", "clear",
    "cmp", "comm", "conspy", "cp", "cpio", "crc32", "create-shell", "crond", "crontab", "cryptpw",
    "cttyhack", "cut", "date", "dc", "dd", "deallocvt", "delgroup", "deluser", "depmod", "devmem",
    "df", "dhcprelay", "diff", "dirname", "dmesg", "dnsd", "dnsdomainname", "dos2unix", "dpkg",
    "dpkg-deb", "du", "dumpkmap", "dumpleases", "echo", "ed", "egrep", "eject", "env", "envdir",
    "envuidgid", "ether-wake", "expand", "expr", "factor", "fakeidentd", "fallocate", "false",
    "fatattr", "fbset", "fbsplash", "fdflush", "fdformat", "fdisk", "fgconsole", "fgrep", "find",
    "findfs", "flock", "fold", "free", "freeramdisk", "fsck", "fsck.minix", "fsfreeze", "fstrim",
    "fsync", "ftpd", "ftpget", "ftpput", "fuser", "getopt", "getty", "grep", "groups", "gunzip",
    "gzip", "halt", "hd", "hdparm", "head", "hexdump", "hexedit", "hostid", "hostname", "httpd",
    "hush", "hwclock", "i2cdump", "i2cget", "i2cset", "i2ctransfer", "id", "ifconfig", "ifdown",
    "ifenslave", "ifplugd", "ifup", "inetd", "init", "insmod", "install", "ionice", "iostat", "ip",
    "ipaddr", "ipcalc", "ipcrm", "ipcs", "iplink", "ipneigh", "iproute", "iprule", "iptunnel",
    "kbd_mode", "kill", "killall", "killall5", "klogd", "last", "less", "link", "linux32",
    "linux64", "linuxrc", "ln", "loadfont", "loadkmap", "logger", "login", "logname", "logread",
    "losetup", "lpd", "lpq", "lpr", "ls", "lsattr", "lsmod", "lsof", "lspci", "lsscsi", "lsusb",
    "lzcat", "lzma", "lzop", "makedevs", "makemime", "man", "md5sum", "mdev", "mesg", "microcom",
    "mkdir", "mkdosfs", "mke2fs", "mkfifo", "mkfs.ext2", "mkfs.minix", "mkfs.vfat", "mknod",
    "mkpasswd", "mkswap", "mktemp", "modinfo", "modprobe", "more", "mount", "mountpoint", "mpstat",
    "mt", "mv", "nameif", "nanddump", "nandwrite", "nbd-client", "nc", "netstat", "nice", "nl",
    "nmeter", "nohup", "nologin", "nproc", "nsenter", "nslookup", "ntpd", "od", "openvt",
    "partprobe", "passwd", "paste", "patch", "pgrep", "pidof", "ping", "ping6", "pipe_progress",
    "pivot_root", "pkill", "pmap", "popmaildir", "poweroff", "printenv", "printf", "ps", "pscan",
    "pstree", "pwd", "pwdx", "raidautorun", "rdate", "rdev", "readahead", "readlink", "readprofile",
    "realpath", "reboot", "reformime", "remove-shell", "renice", "reset", "resize", "resume",
    "rev", "rm", "rmdir", "rmmod", "route", "rpm", "rpm2cpio", "rtcwake", "run-init", "run-parts",
    "runlevel", "runsv", "runsvdir", "rx", "script", "scriptreplay", "sed", "sendmail", "seq",
    "setarch", "setconsole", "setfattr", "setfont", "setkeycodes", "setlogcons", "setpriv",
    "setserial", "setsid", "setuidgid", "sh", "sha1sum", "sha256sum", "sha3sum", "sha512sum",
    "showkey", "shred", "shuf", "slattach", "sleep", "smemcap", "softlimit", "sort", "split",
    "ssl_client", "start-stop-daemon", "stat", "strings", "stty", "su", "sulogin", "sum", "sv",
    "svc", "svlogd", "svok", "swapoff", "swapon", "switch_root", "sync", "sysctl", "syslogd",
    "tac", "tail", "tar", "taskset", "tc", "tcpsvd", "tee", "telnet", "telnetd", "test", "tftp",
    "tftpd", "time", "timeout", "top", "touch", "tr", "traceroute", "traceroute6", "true",
    "truncate", "ts", "tty", "ttysize", "tunctl", "ubiattach", "ubidetach", "ubimkvol",
    "ubirename", "ubirmvol", "ubirsvol", "ubiupdatevol", "udhcpc", "udhcpc6", "udhcpd", "udpsvd",
    "uevent", "umount", "uname", "unexpand", "uniq", "unix2dos", "unlink", "unlzma", "unshare",
    "unxz", "unzip", "uptime", "users", "usleep", "uudecode", "uuencode", "vconfig", "vi", "vlock",
    "volname", "wall", "watch", "watchdog", "wc", "wget", "which", "who", "whoami", "whois",
    "xargs", "xxd", "xz", "xzcat", "yes", "zcat", "zcip",
})


def audit_busybox(target: str, busybox_paths: list[str], max_entries: int = 200000,
                   file_kind_map: dict[str, str] | None = None) -> BusyboxAudit:
    """`busybox_paths`: absolute paths of every non-symlink busybox binary
    already found elsewhere in the pipeline (report.binaries, filtered by
    basename == "busybox") -- avoids a redundant tree walk just to find them
    again here.

    `file_kind_map`: path -> kind ("binary"/"script"/"symlink"/"other"),
    already computed for the full-tree file listing (FileEntry, which
    recognizes shell/php/python/lua scripts, not just ELF) -- reused so a
    vendor shell script under bin/sbin shows up as "script" rather than
    falling back to the cruder ELF-or-not classification below when absent.
    """
    audit = BusyboxAudit(has_busybox=bool(busybox_paths), busybox_paths=list(busybox_paths))

    busybox_strings: set[str] = set()
    for p in busybox_paths:
        try:
            with open(p, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        # min_len=1, not extract_strings' usual default of 4: plenty of
        # applet names are shorter than that (ls, sh, vi, su, id, w, ...),
        # and since the result only ever feeds a set-membership check
        # against REFERENCE_APPLETS below, the extra short-string noise
        # this pulls in is harmless -- it just never matches anything.
        busybox_strings.update(extract_strings(data, min_len=1))

    compiled_in_set = REFERENCE_APPLETS & busybox_strings if audit.has_busybox else set()
    audit.compiled_in = sorted(compiled_in_set)
    audit.missing = sorted(REFERENCE_APPLETS - compiled_in_set) if audit.has_busybox else []

    if os.path.isfile(target):
        return audit

    n = 0
    for root, _dirs, files in os.walk(target):
        base = os.path.basename(root)
        is_bin_dir = audit.has_busybox and base in _BIN_DIR_NAMES
        is_initd = base == _INITD_DIR_NAME
        if not is_bin_dir and not is_initd:
            continue
        for f in files:
            if n >= max_entries:
                return audit
            n += 1
            path = os.path.join(root, f)

            if is_initd:
                if len(audit.init_scripts) < _MAX_INIT_SCRIPTS:
                    _collect_init_script(path, audit)
                else:
                    audit.truncated_init = True

            if is_bin_dir:
                _collect_extra_command(path, f, target, compiled_in_set, audit, file_kind_map)
    return audit


def _collect_init_script(path: str, audit: BusyboxAudit) -> None:
    # Same reasoning as every other tree-walker in this codebase: a device
    # node/FIFO/socket must never be opened, or read() blocks forever.
    if os.path.islink(path) or not os.path.isfile(path):
        return
    try:
        with open(path, "rb") as fh:
            data = fh.read(_INIT_SCRIPT_SIZE_CAP + 1)
    except OSError:
        return
    truncated = len(data) > _INIT_SCRIPT_SIZE_CAP
    content = data[:_INIT_SCRIPT_SIZE_CAP].decode("utf-8", "replace")
    audit.init_scripts.append(InitScript(path=path, content=content, truncated=truncated))


def _collect_extra_command(path: str, name: str, target: str, compiled_in_set: set[str],
                            audit: BusyboxAudit, file_kind_map: dict[str, str] | None) -> None:
    if len(audit.extra_commands) >= _MAX_EXTRA_COMMANDS:
        audit.truncated_extra = True
        return
    # Not "extra" if busybox itself, or a name this busybox build actually
    # compiled in (a standalone binary with that name is a separate,
    # already-covered anomaly -- see vuln/backdoor.py's shadowing check).
    if name == "busybox" or name in compiled_in_set:
        return
    try:
        st = os.lstat(path)
    except OSError:
        return
    rel_dir = "/" + os.path.dirname(os.path.relpath(path, target))

    if stat.S_ISLNK(st.st_mode):
        try:
            link_target = os.readlink(path)
        except OSError:
            return
        if os.path.basename(link_target) == "busybox":
            return  # the normal case: a plain busybox-provided command
        audit.extra_commands.append(ExtraCommand(path=path, name=name, kind="symlink", dir=rel_dir))
        return

    if not stat.S_ISREG(st.st_mode):
        return
    kind = (file_kind_map or {}).get(path) or ("binary" if is_elf(path) else "other")
    audit.extra_commands.append(ExtraCommand(path=path, name=name, kind=kind, dir=rel_dir))
