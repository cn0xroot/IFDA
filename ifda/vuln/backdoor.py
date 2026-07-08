"""Non-busybox command detector (suspected backdoor signal).

Embedded Linux firmware conventionally implements most standard utilities
(ls, ps, ifconfig, telnetd, sh, ...) as symlinks into a single busybox
multi-call binary rather than as separate standalone executables -- this is
almost always true whenever busybox is present at all, since duplicating each
applet as its own binary would waste the flash space the toolchain is
specifically trying to save. A standalone, non-symlink binary that
nonetheless implements one of these conventionally-busybox-provided command
names is therefore a real anomaly worth surfacing: either a legitimate (if
unusual) separately-built utility, or -- the case this exists to catch --
something planted to shadow/replace the expected implementation. Dropping a
standalone `/bin/login` or `/usr/sbin/telnetd` that authenticates however the
attacker likes, alongside or instead of the busybox-provided one, is a
well-known IoT backdoor technique.

This only fires when busybox itself is present somewhere in the same tree --
without it, "should be a busybox symlink" doesn't apply, and flagging every
standalone coreutils build in a non-busybox rootfs would be pure noise.

Symlinks are checked by their literal link-target text (os.readlink), never
resolved with os.path.realpath: an extracted firmware tree isn't a chroot, so
an absolute symlink (e.g. "/bin/busybox", valid on the real device root)
would otherwise resolve against *this host's* filesystem instead of the
extracted tree -- the same reason every other scanner in this codebase
(inventory/secrets.py, scripts/shell.py, scripts/langs.py) skips symlinks
outright rather than following them.
"""

from __future__ import annotations

import os
import stat

from ..loader import is_elf
from ..model import Finding, Evidence, Severity

RULE = "non-busybox-command"

# Command names conventionally provided as busybox symlinks in embedded
# Linux rootfs, split out by how sensitive it'd be for something else to
# silently take over the name. Not exhaustive -- busybox ships ~400 applets --
# just the common, security-relevant subset likely to appear in IoT firmware.
_HIGH_RISK_APPLETS = {
    "login", "sh", "ash", "bash", "sshd", "telnetd", "ftpd", "httpd",
    "passwd", "su", "adduser", "useradd", "inetd", "dropbear",
}
_APPLETS = _HIGH_RISK_APPLETS | {
    "ls", "cat", "ps", "mount", "umount", "ifconfig", "route", "ping",
    "cp", "mv", "rm", "mkdir", "rmdir", "chmod", "chown", "grep", "sed",
    "awk", "find", "tar", "gzip", "gunzip", "wget", "nc", "netstat",
    "ip", "iptables", "kill", "killall", "top", "vi", "ed",
    "start-stop-daemon", "syslogd", "klogd", "udhcpc", "udhcpd", "hwclock",
    "insmod", "rmmod", "modprobe", "reboot", "poweroff", "halt", "init",
    "crond", "date", "df", "du", "free", "sleep", "sync", "echo",
    "printf", "head", "tail", "sort", "uniq", "wc", "xargs", "which",
}


def scan_backdoors(target: str, max_entries: int = 200000) -> list[Finding]:
    """FR-VUL: flag standalone binaries shadowing conventionally-busybox
    command names, when busybox is present in `target`."""
    if os.path.isfile(target):
        return []  # applies to an extracted tree, same as fs hardening

    has_busybox = False
    candidates: list[str] = []
    n = 0
    for root, _dirs, files in os.walk(target):
        for f in files:
            if n >= max_entries:
                break
            n += 1
            path = os.path.join(root, f)
            if f == "busybox":
                try:
                    if not stat.S_ISLNK(os.lstat(path).st_mode):
                        has_busybox = True
                except OSError:
                    pass
            elif f in _APPLETS:
                candidates.append(path)
        if n >= max_entries:
            break

    if not has_busybox:
        return []  # nothing to compare against; avoid noise on non-busybox rootfs

    out: list[Finding] = []
    for path in candidates:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            try:
                link_target = os.readlink(path)
            except OSError:
                continue
            if os.path.basename(link_target) != "busybox":
                out.append(_mk(path, target, symlink_target=link_target))
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        out.append(_mk(path, target, symlink_target=None))
    return out


def _mk(path: str, target: str, symlink_target: str | None) -> Finding:
    base = os.path.basename(path)
    rel = "/" + os.path.relpath(path, target)
    high_risk = base in _HIGH_RISK_APPLETS

    if symlink_target is not None:
        sev, conf = Severity.LOW, 0.4
        title = f"{base}: symlink bypasses busybox"
        desc = (f"{rel} is a symlink to '{symlink_target}', not busybox, even though "
                "busybox is present and conventionally provides this command. Could be "
                "an intentional alternate provider, or worth reviewing.")
    else:
        elf = is_elf(path)
        sev = Severity.HIGH if high_risk else Severity.MEDIUM
        conf = 0.65 if high_risk else 0.45
        title = f"{base}: standalone binary shadows busybox applet"
        desc = (f"{rel} is a standalone {'ELF binary' if elf else 'file'} implementing "
                f"'{base}', a command busybox (present in this firmware) conventionally "
                "provides via symlink. This deviates from the expected pattern"
                + (" for a security-sensitive command" if high_risk else "")
                + " and may indicate a planted replacement (backdoor) rather than a "
                  "legitimate separately-built utility.")

    f = Finding(
        id="",
        title=title,
        vuln_class="suspected_backdoor",
        severity=sev,
        confidence=conf,
        component=rel,
        rule=RULE,
        description=desc,
        remediation=(f"Verify {rel}'s provenance and behavior; if unintended, remove it "
                     "and restore the busybox symlink."),
        evidence=[Evidence(binary=path)],
    )
    f.id = f.fingerprint()
    return f
