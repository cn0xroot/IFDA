"""Filesystem hardening & configuration checks (EMBA S40-S55 style).

Operates on mode bits, which extraction tools (unsquashfs, etc.) preserve even
when ownership is lost. Flags privilege-escalation and tampering surface:
setuid/setgid binaries, world-writable files/dirs, weak permissions on sensitive
files, and enumerates init/startup scripts (FR-INV-3 attack surface).
"""

from __future__ import annotations

import os
import stat

from ..model import Finding, Evidence, Severity

RULE = "fs-hardening"

# setuid on these is a classic local privesc (shell-capable / GTFOBins-like).
_DANGEROUS_SUID = {
    "sh", "bash", "ash", "dash", "ksh", "zsh", "busybox", "lua", "luajit",
    "perl", "python", "python2", "python3", "tclsh", "expect", "awk", "gawk",
    "find", "vi", "vim", "nmap", "nc", "netcat", "ncat", "gdb", "tar", "cp",
    "dd", "env", "ftp", "more", "less", "man", "ed",
}
# Files whose contents must not be world-readable.
_SECRET_FILES = {"shadow", "gshadow", "master.passwd"}
_KEY_SUFFIXES = (".key", "_key", "id_rsa", "id_dsa", "id_ecdsa", ".pem")

# Paths that hold init/startup scripts and service definitions.
_INIT_MARKERS = ("/etc/init.d/", "/etc/rc.d/", "/etc/rc.local", "/etc/inittab",
                 "/etc/systemd/", "/etc/xinetd.d/", "/etc/rcS")


def scan_filesystem(target: str, max_entries: int = 200000) -> list[Finding]:
    if os.path.isfile(target):
        return []  # hardening checks apply to an extracted tree
    out: list[Finding] = []
    n = 0
    for root, dirs, files in os.walk(target):
        for d in dirs:
            if n >= max_entries:
                return out
            n += 1
            out.extend(_check_dir(os.path.join(root, d), target))
        for f in files:
            if n >= max_entries:
                return out
            n += 1
            out.extend(_check_file(os.path.join(root, f), target))
    return out


def _rel(path: str, target: str) -> str:
    return "/" + os.path.relpath(path, target)


def _check_dir(path: str, target: str) -> list[Finding]:
    try:
        st = os.lstat(path)
    except OSError:
        return []
    if stat.S_ISLNK(st.st_mode):
        return []
    mode = st.st_mode
    if (mode & stat.S_IWOTH) and not (mode & stat.S_ISVTX):
        return [_mk(path, _rel(path, target), "world_writable_dir", Severity.MEDIUM, 0.7,
                    "World-writable directory without sticky bit",
                    f"{_rel(path, target)} is world-writable and lacks the sticky "
                    "bit; any user can rename/delete others' files here.",
                    "chmod o-w (or add the sticky bit for shared temp dirs).",
                    stat.filemode(mode))]
    return []


def _check_file(path: str, target: str) -> list[Finding]:
    try:
        st = os.lstat(path)
    except OSError:
        return []
    mode = st.st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
        return []

    rel = _rel(path, target)
    base = os.path.basename(path)
    out: list[Finding] = []

    suid = bool(mode & stat.S_ISUID)
    sgid = bool(mode & stat.S_ISGID)
    wworld = bool(mode & stat.S_IWOTH)

    # World-writable executable/script: anyone can alter code that may run privileged.
    if wworld and (mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
        out.append(_mk(path, rel, "world_writable_exec", Severity.HIGH, 0.8,
                       "World-writable executable",
                       f"{rel} is world-writable and executable; an attacker can "
                       "replace its contents.",
                       "Remove world-write (chmod o-w).", stat.filemode(mode)))
    elif wworld:
        out.append(_mk(path, rel, "world_writable_file", Severity.LOW, 0.5,
                       "World-writable file",
                       f"{rel} is writable by any user.",
                       "Remove world-write (chmod o-w).", stat.filemode(mode)))

    # setuid / setgid binaries.
    if suid or sgid:
        if wworld:
            sev, conf = Severity.CRITICAL, 0.9
        elif base in _DANGEROUS_SUID:
            sev, conf = Severity.HIGH, 0.75
        else:
            sev, conf = Severity.MEDIUM, 0.6
        bits = "setuid" if suid else ""
        bits += ("+setgid" if suid and sgid else ("setgid" if sgid else ""))
        out.append(_mk(path, rel, "setuid_binary", sev, conf,
                       f"{bits} binary: {base}",
                       f"{rel} carries the {bits} bit"
                       + (" and is shell/interpreter-capable (privesc risk)"
                          if base in _DANGEROUS_SUID else "")
                       + (" and is world-writable" if wworld else "") + ".",
                       "Drop the setuid/setgid bit unless strictly required; prefer "
                       "capabilities or a privilege broker.", stat.filemode(mode)))

    # Sensitive files readable by others.
    if (mode & stat.S_IROTH):
        if base in _SECRET_FILES:
            out.append(_mk(path, rel, "weak_permissions", Severity.HIGH, 0.85,
                           f"World-readable {base}",
                           f"{rel} contains password hashes and is world-readable.",
                           "chmod 600 (root-only).", stat.filemode(mode)))
        elif base.endswith(_KEY_SUFFIXES) or base in ("id_rsa", "id_dsa"):
            out.append(_mk(path, rel, "weak_permissions", Severity.HIGH, 0.7,
                           f"World-readable key file: {base}",
                           f"{rel} looks like private-key material and is "
                           "world-readable.",
                           "chmod 600 and store per-device.", stat.filemode(mode)))

    # Init / startup scripts: attack-surface inventory (FR-INV-3).
    if any(m in rel for m in _INIT_MARKERS):
        out.append(_mk(path, rel, "init_script", Severity.INFO, 0.6,
                       f"Startup/service script: {base}",
                       f"{rel} runs at boot/service start; review the services it "
                       "launches as part of the attack surface.",
                       "Disable unnecessary services.", stat.filemode(mode)))

    return out


def _mk(path, rel, vclass, sev, conf, title, desc, remediation, snippet) -> Finding:
    ev = Evidence(binary=path, snippet=snippet)
    f = Finding(
        id="",
        title=title,
        vuln_class=vclass,
        severity=sev,
        confidence=conf,
        component=rel,
        rule=RULE,
        description=desc,
        remediation=remediation,
        evidence=[ev],
    )
    f.id = f.fingerprint()
    return f
