"""Network service identification (FR-INV): which server software is
actually present -- not just "there's a binary called httpd" but which known
implementation it is (nginx? GoAhead? BusyBox's own applet?), its version
(read from an embedded banner string, never guessed), and which port it's
configured for.

This is static analysis, not a live scan: nothing here ever binds a socket
or talks to a real device. "Port" means "what the identified service is
*configured* to listen on" -- inferred from the same evidence a human
reviewer would check, in order of how much it can be trusted:

  1. An explicit port setting in a UCI-style config block for this service
     (`config dropbear` / `option Port '22'`).
  2. An inetd-style service line (`ftp  stream  tcp  ...  /usr/sbin/ftpd`),
     cross-referenced against /etc/services for the numeric port -- these
     lines show up both in a real /etc/inetd.conf and, just as often in real
     firmware, hardcoded inside an init.d script that *writes* inetd.conf at
     boot (see inetd's own init script for exactly this pattern).
  3. A `-p PORT` / `--port PORT` command-line flag in the service's own
     init.d script.
  4. The well-known default port for that kind of service (22 for SSH, 80
     for HTTP, ...) -- the fallback when nothing more specific was found.

Identification itself is signature-based: a curated set of (binary name(s),
version-banner regex) pairs for the most common embedded-Linux network
daemons, covering the categories real firmware actually ships (web, SSH,
FTP, Telnet, SOAP via gSOAP, DNS, SNMP, UPnP, plus the WiFi management
daemons that come up just as often in practice). A generically-named binary
("httpd") with no matching banner still gets reported, at low confidence,
rather than silently skipped -- "not sure what this is, but there does
appear to be an HTTP server here" is more useful to a reviewer than nothing.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..loader import is_elf
from ..model import ServiceInfo

# Version-banner regexes are applied to the raw bytes of the binary itself
# (not the tokenized strings list) since the banners this looks for are
# always short, contiguous ASCII runs -- a straight regex search is simpler
# and just as reliable as re-deriving BinaryInfo.strings here.
_MAX_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True)
class _Sig:
    name: str                        # canonical software name shown in the UI
    category: str                    # "web" | "ssh" | "ftp" | "telnet" | "soap" | "dns" | "snmp" | "upnp" | "wifi"
    binary_names: frozenset[str]      # basenames that identify this software
    version_re: "re.Pattern | None"  # group(1) = version; None if no reliable banner exists
    default_ports: tuple[int, ...] = ()
    busybox_applet: bool = False     # True if BusyBox itself can provide this name via a symlink
    min_confidence: float = 0.55     # confidence when the name matches but version_re didn't


_SIGNATURES: list[_Sig] = [
    # --- Web servers ---
    _Sig("nginx", "web", frozenset({"nginx"}),
         re.compile(rb"nginx/([\d.]+)"), (80, 443)),
    _Sig("GoAhead", "web", frozenset({"goahead", "webs"}),
         re.compile(rb"GoAhead-http/([\d.]+)"), (80,)),
    _Sig("Boa", "web", frozenset({"boa"}),
         re.compile(rb"Boa/([\w.]+)"), (80,)),
    _Sig("lighttpd", "web", frozenset({"lighttpd"}),
         re.compile(rb"lighttpd/([\d.]+)"), (80, 443)),
    _Sig("thttpd", "web", frozenset({"thttpd"}),
         re.compile(rb"thttpd/([\d.]+)"), (80,)),
    _Sig("mini_httpd", "web", frozenset({"mini_httpd"}),
         re.compile(rb"mini_httpd/([\d.]+)"), (80,)),
    _Sig("Apache httpd", "web", frozenset({"httpd", "apache2"}),
         re.compile(rb"Apache/([\d.]+)"), (80, 443)),
    _Sig("Mongoose", "web", frozenset({"mongoose"}),
         re.compile(rb"Mongoose/([\d.]+)"), (80,)),
    _Sig("uhttpd", "web", frozenset({"uhttpd"}), None, (80, 443), min_confidence=0.6),
    _Sig("BusyBox httpd", "web", frozenset({"httpd"}), None, (80,), busybox_applet=True, min_confidence=0.5),

    # --- SSH ---
    _Sig("OpenSSH", "ssh", frozenset({"sshd"}),
         re.compile(rb"OpenSSH[_-]([\w.]+)"), (22,)),
    _Sig("Dropbear SSH", "ssh", frozenset({"dropbear"}),
         re.compile(rb"SSH-2\.0-dropbear_([\w.]+)|dropbear_([\d.]+)"), (22,)),

    # --- FTP ---
    _Sig("vsftpd", "ftp", frozenset({"vsftpd"}),
         re.compile(rb"vsftpd:? ?\(?([\d.]+)\)?"), (21,)),
    _Sig("ProFTPD", "ftp", frozenset({"proftpd"}),
         re.compile(rb"ProFTPD ([\d.]+)"), (21,)),
    _Sig("Pure-FTPd", "ftp", frozenset({"pure-ftpd", "pure-uploadscript"}),
         re.compile(rb"Pure-FTPd\s*([\d.]+)?"), (21,), min_confidence=0.6),
    _Sig("BusyBox ftpd", "ftp", frozenset({"ftpd"}), None, (21,), busybox_applet=True, min_confidence=0.5),
    _Sig("BusyBox tftpd", "ftp", frozenset({"tftpd"}), None, (69,), busybox_applet=True, min_confidence=0.5),

    # --- Telnet ---
    _Sig("BusyBox telnetd", "telnet", frozenset({"telnetd"}), None, (23,), busybox_applet=True, min_confidence=0.5),
    _Sig("utelnetd", "telnet", frozenset({"utelnetd"}), re.compile(rb"utelnetd[- ]([\d.]+)"), (23,), min_confidence=0.6),

    # --- SOAP (gSOAP-generated servers are extremely common in IoT/router
    # management daemons -- the generated code embeds its own version banner). ---
    _Sig("gSOAP", "soap", frozenset(), re.compile(rb"gSOAP(?:/| )([\d.]+)"), (), min_confidence=0.5),

    # --- DNS ---
    _Sig("dnsmasq", "dns", frozenset({"dnsmasq"}),
         re.compile(rb"dnsmasq-([\d.]+)"), (53,)),

    # --- SNMP ---
    _Sig("Net-SNMP", "snmp", frozenset({"snmpd"}),
         re.compile(rb"NET-SNMP version:? ([\d.]+)"), (161,)),

    # --- UPnP ---
    _Sig("MiniUPnPd", "upnp", frozenset({"miniupnpd"}),
         re.compile(rb"MiniUPnPd/([\d.]+)"), (1900,)),

    # --- WiFi management (not remotely reachable the way the above are, but
    # just as much "which daemon is this" inventory the same technique answers). ---
    _Sig("hostapd", "wifi", frozenset({"hostapd"}),
         re.compile(rb"hostapd v([\d.]+)"), ()),
    _Sig("wpa_supplicant", "wifi", frozenset({"wpa_supplicant"}),
         re.compile(rb"wpa_supplicant v([\d.]+)"), ()),
]

# gSOAP doesn't have a fixed binary name (it's a code-generation toolkit
# linked into a vendor's own custom daemon under whatever name they chose),
# so it's matched by banner string against *every* binary rather than by
# name -- the one signature above with an empty binary_names set.
_GSOAP_SIG = next(s for s in _SIGNATURES if s.name == "gSOAP")

_PORT_FLAG_RE = re.compile(r"(?:^|\s)(?:-p\s*|--port[= ])(\d{1,5})\b")
# inetd.conf's 7-field format -- appears verbatim both in a real /etc/inetd.conf
# and, just as often in real firmware, hardcoded as a shell "echo" line inside
# an init.d script that writes inetd.conf out at first boot if it's missing.
#  Deliberately not anchored to line start: a real /etc/inetd.conf has one
# entry per line, but firmware just as often hardcodes this exact format
# mid-line inside a shell "echo ... >> /etc/inetd.conf" statement (see this
# module's docstring) -- \b is enough to avoid matching a mid-word fragment.
_INETD_LINE_RE = re.compile(
    r"\b([\w.-]+)\s+(?:stream|dgram)\s+(?:tcp|udp)6?\s+\S+\s+\S+\s+(\S+)")


def detect_services(target: str, max_entries: int = 200000) -> list[ServiceInfo]:
    """FR-INV: identify known network-service software in the tree, with
    best-effort version and listening-port inference. Returns [] for a
    single-file target (no init.d/config structure to cross-reference)."""
    if os.path.isfile(target):
        return []

    by_basename: dict[str, list[str]] = {}
    symlink_target_basename: dict[str, str] = {}
    n = 0
    for root, _dirs, files in os.walk(target):
        for f in files:
            if n >= max_entries:
                break
            n += 1
            path = os.path.join(root, f)
            by_basename.setdefault(f, []).append(path)
            if os.path.islink(path):
                try:
                    symlink_target_basename[path] = os.path.basename(os.readlink(path))
                except OSError:
                    pass
        if n >= max_entries:
            break

    services_by_service_name = _parse_etc_services(target)
    inetd_service_for_binary = _find_inetd_style_ports(target, by_basename)

    out: list[ServiceInfo] = []
    seen_paths: set[str] = set()

    for sig in _SIGNATURES:
        if sig is _GSOAP_SIG:
            continue  # handled separately below (matched by content, not name)
        for basename in sig.binary_names:
            for path in by_basename.get(basename, []):
                if path in seen_paths:
                    continue
                if path in symlink_target_basename:
                    if sig.busybox_applet and symlink_target_basename[path] == "busybox":
                        seen_paths.add(path)
                        out.append(_mk(sig, path, "", 0.5, target, basename,
                                        services_by_service_name, inetd_service_for_binary))
                    continue
                # A config file or init.d script is very often named exactly
                # after the daemon it manages (/etc/config/dropbear, /etc/
                # init.d/dnsmasq, ...) and shares its basename with the real
                # binary -- without this check, both would be reported as
                # separate "service" hits under the same name. Only an actual
                # ELF is the service; the rest just get consulted for port
                # inference (_find_uci_port/_find_flag_port already read them
                # by path, independent of this match).
                if not os.path.isfile(path) or not is_elf(path):
                    continue
                version, conf = _match_version(path, sig)
                if sig.version_re is not None and version is None and sig.min_confidence < 0.5:
                    continue  # a strict signature that found no banner at all isn't worth reporting
                seen_paths.add(path)
                out.append(_mk(sig, path, version or "", conf, target, basename,
                                services_by_service_name, inetd_service_for_binary))

    # gSOAP: scan every not-yet-claimed ELF-ish file's content for its banner
    # (no fixed binary name to key off of -- it's linked into a vendor's own
    # custom daemon under an arbitrary name).
    for basename, paths in by_basename.items():
        for path in paths:
            if path in seen_paths or path in symlink_target_basename:
                continue
            if not os.path.isfile(path) or not is_elf(path):
                continue
            version, conf = _match_version(path, _GSOAP_SIG)
            if version is None:
                continue
            seen_paths.add(path)
            out.append(_mk(_GSOAP_SIG, path, version, conf, target, basename,
                            services_by_service_name, inetd_service_for_binary))

    return out


def _match_version(path: str, sig: _Sig) -> tuple[str | None, float]:
    if sig.version_re is None:
        return None, sig.min_confidence
    try:
        size = os.path.getsize(path)
        if size == 0 or size > _MAX_BYTES:
            return None, sig.min_confidence
        with open(path, "rb") as fh:
            data = fh.read(_MAX_BYTES)
    except OSError:
        return None, sig.min_confidence
    m = sig.version_re.search(data)
    if not m:
        return None, sig.min_confidence
    # First non-None capture group (some patterns have alternates with their
    # own group, e.g. dropbear's SSH-banner-or-bare-version alternation).
    version = next((g for g in m.groups() if g), None)
    if version is None:
        return "", 0.9
    return version.decode("ascii", "replace"), 0.95


def _mk(sig: _Sig, path: str, version: str, confidence: float, target: str, basename: str,
        services_by_service_name: dict[str, int],
        inetd_service_for_binary: dict[str, int]) -> ServiceInfo:
    ports, port_source = _resolve_ports(sig, path, basename, target, services_by_service_name,
                                         inetd_service_for_binary)
    return ServiceInfo(
        name=sig.name,
        category=sig.category,
        binary_path=path,
        version=version,
        ports=ports,
        port_source=port_source,
        confidence=confidence,
    )


def _resolve_ports(sig: _Sig, path: str, basename: str, target: str,
                    services_by_service_name: dict[str, int],
                    inetd_service_for_binary: dict[str, int]) -> tuple[list[int], str]:
    uci_port = _find_uci_port(target, basename)
    if uci_port is not None:
        return [uci_port], "config"
    if path in inetd_service_for_binary:
        return [inetd_service_for_binary[path]], "inetd"
    flag_port = _find_flag_port(target, basename)
    if flag_port is not None:
        return [flag_port], "init.d flag"
    if sig.default_ports:
        return list(sig.default_ports), "default"
    return [], ""


def _parse_etc_services(target: str) -> dict[str, int]:
    """name -> port from /etc/services (tcp entries preferred), so an
    inetd-style line's *service name* (not a literal port number) can be
    resolved the same way a real inetd would resolve it at boot."""
    path = os.path.join(target, "etc", "services")
    out: dict[str, int] = {}
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read(1024 * 1024)
    except OSError:
        return out
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or "/" not in parts[1]:
            continue
        name = parts[0]
        port_str, _, proto = parts[1].partition("/")
        if not port_str.isdigit():
            continue
        if name not in out or proto == "tcp":
            out[name] = int(port_str)
    return out


def _find_inetd_style_ports(target: str, by_basename: dict[str, list[str]]) -> dict[str, int]:
    """Scan every config/script file for inetd.conf-format lines (present
    either in a real /etc/inetd.conf or, just as often, hardcoded in an
    init.d script that generates one at boot -- see this module's docstring)
    and resolve each referenced binary's listening port via /etc/services.
    Returns {absolute binary path -> port}."""
    services_by_name = _parse_etc_services(target)
    if not services_by_name:
        return {}
    result: dict[str, int] = {}
    for root, _dirs, files in os.walk(target):
        for f in files:
            path = os.path.join(root, f)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                size = os.path.getsize(path)
                if size == 0 or size > 512 * 1024:
                    continue
                with open(path, "r", errors="replace") as fh:
                    text = fh.read(512 * 1024)
            except OSError:
                continue
            if "stream" not in text and "dgram" not in text:
                continue
            # A real /etc/inetd.conf has actual tab bytes between fields, but
            # just as often in real firmware this line is instead hardcoded
            # as a shell "echo -e '...\t...'" statement inside an init.d
            # script that writes inetd.conf out at boot -- the *source* of
            # that script contains the literal two characters backslash+t,
            # not a real tab, since \t only becomes a tab when the shell
            # actually runs the echo. Normalize both to a real tab so the
            # same regex matches either form.
            text = text.replace("\\t", "\t")
            for m in _INETD_LINE_RE.finditer(text):
                service_name, bin_ref = m.group(1), m.group(2)
                port = services_by_name.get(service_name)
                if port is None:
                    continue
                bin_basename = os.path.basename(bin_ref)
                for cand_path in by_basename.get(bin_basename, []):
                    result[cand_path] = port
    return result


def _find_uci_port(target: str, basename: str) -> int | None:
    """A UCI config block (`config <type> [name]` ... `option Port 'N'`)
    naming this service by its binary's basename -- e.g. `config dropbear`
    with `option Port '22'` in /etc/config/dropbear."""
    path = os.path.join(target, "etc", "config", basename)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read(65536)
    except OSError:
        return None
    m = re.search(r"(?im)^\s*option\s+port\s+'?(\d{1,5})'?", text)
    return int(m.group(1)) if m else None


def _find_flag_port(target: str, basename: str) -> int | None:
    """A `-p PORT` / `--port PORT` flag on a line that also names this
    service's binary, inside that service's own init.d script."""
    path = os.path.join(target, "etc", "init.d", basename)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", errors="replace") as fh:
            text = fh.read(65536)
    except OSError:
        return None
    for line in text.splitlines():
        if basename not in line:
            continue
        m = _PORT_FLAG_RE.search(line)
        if m:
            return int(m.group(1))
    return None
