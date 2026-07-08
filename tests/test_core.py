"""End-to-end and unit tests for the RE + VUL core.

The end-to-end test compiles a seeded-vulnerable binary (skipped if no gcc) and
asserts the acceptance-criteria behavior: dangerous-function detection, a
traceable source->sink taint path, and mitigation detection. Unit tests cover
CVE correlation and triage persistence without a toolchain.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import textwrap

import pytest

from ifda.model import BinaryInfo, TriageState, Severity
from ifda.vuln.cve import correlate_cves, extract_sbom
from ifda.vuln.findings import prioritize, TriageStore


SEED_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    void handle_request(void){
        char cmd[256]; char *in=getenv("QUERY_STRING");
        sprintf(cmd,"ping -c1 %s",in); system(cmd);
    }
    int main(int c,char**v){ handle_request(); return 0; }
    """
)


@pytest.fixture(scope="module")
def seeded_binary(tmp_path_factory):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("seed")
    src, out = d / "v.c", d / "v"
    src.write_text(SEED_C)
    subprocess.run(
        [gcc, "-O0", "-fno-stack-protector", "-no-pie", str(src), "-o", str(out)],
        check=True,
    )
    return str(out)


def test_endtoend_seeded_vuln(seeded_binary):
    from ifda.pipeline import analyze

    report = analyze(seeded_binary)
    classes = {f.vuln_class for f in report.findings}
    assert "command_injection" in classes
    assert "buffer_overflow" in classes

    # Acceptance criteria: a traceable source -> sink path to system().
    taint = [f for f in report.findings if f.rule == "taint-reachability"]
    assert any(
        "getenv" in f.evidence[0].taint_path
        and "system()" in f.evidence[0].taint_path
        for f in taint
    )


def test_mitigation_fields_present(seeded_binary):
    from ifda.pipeline import analyze_binary

    info, _ = analyze_binary(seeded_binary)
    assert info.arch == "x86_64"
    assert info.mitigations.canary is False  # built with -fno-stack-protector
    assert info.mitigations.nx is not None


def test_cve_correlation():
    info = BinaryInfo(path="busybox", sha256="x")
    info.strings = ["BusyBox v1.21.1 multi-call binary", "OpenSSL 1.0.1f 6 Jan 2014"]
    assert {(c.name, c.version) for c in extract_sbom(info)} == {
        ("busybox", "1.21.1"),
        ("openssl", "1.0.1f"),
    }
    cves = {c for f in correlate_cves(info) for c in f.cve_ids}
    assert "CVE-2014-0160" in cves  # Heartbleed on 1.0.1f


def test_cve_not_flagged_when_patched():
    info = BinaryInfo(path="ssl", sha256="x")
    info.strings = ["OpenSSL 1.0.2h 3 May 2016"]
    assert correlate_cves(info) == []


def test_prioritize_orders_by_severity():
    info = BinaryInfo(path="b", sha256="x")
    info.strings = ["BusyBox v1.21.1", "OpenSSL 1.0.1f"]
    findings = prioritize(correlate_cves(info))
    ranks = [f.severity.value for f in findings]
    assert ranks == sorted(ranks, key=lambda s: ["info","low","medium","high","critical"].index(s), reverse=True)


LIB_C = textwrap.dedent(
    """
    #include <stdio.h>
    #include <stdlib.h>
    void run_ping(char *host){ char c[256]; sprintf(c,"ping %s",host); system(c); }
    """
)
CGI_C = textwrap.dedent(
    """
    #include <stdlib.h>
    extern void run_ping(char *host);
    int main(void){ char *q=getenv("QUERY_STRING"); run_ping(q); return 0; }
    """
)


@pytest.fixture(scope="module")
def cross_tree(tmp_path_factory):
    gcc = shutil.which("gcc")
    if not gcc:
        pytest.skip("gcc not available")
    d = tmp_path_factory.mktemp("tree")
    (d / "lib").mkdir()
    (d / "www").mkdir()
    libc, cgic = d / "libcmd.c", d / "cgi.c"
    libc.write_text(LIB_C)
    cgic.write_text(CGI_C)
    so = d / "lib" / "libcmd.so"
    cgi = d / "www" / "cgi"
    subprocess.run([gcc, "-O0", "-fno-stack-protector", "-shared", "-fPIC",
                    "-o", str(so), str(libc)], check=True)
    subprocess.run([gcc, "-O0", "-fno-stack-protector", "-no-pie", "-o", str(cgi),
                    str(cgic), f"-L{d/'lib'}", "-lcmd"], check=True)
    return str(d)


def test_cross_binary_taint(cross_tree):
    from ifda.pipeline import analyze

    report = analyze(cross_tree)
    cross = [f for f in report.findings if f.rule == "cross-binary-taint"]
    # source in cgi must reach the system() sink that lives in libcmd.so.
    assert any(
        "getenv()" in f.evidence[0].taint_path
        and "system()" in f.evidence[0].taint_path
        and any("(cross)" in step for step in f.evidence[0].taint_path)
        for f in cross
    )


# (id, cross-compiler) for the non-host architectures we resolve precisely.
CROSS_ARCHES = [
    ("mips", "mips-linux-gnu-gcc"),
    ("arm", "arm-linux-gnueabi-gcc"),
    ("aarch64", "aarch64-linux-gnu-gcc"),
]


def _require(cc_name: str) -> str:
    cc = shutil.which(cc_name)
    if not cc:
        pytest.skip(f"{cc_name} not available")
    return cc


@pytest.mark.parametrize("expected_arch,cc_name", CROSS_ARCHES)
def test_cross_arch_call_resolution(expected_arch, cc_name, tmp_path):
    """Externals on MIPS/ARM/AArch64 must resolve to precise call sites,
    matching x86 detection quality — not the import-presence fallback."""
    from ifda.pipeline import analyze_binary

    cc = _require(cc_name)
    src, out = tmp_path / "v.c", tmp_path / "v"
    src.write_text(SEED_C)
    subprocess.run([cc, "-O0", "-fno-stack-protector", str(src), "-o", str(out)],
                   check=True)

    info, findings = analyze_binary(str(out))
    assert info.arch == expected_arch
    # No 'resolution limited' warning once call resolution works.
    assert not any("resolution limited" in w for w in info.warnings)
    # Precise call-site rule fired (not the :import fallback).
    precise = {f.title for f in findings if f.rule == "unsafe-api"}
    assert any("system()" in t for t in precise)
    assert any("sprintf()" in t for t in precise)
    # And taint reached system() from getenv().
    assert any(
        f.rule == "taint-reachability" and "system()" in f.evidence[0].taint_path
        for f in findings
    )


@pytest.mark.parametrize("expected_arch,cc_name", CROSS_ARCHES)
def test_cross_arch_cross_binary(expected_arch, cc_name, tmp_path):
    """Cross-binary taint must work on each arch, including PIC shared libs."""
    from ifda.pipeline import analyze

    cc = _require(cc_name)
    (tmp_path / "lib").mkdir()
    (tmp_path / "www").mkdir()
    libc, cgic = tmp_path / "libcmd.c", tmp_path / "cgi.c"
    libc.write_text(LIB_C)
    cgic.write_text(CGI_C)
    so, cgi = tmp_path / "lib" / "libcmd.so", tmp_path / "www" / "cgi"
    subprocess.run([cc, "-O0", "-fno-stack-protector", "-shared", "-fPIC",
                    "-o", str(so), str(libc)], check=True)
    subprocess.run([cc, "-O0", "-fno-stack-protector", "-o", str(cgi),
                    str(cgic), f"-L{tmp_path/'lib'}", "-lcmd"], check=True)

    report = analyze(str(tmp_path))
    cross = [f for f in report.findings if f.rule == "cross-binary-taint"]
    assert any(
        "getenv()" in f.evidence[0].taint_path
        and "system()" in f.evidence[0].taint_path
        and any("(cross)" in step for step in f.evidence[0].taint_path)
        for f in cross
    )


def test_embedded_secrets(tmp_path):
    """FR-INV-4: private keys, weak password hashes, hardcoded creds and tokens
    are flagged; placeholders and variable references are not."""
    from ifda.inventory import scan_secrets

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "shadow").write_text(
        "root:$1$xyz$AbCdEfGhIjKlMnOp:19000:0:99999:7:::\n"
        "admin:$6$salt$longhash0123456789:19000:0:99999:7:::\n"
    )
    (tmp_path / "etc" / "app.conf").write_text(
        "db_password = S3cr3tDbPass!\nftp_pass = ${FTP_PW}\nadmin_pw = changeme\n"
    )
    (tmp_path / "etc" / "server.key").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEdeadbeef==\n-----END RSA PRIVATE KEY-----\n"
    )

    findings = scan_secrets(str(tmp_path))
    classes = {f.vuln_class for f in findings}
    assert "private_key" in classes
    assert "hardcoded_credential" in classes

    # Weak MD5 hash outranks strong SHA-512 hash.
    hashes = {f.title.split("'")[1]: f.severity.value
              for f in findings if f.vuln_class == "password_hash"}
    assert hashes["root"] == "high"      # $1$ MD5-crypt is weak
    assert hashes["admin"] == "medium"   # $6$ SHA-512

    # The db_password credential is found; its value is redacted in evidence.
    creds = [f.evidence[0].snippet for f in findings if f.vuln_class == "hardcoded_credential"]
    assert any("db_password" in c for c in creds)
    assert not any("S3cr3tDbPass" in c for c in creds)  # never emit the raw secret
    # Placeholders / variable references are not treated as credentials.
    assert not any("changeme" in c or "FTP_PW" in c for c in creds)


def test_external_signature_rules(tmp_path):
    """FR-INT-3 / NFR-USE-2: provider-token signatures come from the externalized
    rule file and match by shape; values stay redacted."""
    from ifda.inventory import scan_secrets
    from ifda.rules import load_rules

    rules, version = load_rules()
    assert len(rules) >= 8 and version            # rule file loaded & compiled
    ids = {r.id for r in rules}
    assert {"aws-access-key", "github-pat", "jwt"} <= ids

    secret = "ghp_" + "a" * 38
    (tmp_path / "app.conf").write_text(
        f"aws = AKIAABCDEFGHIJKLMNOP\ngithub_token = {secret}\n"
    )
    findings = scan_secrets(str(tmp_path))
    by_rule = {f.rule: f for f in findings}
    assert "signature-rule:aws-access-key" in by_rule
    assert "signature-rule:github-pat" in by_rule
    assert by_rule["signature-rule:github-pat"].vuln_class == "api_token"
    # The raw token is never emitted in evidence.
    assert all(secret not in e.snippet
               for f in findings for e in f.evidence)


def test_entropy_secret_fallback(tmp_path):
    """Prefix-less high-entropy secrets (no provider prefix) are caught by the
    entropy fallback when assigned to a secret-like key; ordinary text is not."""
    from ifda.inventory import scan_secrets

    (tmp_path / "cfg").write_text(
        "session_token = 9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e\n"
        "welcome_banner = WelcomeToTheRouterAdminPanel2024\n"   # low entropy, ignore
    )
    findings = scan_secrets(str(tmp_path))
    ent = [f for f in findings if f.vuln_class == "high_entropy_secret"]
    assert len(ent) == 1                          # only the random hex token
    assert ent[0].severity is Severity.MEDIUM     # key-hinted -> medium
    assert "9f8a7b6c" not in ent[0].evidence[0].snippet   # redacted


def test_shell_command_injection(tmp_path):
    """Shell/CGI analysis flags eval/sh -c/download-pipe on untrusted data and
    keeps quoted/arg-position cases low — no high-severity false positives."""
    from ifda.scripts import scan_scripts

    cgi = tmp_path / "ping.cgi"
    cgi.write_text(
        "#!/bin/sh\n"
        'host=$(echo "$QUERY_STRING" | sed "s/.*host=//")\n'  # taints host (subst)
        'eval "result=$host"\n'                                # HIGH eval
        'ping -c 3 $host\n'                                    # LOW arg
        'nvram set last="$host"\n'                             # quoted -> not flagged
    )
    upd = tmp_path / "update.sh"
    upd.write_text("#!/bin/sh\nwget http://x/u -O - | sh\necho safe\n")

    findings = scan_scripts(str(tmp_path))
    titles = {f.title for f in findings}
    assert any("eval" in t for t in titles)
    assert any("download piped into shell" in t for t in titles)

    # The quoted nvram-set line must not be a high finding.
    highs = [f for f in findings if f.severity.value in ("high", "critical")]
    assert not any("nvram set last" in f.evidence[0].snippet for f in highs)
    # The bare `echo safe` and shebang produce nothing.
    assert all("echo safe" not in f.evidence[0].snippet for f in findings)


def test_php_python_lua_injection(tmp_path):
    """FR-INV-3: PHP/Python/Lua command, code, inclusion and deserialization
    sinks on untrusted data are flagged; static/safe calls are not."""
    from ifda.scripts import scan_lang_scripts

    (tmp_path / "a.php").write_text(
        "<?php\n"
        "$ip = $_GET['ip'];\n"
        "system('ping -c1 '.$ip);\n"      # HIGH command_injection
        "system('uptime');\n"             # static -> ignored
        "include($_REQUEST['p'].'.php');\n"  # HIGH file_inclusion
        "eval($_POST['code']);\n"         # HIGH code_injection
    )
    (tmp_path / "b.py").write_text(
        "import os, subprocess, pickle\n"
        "from flask import request\n"
        "host = request.args.get('h')\n"
        "os.system('ping ' + host)\n"               # HIGH command_injection
        "subprocess.call(['ls', '-l'])\n"           # safe (no shell) -> ignored
        "data = pickle.loads(request.data)\n"       # HIGH deserialization
    )
    (tmp_path / "c.lua").write_text(
        "local cmd = http.formvalue('cmd')\n"
        "os.execute('reboot')\n"                    # static -> ignored
        "os.execute('ping '..cmd)\n"                # HIGH command_injection
    )

    findings = scan_lang_scripts(str(tmp_path))
    by_class = {f.vuln_class for f in findings}
    assert {"command_injection", "code_injection",
            "file_inclusion", "deserialization"} <= by_class

    # Every reported finding is HIGH (all the planted sinks are tainted); the
    # static/safe lines must not appear in any evidence snippet.
    snippets = " ".join(f.evidence[0].snippet for f in findings)
    assert "uptime" not in snippets
    assert "reboot" not in snippets
    assert "['ls', '-l']" not in snippets
    # Per-language rule tags are recorded.
    rules = {f.rule for f in findings}
    assert any(r.endswith(":php") for r in rules)
    assert any(r.endswith(":python") for r in rules)
    assert any(r.endswith(":lua") for r in rules)


def test_filesystem_hardening(tmp_path):
    """FR-INV hardening: setuid binaries, world-writable execs, weak perms on
    sensitive files, and init-script enumeration are reported at the right tier."""
    import os
    from ifda.fs import scan_filesystem

    (tmp_path / "bin").mkdir()
    (tmp_path / "etc" / "init.d").mkdir(parents=True)

    bb = tmp_path / "bin" / "busybox"
    bb.write_text("#!/bin/sh\n")
    os.chmod(bb, 0o4755)                       # setuid, shell-capable -> HIGH

    cgi = tmp_path / "bin" / "upload.cgi"
    cgi.write_text("#!/bin/sh\n")
    os.chmod(cgi, 0o777)                        # world-writable exec -> HIGH

    shadow = tmp_path / "etc" / "shadow"
    shadow.write_text("root:x:0:0:::\n")
    os.chmod(shadow, 0o644)                     # world-readable secret -> HIGH

    svc = tmp_path / "etc" / "init.d" / "S50telnet"
    svc.write_text("#!/bin/sh\n")
    os.chmod(svc, 0o755)                        # init script -> INFO

    findings = scan_filesystem(str(tmp_path))
    by_class = {f.vuln_class: f for f in findings}

    assert by_class["setuid_binary"].severity is Severity.HIGH
    assert by_class["world_writable_exec"].severity is Severity.HIGH
    assert by_class["weak_permissions"].severity is Severity.HIGH
    assert by_class["init_script"].severity is Severity.INFO


def test_firmware_meta(tmp_path):
    """Firmware-level summary: kernel version banner found anywhere in the
    tree, total file count/size, and majority arch/endian across binaries."""
    from ifda.inventory import detect_kernel_version, scan_tree_stats, summarize_arch_endian

    (tmp_path / "boot").mkdir()
    # Kernel version banner embedded mid-file, the way it sits inside a real
    # (possibly compressed) kernel image rather than as the whole file.
    (tmp_path / "boot" / "zImage").write_bytes(
        b"\x00" * 64 + b"Linux version 4.14.170 (buildbot@host) #1 SMP\x00" + b"\xff" * 64)
    (tmp_path / "other.bin").write_bytes(b"nothing interesting here")

    assert detect_kernel_version(str(tmp_path)) == "4.14.170"

    count, total = scan_tree_stats(str(tmp_path))
    assert count == 2
    assert total == sum(p.stat().st_size for p in tmp_path.rglob("*") if p.is_file())

    arch, endian = summarize_arch_endian(
        ["arm", "arm", "mips", ""], ["little", "little", "big", ""])
    assert arch == "arm"
    assert endian == "little"


def test_kernel_version_from_modules_dir(tmp_path):
    """Split boot/rootfs firmware: the rootfs being scanned carries the
    loadable modules but not the kernel image, so there's no 'Linux version'
    banner. The kernel version must still be recovered from the
    lib/modules/<version>/ directory name."""
    from ifda.inventory import detect_kernel_version

    (tmp_path / "lib" / "modules" / "4.4.60").mkdir(parents=True)
    (tmp_path / "lib" / "modules" / "4.4.60" / "fat.ko").write_bytes(b"not a real module")
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config").write_text("nothing versiony here")

    assert detect_kernel_version(str(tmp_path)) == "4.4.60"


def test_kernel_version_from_vermagic(tmp_path):
    """A loadable module's vermagic string carries the kernel version even
    when the module lives outside a conventional lib/modules/<version>/ path."""
    from ifda.inventory import detect_kernel_version

    (tmp_path / "drivers").mkdir()
    (tmp_path / "drivers" / "custom.ko").write_bytes(
        b"\x7fELF\x00\x00" + b"padding" * 4 + b"\x00vermagic=5.10.110 SMP mod_unload\x00")

    assert detect_kernel_version(str(tmp_path)) == "5.10.110"


def test_firmware_meta_skips_device_nodes(tmp_path):
    """Regression: a real extracted rootfs's /dev often preserves character
    device nodes (e.g. /dev/console, major 5 minor 1) with their real
    major/minor numbers. open()+read() on one of those blocks forever
    waiting for I/O that will never come -- which hung the whole analysis
    pipeline on a real firmware target until this was fixed to skip
    anything that isn't a regular file, the same way every other
    tree-walker in this codebase already does."""
    import os
    from ifda.inventory import detect_kernel_version

    (tmp_path / "dev").mkdir()
    os.mknod(str(tmp_path / "dev" / "console"), 0o600 | 0o020000, os.makedev(5, 1))  # S_IFCHR
    (tmp_path / "boot").mkdir()
    (tmp_path / "boot" / "zImage").write_bytes(b"Linux version 4.14.170 boom\x00")

    # Must return promptly (no test timeout needed) rather than blocking on
    # the character device's read().
    assert detect_kernel_version(str(tmp_path)) == "4.14.170"


def test_list_all_files(tmp_path):
    """Full file listing (FR-INV): every file in the tree is present with a
    size and md5, a symlink is listed but never opened for hashing, and a
    device node is listed (size only, no md5) rather than blocking forever."""
    import os
    from ifda.inventory import list_all_files

    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config").write_text("hello world")
    os.symlink("config", str(tmp_path / "etc" / "config.lnk"))
    (tmp_path / "dev").mkdir()
    os.mknod(str(tmp_path / "dev" / "console"), 0o600 | 0o020000, os.makedev(5, 1))

    files = {os.path.relpath(f["path"], tmp_path): f for f in list_all_files(str(tmp_path))}

    assert set(files) == {"etc/config", "etc/config.lnk", "dev/console"}
    assert files["etc/config"]["size"] == 11
    assert files["etc/config"]["md5"] == __import__("hashlib").md5(b"hello world").hexdigest()
    assert files["etc/config.lnk"]["is_symlink"] is True
    assert files["etc/config.lnk"]["md5"] == ""  # never opened/followed
    assert files["dev/console"]["is_symlink"] is False
    assert files["dev/console"]["md5"] == ""  # never opened -- would hang otherwise


def test_pipeline_files_cover_whole_tree(tmp_path):
    """Regression: analyze()'s file listing must cover every file under the
    target, not just the ELF binaries/scripts subset -- classified by kind
    (binary/script/symlink/other) using the same paths already resolved for
    report.binaries/report.scripts."""
    import os
    from ifda.pipeline import analyze

    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 12)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "config.txt").write_text("just a config file")
    os.symlink("busybox", str(tmp_path / "bin" / "sh"))

    report = analyze(str(tmp_path))

    by_path = {f.path: f for f in report.files}
    assert len(report.files) == 3
    assert by_path[str(tmp_path / "bin" / "busybox")].kind == "binary"
    assert by_path[str(tmp_path / "etc" / "config.txt")].kind == "other"
    assert by_path[str(tmp_path / "bin" / "sh")].kind == "symlink"
    assert report.file_count == 3
    assert report.firmware_size == sum(f.size for f in report.files)


def test_backdoor_scan(tmp_path):
    """Non-busybox command scan: a standalone binary shadowing a
    conventionally-busybox command is flagged; a proper busybox symlink is
    not; and nothing fires at all when busybox isn't present in the tree."""
    import os
    from ifda.vuln.backdoor import scan_backdoors

    (tmp_path / "bin").mkdir()
    bb = tmp_path / "bin" / "busybox"
    bb.write_bytes(b"\x7fELF" + b"\x00" * 12)

    # Expected pattern: a real symlink into busybox.
    os.symlink("busybox", tmp_path / "bin" / "ls")

    # Anomaly: a standalone ELF implementing a high-risk applet name that
    # busybox already provides here -- the backdoor-shadowing pattern.
    fake_login = tmp_path / "bin" / "login"
    fake_login.write_bytes(b"\x7fELF" + b"\x00" * 12)

    findings = scan_backdoors(str(tmp_path))
    by_component = {f.component: f for f in findings}

    assert "/bin/ls" not in by_component
    assert by_component["/bin/login"].severity is Severity.HIGH
    assert by_component["/bin/login"].vuln_class == "suspected_backdoor"


def test_backdoor_scan_no_busybox_no_noise(tmp_path):
    """Without busybox anywhere in the tree, the heuristic doesn't apply --
    a standalone /bin/login here is unremarkable and must not be flagged."""
    from ifda.vuln.backdoor import scan_backdoors

    (tmp_path / "bin").mkdir()
    (tmp_path / "bin" / "login").write_bytes(b"\x7fELF" + b"\x00" * 12)

    assert scan_backdoors(str(tmp_path)) == []


def test_busybox_audit_compiled_and_missing(tmp_path):
    """Applet detection is exact-string-token based: names embedded in the
    fake busybox binary as their own NUL-terminated strings show up as
    compiled_in; well-known applets never mentioned show up as missing
    ("crippled busybox")."""
    from ifda.inventory import audit_busybox

    bb = tmp_path / "busybox"
    bb.write_bytes(b"\x7fELF" + b"\x00" * 8 + b"ls\x00cat\x00sh\x00" + b"unrelated junk\x00")

    audit = audit_busybox(str(tmp_path), [str(bb)])

    assert audit.has_busybox is True
    assert {"ls", "cat", "sh"} <= set(audit.compiled_in)
    assert "telnetd" in audit.missing  # never mentioned in the fake binary
    assert "telnetd" not in audit.compiled_in


def test_busybox_audit_no_busybox(tmp_path):
    """Without any busybox binary, compiled_in/missing are both empty --
    there's no baseline to compare against, so nothing should be reported
    as "missing" (that would just be every applet, which is noise)."""
    from ifda.inventory import audit_busybox

    audit = audit_busybox(str(tmp_path), [])
    assert audit.has_busybox is False
    assert audit.compiled_in == []
    assert audit.missing == []


def test_busybox_audit_extra_commands(tmp_path):
    """bin/: a busybox symlink is not "extra"; a standalone binary whose name
    busybox actually compiled in is not "extra" either (that's the separate
    shadowing/backdoor concern); a standalone binary with a name busybox
    never provides is "extra" -- across more than one bin/sbin directory."""
    import os
    from ifda.inventory import audit_busybox

    bb = tmp_path / "bin" / "busybox"
    (tmp_path / "bin").mkdir(parents=True)
    bb.write_bytes(b"\x7fELF" + b"\x00" * 8 + b"ls\x00sh\x00")
    os.symlink("busybox", tmp_path / "bin" / "ls")  # normal busybox-provided command
    (tmp_path / "bin" / "sh").write_bytes(b"\x7fELF\x00\x00\x00\x00")  # standalone but a known applet -- not "extra"

    (tmp_path / "usr" / "sbin").mkdir(parents=True)
    (tmp_path / "usr" / "sbin" / "vendord").write_bytes(b"\x7fELF\x00\x00\x00\x00")  # genuinely extra

    audit = audit_busybox(str(tmp_path), [str(bb)])

    by_name = {c.name: c for c in audit.extra_commands}
    assert "ls" not in by_name
    assert "sh" not in by_name
    assert by_name["vendord"].dir == "/usr/sbin"
    assert by_name["vendord"].kind == "binary"


def test_busybox_audit_init_scripts(tmp_path):
    """/etc/init.d scripts are captured with their full source, and a device
    node dropped in there (real firmware sometimes does) is skipped rather
    than hanging the scan."""
    import os
    from ifda.inventory import audit_busybox

    initd = tmp_path / "etc" / "init.d"
    initd.mkdir(parents=True)
    (initd / "S50network").write_text("#!/bin/sh\necho starting network\n")
    os.mknod(str(initd / "console"), 0o600 | 0o020000, os.makedev(5, 1))

    audit = audit_busybox(str(tmp_path), [])

    assert len(audit.init_scripts) == 1
    script = audit.init_scripts[0]
    assert script.path.endswith("S50network")
    assert script.content == "#!/bin/sh\necho starting network\n"
    assert script.truncated is False


def test_cyclonedx_sbom():
    from ifda.report.sbom import render_cyclonedx
    import json
    from ifda.model import AnalysisReport
    from ifda.vuln.cve import correlate_cves

    b = BinaryInfo(path="/sbin/busybox", sha256="x")
    b.strings = ["BusyBox v1.21.1", "OpenSSL 1.0.1f 6 Jan 2014"]
    rep = AnalysisReport(target="fw.bin", tool_version="0.1.0")
    rep.binaries = [b]
    rep.findings = correlate_cves(b)
    doc = json.loads(render_cyclonedx(rep))
    assert doc["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in doc["components"]}
    assert {"busybox", "openssl"} <= names
    assert any(v["id"] == "CVE-2014-0160" for v in doc["vulnerabilities"])


def test_triage_persistence(tmp_path):
    info = BinaryInfo(path="b", sha256="x")
    info.strings = ["OpenSSL 1.0.1f"]
    findings = correlate_cves(info)
    assert len(findings) >= 2  # OpenSSL 1.0.1f matches multiple CVEs; ids must differ
    assert len({f.id for f in findings}) == len(findings)
    fid = findings[0].id

    store_path = tmp_path / "triage.json"
    store = TriageStore(str(store_path))
    store.set(fid, TriageState.FALSE_POSITIVE)

    # Re-load (simulating a re-scan) and apply.
    store2 = TriageStore(str(store_path))
    store2.apply(findings)
    assert findings[0].triage is TriageState.FALSE_POSITIVE
    # Only the triaged finding is muted; unrelated CVEs on the same component
    # must not be silently suppressed by a shared fingerprint (the bug this
    # guards against).
    assert findings[1].triage is TriageState.NEW
    assert store2.active(findings) == findings[1:]


# A captured Ghidra post-script output, so the parser + enrichment are tested
# without needing Ghidra installed (the heavy live path is opt-in below).
_GHIDRA_FIXTURE = """
{"program":"vuln","functions":[
 {"name":"handle","address":"0x1149","signature":"undefined handle(void)",
  "pseudocode":"void handle(char *param_1)\\n{\\n  char local_58 [72];\\n  strcpy(local_58,param_1);\\n  system(local_58);\\n  return;\\n}"}
]}
"""


def test_decompile_output_parser():
    """FR-RE-2: the Ghidra post-script output parses into name->pseudocode."""
    from ifda.re.decompile import _parse_output

    parsed = _parse_output(_GHIDRA_FIXTURE)
    assert "handle" in parsed
    assert parsed["handle"]["address"] == "0x1149"
    assert "strcpy(local_58,param_1)" in parsed["handle"]["pseudocode"]
    assert "system(local_58)" in parsed["handle"]["pseudocode"]


def test_decompile_enrichment_maps_to_findings(monkeypatch):
    """enrich_findings attaches pseudocode to findings by (binary, function),
    without invoking Ghidra (decompile() is monkeypatched)."""
    from ifda.model import Finding, Evidence, Severity
    import ifda.re.decompile as dc

    f = Finding(id="x", title="t", vuln_class="command_injection",
                severity=Severity.HIGH, confidence=0.8, component="/fw/bin",
                rule="r", evidence=[Evidence(binary="/fw/bin", function="handle")])
    monkeypatch.setattr(dc, "decompile",
                        lambda path, funcs, timeout=300, analysis_timeout=120: dc._parse_output(_GHIDRA_FIXTURE))
    n = dc.enrich_findings("/fw/bin", [f])
    assert n == 1
    assert "system(local_58)" in f.pseudocode


def test_decompile_degrades_without_ghidra(monkeypatch):
    """NFR-USE-1: with no Ghidra, decompile() is a no-op, not an error."""
    import ifda.re.decompile as dc

    monkeypatch.setattr(dc, "ghidra_home", lambda: None)
    assert dc.ghidra_available() is False
    assert dc.decompile("/nonexistent/bin", ["main"]) == {}


@pytest.mark.skipif(
    os.environ.get("IFDA_GHIDRA_TEST") != "1",
    reason="live Ghidra decompilation is slow; set IFDA_GHIDRA_TEST=1 to run",
)
def test_decompile_live(tmp_path):
    """Opt-in: actually run Ghidra headless on a seeded binary (FR-RE-2)."""
    from ifda.re.decompile import decompile, ghidra_available

    if not (ghidra_available() and shutil.which("gcc")):
        pytest.skip("ghidra or gcc unavailable")
    src = tmp_path / "v.c"
    src.write_text("#include <string.h>\n#include <stdlib.h>\n"
                   "void handle(char*i){char b[64];strcpy(b,i);system(b);}\n"
                   "int main(int c,char**v){if(c>1)handle(v[1]);return 0;}\n")
    binp = tmp_path / "v"
    subprocess.run(["gcc", "-O0", "-o", str(binp), str(src)], check=True)
    res = decompile(str(binp), ["handle"])
    assert "handle" in res
    assert "strcpy" in res["handle"]["pseudocode"]


def test_cve_bin_tool_scan_parses_entries(monkeypatch):
    """Fast, deterministic: exercises scan_target's entry parsing (severity
    mapping, remarks filtering, component/Finding construction) without
    invoking the real cve-bin-tool binary or its multi-GB CVE database."""
    import ifda.vuln.cve_bin_tool as cbt
    from ifda.model import Severity

    monkeypatch.setattr(cbt, "cve_bin_tool_available", lambda: True)
    fixture = [
        {"vendor": "gnu", "product": "wget", "version": "1.20.3", "location": "/fw/bin/wget",
         "cve_number": "CVE-2019-5953", "severity": "HIGH", "remarks": "NewFound",
         "description": "buffer overflow"},
        {"vendor": "openssl", "product": "openssl", "version": "1.0.1f", "location": "/fw/lib/libssl.so",
         "cve_number": "CVE-2014-0160", "severity": "CRITICAL", "remarks": "Confirmed"},
        {"vendor": "x", "product": "x", "version": "1.0", "location": "/fw/x",
         "cve_number": "CVE-9999-0001", "severity": "LOW", "remarks": "FalsePositive"},
    ]
    monkeypatch.setattr(cbt, "_run", lambda target, timeout: fixture)

    findings, comps = cbt.scan_target("/fw")

    cve_ids = {f.cve_ids[0] for f in findings}
    assert cve_ids == {"CVE-2019-5953", "CVE-2014-0160"}  # FalsePositive filtered out
    wget = next(f for f in findings if f.cve_ids[0] == "CVE-2019-5953")
    assert wget.severity == Severity.HIGH
    assert wget.component == "wget@1.20.3"
    # The FalsePositive-only "x" entry is filtered before it ever becomes a
    # component, not just before it becomes a finding.
    names = {(c.name, c.version) for c in comps}
    assert names == {("wget", "1.20.3"), ("openssl", "1.0.1f")}


def test_iter_binaries_skips_special_files(tmp_path, monkeypatch):
    """Real firmware trees carry device nodes (e.g. dev/console), FIFOs, and
    sockets. is_elf() opens+reads its argument unconditionally; opening a
    character device like /dev/console with no controlling terminal blocks
    forever on read(), silently wedging the whole scan at "enumerating
    binaries" with zero progress. iter_binaries must filter these out
    *before* ever calling is_elf() on them — is_elf is stubbed (not
    delegated to the real implementation) so this test can't itself hang if
    that guard regresses."""
    import ifda.pipeline as pipeline

    (tmp_path / "bin").mkdir()
    real_bin = tmp_path / "bin" / "busybox"
    real_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)
    fifo_path = tmp_path / "console"
    os.mkfifo(fifo_path)

    calls = []

    def fake_is_elf(path):
        calls.append(path)
        return path == str(real_bin)

    monkeypatch.setattr(pipeline, "is_elf", fake_is_elf)

    found = list(pipeline.iter_binaries(str(tmp_path)))
    assert str(fifo_path) not in calls
    assert found == [str(real_bin)]


def test_cve_bin_tool_degrades_when_missing():
    """NFR-USE-1: missing cve-bin-tool means empty results, not a crash —
    the pipeline surfaces this via a warning (see analyze()) rather than
    silently pretending coverage is unaffected."""
    from ifda.vuln.cve_bin_tool import scan_target

    findings, comps = scan_target("/fw")
    assert findings == [] and comps == []


@pytest.mark.skipif(
    os.environ.get("IFDA_CVE_BIN_TOOL_TEST") != "1",
    reason="live cve-bin-tool scan needs its local CVE database; set IFDA_CVE_BIN_TOOL_TEST=1 to run",
)
def test_cve_bin_tool_live(tmp_path):
    """Opt-in: actually invoke cve-bin-tool end to end (FR-VUL-1 broad coverage)."""
    import shutil as _shutil

    from ifda.vuln.cve_bin_tool import cve_bin_tool_available, scan_target

    if _shutil.which("cve-bin-tool") is None:
        pytest.skip("cve-bin-tool not installed")
    assert cve_bin_tool_available() is True
    findings, comps = scan_target(str(tmp_path), timeout=600)
    assert isinstance(findings, list) and isinstance(comps, list)
