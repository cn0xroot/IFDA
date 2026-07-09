# IFDA — IoT Firmware Deep Analysis

> English | [简体中文](README.zh-CN.md)

Automated reverse engineering and vulnerability discovery for IoT firmware
binaries. This repository implements the **analysis core** described in
[`firmware-analysis-requirements.md`](firmware-analysis-requirements.md).

> **Defensive / authorized use only.** Analyze firmware you own or are
> authorized to assess. See requirements §1.3.

## Iteration 1 scope

Per the agreed plan, the first iteration delivers **binary reverse engineering
(FR-RE)** and **vulnerability discovery (FR-VUL)**. It assumes ingestion and
extraction (FR-ING / FR-EXT) have already produced files on disk — point it at a
single ELF or an extracted firmware tree.

Engines wrap existing tooling: **capstone** (multiarch disassembly, works for
MIPS/ARM regardless of host), **pyelftools** + **binutils** (ELF parsing,
mitigations). A heavier taint engine (angr) is an optional future drop-in behind
the same interface.

## Architecture

```
        ┌───────────────────────────── Python analysis core (this repo) ──────┐
 extr.  │ loader/      re/            vuln/           inventory/ scripts/ fs/  │
 arts ──┼► load_elf ─► disassemble ─► dangerous_funcs ► secrets  shell    hard-│─► JSON /
 (FR-   │ (arch,       mitigations    taint (src→sink)  + rules/ (cmd-    ening │   Markdown
  EXT)  │  imports,    call-graph     cve correlation   signatures injection)  │   + SBOM
        │  strings)    xrefs          cross-binary +    + entropy             │   (CycloneDX)
        │                             prioritize/triage                       │
        └─────────────────────────────────────────────────────────────────────┘
                         ▲
                         │ exec `ifda.cli analyze --progress` per job
            Go service / orchestration layer (service/)  ← queue, workers,
            REST API (FR-INT-1), dedup cache, web UI with live progress
```

The Python core is a library + CLI. The **hybrid architecture** chosen for the
project puts batch/corpus orchestration, the REST API (FR-INT-1), queueing
(FR-ING-4), and a web UI in a separate **Go service layer** (`service/`, built)
that drives this core one job at a time via the CLI. The JSON model
(`ifda/model.py`) is the contract between the two; the core streams
`@@IFDA@@<json>` progress events so the service shows live task progress. See
[`service/README.md`](service/README.md) to build and run it.

## Tech stack

**Analysis core (Python 3.10+)**
- [`capstone`](https://www.capstone-engine.org/) — multiarch disassembly (x86/x86_64, ARM, ARM Thumb-2, AArch64, MIPS LE/BE)
- [`pyelftools`](https://github.com/eliben/pyelftools) — ELF parsing and mitigation detection (NX/canary/RELRO/PIE/FORTIFY), no external `binutils` process needed
- [`cve-bin-tool`](https://github.com/intel/cve-bin-tool) — required dependency for FR-VUL-1's broad CVE correlation (NVD/OSV/RedHat/GitLab Advisory/Curl, 350+ components)
- [`yara-python`](https://github.com/VirusTotal/yara-python) (optional) — externalized YARA signature-rule bridge
- [`angr`](https://angr.io/) (optional, future) — heavier taint/symbolic-execution engine, planned drop-in behind the existing taint interfaces

**Service layer (Go 1.22+)**
- Standard library only, zero third-party Go dependencies — the enhanced `net/http` `ServeMux` (method + path-parameter routing), a hand-rolled PBKDF2 (`crypto/hmac` + `crypto/sha256`) for password hashing, `image`/`image/png` for the login CAPTCHA
- Server-Sent Events (no polling, no WebSocket dependency) for live job progress

**Web UI**
- [Alpine.js](https://alpinejs.dev/) 3.14.1 (vendored locally, no build step, works air-gapped)
- Plain CSS with custom-property theming (7 built-in themes, light/dark aware)

**Optional enrichment**
- [Ghidra](https://ghidra-sre.org/) (headless mode) — decompiled pseudocode enrichment for findings

## References & acknowledgements

- [**EMBA**](https://github.com/e-m-b-a/emba) — the open-source IoT firmware analyzer whose
  approach to CVE correlation and sensitive-data hunting shaped several design decisions here.
  IFDA follows EMBA's lead in delegating broad CVE correlation to `cve-bin-tool` rather than
  maintaining a hand-curated CVE list, and its `config/` signature files (`deep_key_search.cfg`,
  `password_regex.cfg`, the `*_files.cfg` sensitive-path lists) informed both the sensitive-string
  keyword dictionary and a PEM-key detection gap this project fixed. Thanks to the EMBA team for
  the prior art.
- [**cve-bin-tool**](https://github.com/intel/cve-bin-tool) (an OpenSSF project) — the actual
  engine behind FR-VUL-1's broad CVE coverage, and the same tool EMBA itself wraps for CVE
  correlation.

## Install

> Full step-by-step environment setup (Go upgrade, cross-compilers, Ghidra + JDK
> pitfalls, verification) is in [`ENVIRONMENT.md`](ENVIRONMENT.md).

```bash
# Python analysis core
apt-get install -y python3-capstone python3-pyelftools   # or: pip install -e .
pip install cve-bin-tool   # required: FR-VUL-1 broad CVE coverage (NVD/OSV/RedHat/GitLab/Curl)
pip install yara-python    # optional: enables the YARA stage if data/yara/*.yar exist

# Go service layer (optional — only if you want the REST API + web UI)
cd service && go build -o ifda-service .                # Go 1.22+
```

`cve-bin-tool` maintains its own local CVE database (NVD + OSV + RedHat + GitLab
Advisory + Curl, ~1GB+); the first scan on a machine downloads/updates it, so
expect that run to be slow and to need network access. Without it, `analyze()`
still runs but CVE correlation falls back to the small curated
`data/vuln_db.json` and the report carries a visible warning about the missing
dependency (NFR-USE-1 — one missing piece degrades, it doesn't crash the job).

## Usage

There are two ways to run ifda: the **CLI** (single run, scriptable) and the
**service** (queue + REST API + web UI with live progress).

### A. CLI — one-shot analysis

```bash
# Analyze a binary or an extracted tree; JSON to stdout by default.
python3 -m ifda.cli analyze /path/to/extracted_rootfs --json report.json --md report.md

# Emit a CycloneDX SBOM alongside the report.
python3 -m ifda.cli analyze ./rootfs --json report.json --sbom sbom.json

# Stream machine-readable progress events on stderr (used by the service).
python3 -m ifda.cli analyze ./rootfs --json report.json --progress

# Enrich findings with Ghidra decompiled pseudocode (opt-in; needs Ghidra,
# set GHIDRA_HOME or install to /opt/ghidra). Slow; degrades to no-op if absent.
python3 -m ifda.cli analyze ./rootfs --md report.md --decompile

# Triage a finding; persists across re-scans (FR-VUL-8).
python3 -m ifda.cli triage triage.json <finding_id> false_positive
python3 -m ifda.cli analyze ./rootfs --triage triage.json   # muted findings dropped
```

`analyze` accepts a single ELF or a directory (an extracted firmware tree). It
walks the tree once and runs every stage: per-binary RE/vuln, cross-binary
taint, secrets + signature rules + entropy, shell and PHP/Python/Lua script
injection, and filesystem hardening.

### B. Service — queue, REST API, and web UI

```bash
cd service
go build -o ifda-service .                 # Go 1.22+, first time only
./ifda-service -addr :8080 -core ..        # -core = repo dir (auto-detected if omitted)
# open http://localhost:8080
```

Flags: `-addr`, `-core`, `-workers` (default 2), `-queue`, `-data` (triage state
+ uploads dir; default `$TMPDIR/ifda-service`), `-auth` (default `true`),
`-user`/`-pass` (seed an account on first run only — doesn't overwrite a
password already changed via the web UI; add `-reset-pass` to force it). See
[`service/README.md`](service/README.md) for the full explanation.

**Web UI** (Alpine.js, embedded — no build step, works air-gapped): submit a
server path *or* upload a file, then watch live SSE progress and explore:

- **Dashboard** — finding/critical/high/binary/CVE cards, severity and
  vuln-class distribution bars, component/config-file/certificate counts
  (click-through), a BusyBox overview card row, and a network-services/
  open-ports card.
- **Findings** — filter by severity toggles, vuln class, triage state, confidence
  threshold, and full-text search; sort by severity/confidence; expand for
  evidence, taint path, and Ghidra pseudocode; **triage inline** (confirm /
  false-positive / accept-risk / reset).
- **Binaries** — per-binary arch, libc, mitigation chips (NX/Canary/RELRO/PIE/
  FORTIFY, color-coded), function count, CVEs (server-side paginated).
- **Files** — full non-ELF file listing, filterable by kind (binary/script/
  **config**/symlink/other); click a row to expand a syntax-highlighted
  source preview inline.
- **BusyBox** — compiled-in vs. reference-list "crippled" applets, extra
  bin/sbin executables at any tree depth, and `/etc/init.d` script source.
- **Network Services** — statically identified services (name/category/
  banner-derived version/port/port-source/binary path), filterable by
  category with keyword search.
- **CVE Database** — browse the tool's actual CVE coverage (cve-bin-tool's
  broad set + the curated offline fallback) independent of any scan; CVE
  numbers throughout the UI link out to the matching NVD page.
- **Sensitive-string dictionary** — standalone page to add/remove/reset the
  keyword dictionary used for secret matching, no scan required.
- **Compare** — diff findings/files/strings between two scans (added/
  removed/unchanged).
- **Export** — download JSON / Markdown / SBOM.
- **User center** — change password, log out.

REST endpoints (full table in [`service/README.md`](service/README.md)):

```bash
# enqueue a job (returns {"id": ...}); dedup cache returns cached unchanged targets
curl -XPOST localhost:8080/api/jobs -H 'Content-Type: application/json' \
     -d '{"target":"/path/to/extracted_rootfs"}'

curl -N  localhost:8080/api/jobs/<id>/events             # live progress (SSE, no polling)
curl     localhost:8080/api/jobs/<id>/report             # findings JSON (triage overlaid)
curl     "localhost:8080/api/jobs/<id>/report?format=md" # or format=sbom; add &download=1

# triage a finding — persisted by fingerprint, survives restarts & re-scans (FR-VUL-8)
curl -XPOST localhost:8080/api/jobs/<id>/triage -H 'Content-Type: application/json' \
     -d '{"finding_id":"<finding_id>","state":"false_positive"}'

# upload an artifact server-side, then submit the returned path as a target
curl -F "file=@firmware.bin" localhost:8080/api/upload   # -> {"target": "...", "name": ...}
```

Triage states: `new | confirmed | false_positive | accepted_risk`. Re-submitting
an unchanged target returns a cached result.

### Output

| Format | How | Contents |
|---|---|---|
| JSON | `--json` / `GET …/report` | full structured report (the integration contract) |
| Markdown | `--md` | executive summary + per-finding detail |
| CycloneDX SBOM | `--sbom` | components + detected CVEs (Dependency-Track ready) |

## What's implemented

| Requirement | Status | Where |
|---|---|---|
| FR-RE-1 Disassembly (multiarch) | ✅ | `re/disasm.py` (capstone) |
| FR-RE-3 CFG / call graph / fn boundaries | ✅ (symbol + linear fallback) | `re/disasm.py` |
| Import call resolution | ✅ x86/x86_64 + ARM/AArch64 (PLT) + MIPS (GOT/`jalr $t9`) | `re/disasm.py` |
| ARM/Thumb-2 + interworking veneers | ✅ (mapping-symbol mode switch, veneer follow) | `re/disasm.py` |
| FR-INV-4 Embedded secrets/credentials | ✅ (keys, hashes, hardcoded creds/tokens, entropy fallback) | `inventory/secrets.py` |
| FR-INT-3 Externalized signature rules (YARA-style) | ✅ (updatable JSON rule library; optional yara-python bridge) | `rules/engine.py`, `data/secret_rules.json` |
| FR-INV-3 Script analysis (shell/CGI cmd-injection) | ✅ (taint-tiered) | `scripts/shell.py` |
| FR-INV-3 Script analysis (PHP/Python/Lua injection) | ✅ (cmd/code/file-incl/deserialization) | `scripts/langs.py` |
| FS hardening (setuid, world-writable, weak perms, init) | ✅ | `fs/hardening.py` |
| FR-RE-5 Mitigations (NX/canary/RELRO/PIE/fortify) | ✅ | `re/mitigations.py` |
| FR-RE-6 Cross-references (call sites, strings) | ✅ (call/import xrefs) | `re/disasm.py` |
| FR-RE-7 Scriptable API | ✅ (library + CLI) | `pipeline.py`, `cli.py` |
| FR-RE-2 Decompiled pseudocode | ✅ (opt-in Ghidra headless; enriches findings) | `re/decompile.py` |
| FR-VUL-1 Known-CVE correlation | ✅ curated offline DB + required `cve-bin-tool` (NVD/OSV/RedHat/GitLab/Curl, 350+ components) | `vuln/cve.py`, `vuln/cve_bin_tool.py`, `data/vuln_db.json` |
| FR-VUL-2 Dangerous-function detection | ✅ | `vuln/dangerous_funcs.py` |
| FR-VUL-3 Taint / reachability | ✅ (call-graph heuristic) | `vuln/taint.py` |
| FR-VUL-4 Vuln-class coverage | ◑ overflow/cmdi/code-inj/file-incl/deserialization/fmt/weak-crypto | `vuln/catalog.py`, `scripts/langs.py` |
| FR-VUL-5 Cross-binary analysis | ✅ (global call graph, CGI→lib) | `vuln/crossbinary.py` |
| FR-VUL-7 Prioritization + evidence | ✅ | `vuln/findings.py`, `model.py` |
| FR-VUL-8 Triage state persistence | ✅ | `vuln/findings.py` |
| FR-VUL-6 Emulated/dynamic validation | ⬜ planned (optional, sandboxed) | — |
| FR-REP-1 JSON + Markdown output | ✅ | `report/` |
| FR-REP-2 SBOM (CycloneDX 1.5) | ✅ (SPDX TODO) | `report/sbom.py` |
| FR-INT-1 REST API + queue + web UI (dashboard, filtering, triage, SSE) | ✅ (Go service layer, Alpine.js) | `service/` |
| FR-ING-4 Batch submission + dedup cache | ✅ (workers + path-mtime cache) | `service/job.go` |
| Config-file classification & content hardening audit | ✅ (kind classification; content rule for telnet/anonymous-FTP/debug/SNMP-default-community/TLS-verify-off/WPS/UPnP) | `inventory/firmware_meta.py`, `vuln/config_audit.py` |
| BusyBox applet audit | ✅ (compiled vs. reference-list diff, extra bin/sbin executables, init.d dump) | `inventory/busybox_audit.py` |
| Certificate detection | ✅ (per-certificate RSA/non-RSA counts via `cryptography`, bundle/chain-aware) | `inventory/secrets.py` |
| Network service identification | ✅ (static-only; banner-derived versions, UCI/inetd/init.d-flag/default port inference) | `inventory/service_id.py` |
| Stripped-binary function-boundary recovery | ✅ (direct-call + prologue discovery, ARM/Thumb auto-detection) | `re/disasm.py` |

Legend: ✅ done · ◑ partial · ⬜ not started

## Accuracy posture

Decompilation-free static analysis is heuristic (requirements §5). Findings carry
**confidence** scores; precise call-site detections (0.8) rank above
import-presence (0.4) and call-graph taint reachability (0.5). Taint findings are
explicitly candidate paths for analyst validation, not proven exploits.

## Tests

```bash
python3 -m pytest tests/ -q
```

25 passed, 2 skipped with cross-compilers + Ghidra installed (the skips are
opt-in live tests — see `ENVIRONMENT.md`). They build real cross-compiled
samples (x86_64, MIPS LE/BE, ARM, ARM Thumb-2, AArch64) and cover: the seeded
command-injection acceptance case (source→sink path to `system()`), per-arch
import-call resolution and cross-binary RCE, mitigation detection, CVE
correlation — both the curated offline DB (including not flagging patched
versions) and `cve-bin-tool`'s entry parsing — embedded secrets (externalized
signature rules + entropy fallback, with redaction), shell/CGI command
injection, PHP/Python/Lua injection (cmd/code/file-inclusion/deserialization),
filesystem hardening, CycloneDX SBOM, prioritization ordering, and triage
persistence.

## Changelog

Full technical detail (root causes, before/after numbers, test counts) is in
[`PROGRESS.md`](PROGRESS.md)'s 变更记录 (Chinese). Feature-level summary:

- **v3.5** — Static network service identification (WEB/SSH/FTP/Telnet/gSOAP/
  DNS/SNMP/UPnP/WiFi-management daemons); versions read only from embedded
  banner strings, never guessed; ports inferred from UCI config → inetd.conf
  → init.d launch flags → known defaults. New "Network Services" tab +
  dashboard service/port-count cards. Fixed duplicate service counting from
  same-named config/init.d files vs. the real ELF binary.
- **v3.4** — Real certificate detection (RSA vs. non-RSA per certificate,
  bundle/chain-aware, via the `cryptography` library instead of a PEM-header
  guess). Dashboard gains component/config-file/certificate counts and a
  BusyBox overview card row.
- **v3.3** — Fixed a v3.2 regression where config files silently lost their
  click-to-preview affordance. Binaries/Scripts tabs moved from `?all=1`
  bulk loads to real server-side pagination.
- **v3.2** — New "config" file classification (extension/basename/UCI-path/
  content-sniff) with a server-side Files-tab Kind filter. New
  `config_audit.py` content-hardening rule (telnet, anonymous FTP, debug
  mode, default SNMP community strings, disabled TLS verification, WPS,
  UPnP left enabled). CVE numbers throughout the UI now link to NVD.
  Zero-dependency syntax highlighting for file/BusyBox previews. Fixed
  compare-scan silently reporting "0 added / all removed" instead of a
  clear error on a failed report fetch.
- **v3.0** — Stripped-ELF function-boundary recovery (direct-call + prologue
  discovery, ARM/Thumb auto-detection). CVE sync reliability fixes
  (upstream `cve-bin-tool` bug patches, NVD GitHub-mirror bootstrap
  script). Findings/binaries/scripts/components migrated from one JSON
  blob per job to SQLite with server-side pagination, fixing both a UI
  crash on large scans and a hidden export-truncation bug. New BusyBox
  applet audit tab (compiled vs. reference-list diff). Fixed a severe
  compare-scan accuracy bug caused by absolute-path fingerprint matching.
  Fixed the dedup cache silently serving pre-upgrade reports after an
  analyzer version bump.
- **v2.0** — Bilingual docs (this `README.zh-CN.md`), a Tech stack section,
  and a References & acknowledgements section (crediting EMBA and
  cve-bin-tool).
- **v1.0** — Initial release: multi-arch disassembly & import-call
  resolution (x86/x86_64, ARM, ARM Thumb-2, AArch64, MIPS LE/BE),
  vulnerability discovery (dangerous functions, taint/reachability,
  cross-binary taint, CVE correlation, CycloneDX SBOM, prioritization +
  triage persistence), embedded-secrets and script-injection detection,
  filesystem hardening, optional Ghidra decompilation, and the Go service
  layer + Alpine.js web UI.

## Next iterations

- Replace heuristic taint with angr behind the existing `detect_taint_paths` /
  `detect_cross_binary_taint` interfaces.
- FR-VUL-6 optional sandboxed emulation to confirm reachability.
- FR-REP-2 SPDX output alongside CycloneDX.
- Service layer hardening: persistent job store, upload/extraction front-end
  (FR-ING/FR-EXT), authn/z. The queue + REST API + web UI are built (`service/`).

Call resolution for x86/x86_64, ARM, ARM Thumb-2, AArch64, and MIPS LE/BE is
all in place.
```
