# IFDA — IoT Firmware Deep Analysis

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

- **Dashboard** — finding/critical/high/binary/CVE cards + severity and
  vuln-class distribution bars.
- **Findings** — filter by severity toggles, vuln class, triage state, confidence
  threshold, and full-text search; sort by severity/confidence; expand for
  evidence, taint path, and Ghidra pseudocode; **triage inline** (confirm /
  false-positive / accept-risk / reset).
- **Binaries** — per-binary arch, libc, mitigation chips (NX/Canary/RELRO/PIE/
  FORTIFY, color-coded), function count, CVEs.
- **Export** — download JSON / Markdown / SBOM.

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
