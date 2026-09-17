# IFDA service layer (Go)

The orchestration tier of the hybrid architecture: a Go HTTP service that drives
the Python analysis core one artifact at a time, with a job queue, a progress
state machine, a REST API (FR-INT-1), batch/corpus submission with a dedup cache
(FR-ING-4 / NFR-PERF), and an embedded web UI that shows live task progress and
findings detail.

```
 browser ──HTTP──► Go service ──exec──► python3 -m ifda.cli analyze --progress
   (web UI)         (queue +            (the Python core; JSON report + @@IFDA@@
                     workers +           progress events on stderr)
                     REST API)
```

The boundary is the JSON report model (`ifda/model.py`): the worker shells out
to the CLI, streams `@@IFDA@@<json>` progress lines from stderr into the job,
and serves the resulting report file back over the API. No Python HTTP server is
needed — the CLI contract is the integration surface.

## Build & run

```bash
cd service
/usr/local/go/bin/go build -o ifda-service .     # Go 1.22+
./ifda-service -addr :8080 -core /path/to/repo    # -core auto-detected if run inside the repo
# open http://localhost:8080
```

Flags: `-addr` (listen address), `-core` (dir containing the `ifda` package;
auto-detected by walking up from cwd), `-workers` (concurrent analyses, default
2), `-queue` (max queued jobs), `-data` (dir for triage state + uploads; default
`$TMPDIR/ifda-service`), `-analyze-timeout` (hard wall-clock cap per analyze
subprocess, default 2h — a safety net against a truly hung run, not a target-size
estimate; raise it for unusually large targets, e.g. an automotive/infotainment
image with thousands of binaries including embedded Chromium, which can need
well over an hour just for the disassemble stage).

Requires `python3` with the `ifda` package importable from `-core` (i.e. the
core's deps installed: `python3-capstone python3-pyelftools`).

### Production launch

`service/start.sh` runs the real deployment: `./ifda-service -addr :8080 -user admin
-pass ifda@2026 -data ./.data`. No `-core` — it relies on auto-detect, so this only
works run from inside the repo (or a subdirectory of it), same as any other invocation
with `-core` omitted. `-data` matters: `./.data` is where the real job history/AI
provider config/user accounts actually live — pointing this at a different or missing
directory silently starts the service on an empty or stale database instead of
erroring (see PROGRESS.md's 2026-08-25 entries). The `-pass` here only seeds `admin`
on an account that doesn't have a password yet; it does **not** mean that's the
current password (see the section below) — do not assume it.

**Restarting kills any job that's currently running — it does not survive as an
orphaned process.** Don't assume an in-flight `python3 -m ifda.cli analyze` subprocess
will keep running independently after the parent `ifda-service` process is killed; in
practice it gets torn down along with it (observed even though the subprocess is
launched in its own process group via `Setpgid: true`, which in theory should isolate
it from a plain `kill <pid>` on the parent — most likely a host-level cgroup/session
teardown rather than anything `job.go` itself does; see PROGRESS.md's 2026-08-25 entry
for the full writeup). Check for a running job before restarting; there's no partial
report to recover afterward.

### Auth flags: `-auth` / `-user` / `-pass` / `-reset-pass`

`-auth` defaults to `true` (login required). `-user`/`-pass` only **seed** an
account the first time it's created (e.g. first launch against a fresh
`-data` dir, or a username that doesn't exist yet in `users.json`) — they do
**not** overwrite a password that already exists, including one changed via
the web UI's User center → Change password. This is deliberate: if your
launch command (a systemd unit, a docker-compose command line, ...) always
passes the same `-user`/`-pass`, treating that as "set this every time" would
silently revert any password a user picked in the UI on every restart, with
no indication anything happened. When this path is taken, the log says so:

```
-user/-pass ignored: "admin" already has a password (possibly changed via the web UI) — pass -reset-pass to force it back to -pass
```

To actually force a password (e.g. recovering a forgotten one), pass
`-reset-pass` alongside `-user`/`-pass` — it overwrites unconditionally, every
time it's present, so remove it from the launch command again once you're
back in.

## REST API

| Method & path | Purpose |
|---|---|
| `POST /api/jobs` `{"target":"/path"}` | Enqueue an analysis; returns the job (202). Dedup cache returns a cached result for an unchanged target. Add `"kind":"extract"` to identify + unpack a raw firmware image via `moria` (FR-ING/FR-EXT; needs a moria build — see below) instead — the completed job carries `regions` (moria's findings, each with an `offset`/`type`/`status`/`usable`/`path`), not a findings report; pick a region and resubmit its `path` as a normal (or another `extract`) job. Add `"force":true` to bypass the dedup cache (e.g. the web UI's re-scan button); meaningless for `kind:"extract"`, which never uses the cache. |
| `GET /api/jobs` | List jobs (newest first) with status + progress. |
| `GET /api/jobs/{id}` | One job: status, progress %, stage, detail, counts. |
| `GET /api/jobs/{id}/events` | **SSE** stream of job progress until terminal. |
| `GET /api/jobs/{id}/report` | Findings report with triage overlaid. `?format=json\|md\|sbom`, `?download=1`. |
| `POST /api/jobs/{id}/triage` `{"finding_id","state"}` | Set triage (`new\|confirmed\|false_positive\|accepted_risk`); persisted. |
| `POST /api/upload` (multipart `file`) | Store an artifact server-side; returns a `target` path to submit. |
| `GET /healthz` | Liveness. |
| `GET /` | Embedded single-page web UI. |

Job status machine: `queued → running → completed | failed`. While running,
`progress` (0–100), `stage`, and `detail` update live; clients receive them via
the SSE `events` stream (no polling).

```bash
curl -XPOST localhost:8080/api/jobs -H 'Content-Type: application/json' \
     -d '{"target":"/path/to/extracted_rootfs"}'
curl -N  localhost:8080/api/jobs/<id>/events                 # live progress (SSE)
curl     localhost:8080/api/jobs/<id>/report                 # findings JSON
curl     "localhost:8080/api/jobs/<id>/report?format=md"     # Markdown export
curl -XPOST localhost:8080/api/jobs/<id>/triage \
     -H 'Content-Type: application/json' \
     -d '{"finding_id":"<id>","state":"false_positive"}'     # triage a finding
```

### Triage persistence

Triage is keyed by finding **fingerprint** (the same id the Python core uses),
stored in `<data>/triage.json`, and overlaid onto every served report. A decision
therefore survives a service restart and re-applies to any future job that
re-discovers the same finding (FR-VUL-8) — including across different scans of the
same firmware.

## Web UI

`web/index.html` + vendored `web/vendor/alpine.min.js`, both embedded into the
binary (no CDN, no build step — works air-gapped). Built on Alpine.js:

- **Header**: the open report's image name with its architecture, kernel and size; a
  segmented group for Compare / CVE database / Sensitive dictionary / AI settings; and a
  user menu holding the things set once per session (triage display name, language, theme).
- **Submit / upload** a target (server path or file upload) at the top of the left rail.
- **Job list** with live SSE progress. Every field in a card is single-line and clips, with
  the full value on its title attribute.
- Five primary tabs. **Dashboard**, **Findings**, **Inventory**, **Strings** and **AI
  analysis**; Inventory and Strings each open a second-level segmented control (Inventory:
  Binaries / Scripts / Components / Files / BusyBox / Services — Strings: all strings /
  sensitive).
- **Dashboard**: total findings with a proportional severity bar covering all five levels,
  an inventory tile row, and the BusyBox / network-service / rootfs-composition panels.
- **Findings**: severity pills carrying each level's count, plus filters for vuln class,
  triage state, confidence threshold and full-text search; sort by severity/confidence;
  group by component (a group of more than five starts collapsed) or show a flat list;
  expand a finding for evidence, taint path, and decompiled pseudocode; triage inline
  (confirm / false-positive / accept-risk / reset).
- **Binaries**: fixed-height rows; per-binary path (the shared directory prefix truncates,
  the file name never does), arch, libc, a six-slot hardening strip
  (NX / CN / RL / PI / FT / SY, colour-coded on / partial / off, with a legend), CVE count,
  string count, function count, and the full MD5.
- **Export** buttons: JSON / Markdown / SBOM download.

Colour tokens are per-theme CSS custom properties on `[data-theme]`. `--muted` is the
lightest value still used for text and is picked per theme to clear 4.5:1 against that
theme's `--panel`; `--dim` is the dimmer step and is for hairlines and decorative glyphs
only, never text.

## Firmware extraction (moria)

The `extract` job kind shells out to `python3 -m ifda.cli extract`, which runs `moria`. The
binary is resolved by `ifda/ingest` as `$IFDA_MORIA`, then the in-tree build of the pinned
submodule at `moria/build/moria`, then `moria` on `PATH` — build it with
`scripts/build-moria.sh` from the repo root.

The service probes this **once at startup** and logs what answered:

```
moria firmware extraction: moria 0.2.1
```

The same string is served as `moria_version` on `GET /healthz` (empty when there is no moria),
which is what the web UI reads to disable the Extract button with a hint instead of letting a
submitted job fail. Rebuilding or installing moria therefore needs a service restart to be
noticed — the probe is not repeated per job.

## Not yet / production notes

- Job store is in-memory (triage is persisted to disk); a shared store
  (Postgres/Redis) is the drop-in behind `Store` + `TriageStore`.
- Upload stores the file as-is; extraction (FR-ING/FR-EXT) and authn/z still
  belong in front of the API for a real deployment.
- The dedup cache keys on target path + size + mtime.
