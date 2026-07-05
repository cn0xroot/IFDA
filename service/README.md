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
`$TMPDIR/ifda-service`).

Requires `python3` with the `ifda` package importable from `-core` (i.e. the
core's deps installed: `python3-capstone python3-pyelftools`).

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
| `POST /api/jobs` `{"target":"/path"}` | Enqueue an analysis; returns the job (202). Dedup cache returns a cached result for an unchanged target. |
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

- **Submit / upload** a target (server path or file upload).
- **Job list** with live SSE progress bars.
- **Dashboard** tab: finding/critical/high/binary/CVE cards + severity and
  vuln-class distribution bars.
- **Findings** tab: filter by severity toggles, vuln class, triage state,
  confidence threshold, and full-text search; sort by severity/confidence;
  expand a finding for evidence, taint path, and decompiled pseudocode; triage
  inline (confirm / false-positive / accept-risk / reset).
- **Binaries** tab: per-binary arch, libc, mitigation chips
  (NX/Canary/RELRO/PIE/FORTIFY, color-coded), function count, CVEs.
- **Export** buttons: JSON / Markdown / SBOM download.

## Not yet / production notes

- Job store is in-memory (triage is persisted to disk); a shared store
  (Postgres/Redis) is the drop-in behind `Store` + `TriageStore`.
- Upload stores the file as-is; extraction (FR-ING/FR-EXT) and authn/z still
  belong in front of the API for a real deployment.
- The dedup cache keys on target path + size + mtime.
