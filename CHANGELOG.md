# Changelog

English, feature-level changelog. Full technical detail (root causes,
before/after numbers, test counts) lives in [`PROGRESS.md`](PROGRESS.md)'s
变更记录 (Chinese). Entries for v3.5 and earlier are summarized in
[`README.md`](README.md#changelog); this file continues from v3.6 onward.

## v3.8 — 2026-07-26

AI-assisted analysis of scan results, plus AI provider configuration
management — entirely in the Go service layer (`service/`); the Python
analysis core is untouched.

- **AI provider management**: new `ai_providers` table
  (`service/reportdb.go`) supporting a custom Host URL + API Key + model,
  multiple provider profiles, full CRUD. Protocol is assumed OpenAI-compatible
  (`GET {host}/models` + `POST {host}/chat/completions`, Bearer auth) — the
  common denominator across self-hosted gateways (one-api/newapi/vLLM/Ollama)
  and mainstream vendor APIs; no multi-protocol adapter in this iteration.
  The model is never hand-typed: the UI calls `/api/ai/models` with the
  Host+Key to populate a real model dropdown, and the Save button stays
  disabled until that call succeeds.
- **Key storage**: the login password's PBKDF2 hash is one-way and can't be
  reused here — an AI provider's API key must be decryptable to forward to
  the provider. New `service/aicrypto.go`: a local random key file
  (`<data>/ai.key`, mode 0600, generated on first run) + AES-256-GCM, stdlib
  only. `key_last4` is captured before encryption (while the plaintext is
  still in hand), since it can't be recovered from the ciphertext afterward.
  The startup log explicitly calls out backing up `ai.key` alongside
  `reports.db`/`users.json` — losing it permanently strands (not exposes)
  every stored key.
- **Analysis flow**: a new "AI Analysis" tab on the report page triggers
  analysis on demand (not automatically after every scan, to keep AI-call
  cost predictable). `buildAnalysisPrompt` (`service/ai.go`) takes the top 60
  findings by severity (reusing `ListFindings`'s existing sort), truncates
  oversized description/pseudocode/evidence fields to 800 chars, and adds a
  rollup line for anything not shown, alongside a report_meta summary. The
  system prompt explicitly instructs the model to treat finding text
  (extracted from the scanned firmware) as evidence data, not instructions —
  the main prompt-injection mitigation. One cached result is kept per job
  (`ai_analyses` table; a re-run overwrites it, no history) — deleting a
  provider nulls its `provider_id` reference but keeps the
  provider_name/model snapshot and the analysis content readable. The
  frontend renders the AI's output with `x-text`/`white-space:pre-wrap`
  only, never `x-html`, since injected finding content coaxing the model into
  emitting markup would otherwise be a stored-XSS vector.
- **Tests**: new `aicrypto_test.go` (encrypt/decrypt round trip, wrong-key
  decryption must fail, key file persists across process restarts, 0600
  permissions), new `ai_test.go` (`httptest`-backed fake OpenAI-compatible
  endpoint covering `/models`/`/chat/completions` success/401/timeout/empty-
  list/malformed-JSON, plus prompt truncation and rollup-count correctness),
  and additions to `reportdb_test.go`/`api_test.go` for provider CRUD,
  analysis-cache state transitions, 409 on an incomplete job, 404 on an
  unknown provider, 502 on an unreachable provider, and an explicit
  "API key never appears in a response body" assertion. Full `go test ./...`
  passes with no regressions.
- **Manual verification**: stood up a local fake OpenAI-compatible HTTP
  endpoint and a real scratch-port service instance — walked through adding
  a provider, fetching its model list, saving, running AI analysis against a
  real completed scan job (`/bin/ls`, 13 findings), confirming the cached
  result, and confirming a deleted provider's prior analysis stays readable
  with `provider_id` cleared. Also started the compiled service against the
  production `.data` directory (5 pre-existing scan jobs) to confirm history
  still loads, the AI key file generates correctly, and the existing login
  password isn't clobbered by `-user`/`-pass`.
