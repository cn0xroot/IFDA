package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// --- HTTP handlers ---

type aiProviderReq struct {
	Name       string `json:"name"`
	Host       string `json:"host"`
	APIKey     string `json:"api_key"` // empty on update means "keep existing"
	Model      string `json:"model"`
	Kind       string `json:"kind"`        // "openai" (default) | "anthropic"
	MaxTokens  int    `json:"max_tokens"`  // 0/unset -> aiMaxOutputTokens; see normalizeMaxTokens
	ProviderID string `json:"provider_id"` // fetchAIModels only: reuse a saved provider's key
}

// normalizeKind validates/defaults the provider kind. Anything other than
// the recognized "anthropic" falls back to "openai" -- the long-standing
// default protocol -- rather than rejecting the request, so an older
// frontend build that never sends `kind` keeps working unchanged.
func normalizeKind(kind string) string {
	if kind == "anthropic" {
		return "anthropic"
	}
	return "openai"
}

// minAIMaxTokens/maxAIMaxTokens bound the user-configurable per-provider
// output cap: too low and every non-trivial analysis truncates before it
// says anything useful; too high risks a single accidental run generating
// an enormous (and, for a paid API, expensive) response with no real
// benefit, since maxFindingsInPrompt already bounds how much there is to
// say. Generous enough for current-generation frontier models' typical
// output ranges without being unbounded.
const (
	minAIMaxTokens = 256
	maxAIMaxTokens = 65536
)

// normalizeMaxTokens defaults an unset/zero value to aiMaxOutputTokens and
// clamps anything else into [minAIMaxTokens, maxAIMaxTokens], rather than
// forwarding an arbitrary user-supplied number straight into the provider
// request.
func normalizeMaxTokens(n int) int {
	if n <= 0 {
		return aiMaxOutputTokens
	}
	if n < minAIMaxTokens {
		return minAIMaxTokens
	}
	if n > maxAIMaxTokens {
		return maxAIMaxTokens
	}
	return n
}

func (a *API) listAIProviders(w http.ResponseWriter, r *http.Request) {
	providers, err := a.reportDB.ListProviders()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]AIProviderPublic, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.Public())
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createAIProvider(w http.ResponseWriter, r *http.Request) {
	var req aiProviderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" || req.Host == "" || req.APIKey == "" || req.Model == "" {
		writeErr(w, http.StatusBadRequest, "name, host, api_key and model are all required")
		return
	}
	enc, err := encryptSecret(a.aiKey, req.APIKey)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store API key")
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	p := AIProvider{
		ID: "ai-" + randHex(8), Name: req.Name, Host: normalizeHost(req.Host),
		APIKeyEnc: enc, KeyLast4: keyLast4(req.APIKey), Model: req.Model, Kind: normalizeKind(req.Kind),
		MaxTokens: normalizeMaxTokens(req.MaxTokens),
		CreatedAt: now, UpdatedAt: now,
	}
	if err := a.reportDB.CreateProvider(p); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, p.Public())
}

func (a *API) updateAIProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := a.reportDB.GetProvider(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeErr(w, http.StatusNotFound, "AI provider not found")
		return
	}
	var req aiProviderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" || req.Host == "" || req.Model == "" {
		writeErr(w, http.StatusBadRequest, "name, host and model are all required")
		return
	}
	var encPtr, last4Ptr *string
	if req.APIKey != "" {
		enc, err := encryptSecret(a.aiKey, req.APIKey)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not store API key")
			return
		}
		last4 := keyLast4(req.APIKey)
		encPtr, last4Ptr = &enc, &last4
	}
	if err := a.reportDB.UpdateProvider(id, req.Name, normalizeHost(req.Host), req.Model, normalizeKind(req.Kind), normalizeMaxTokens(req.MaxTokens), encPtr, last4Ptr); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	updated, err := a.reportDB.GetProvider(id)
	if err != nil || updated == nil {
		writeErr(w, http.StatusInternalServerError, "provider updated but could not be re-read")
		return
	}
	writeJSON(w, http.StatusOK, updated.Public())
}

func (a *API) deleteAIProvider(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	existing, err := a.reportDB.GetProvider(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if existing == nil {
		writeErr(w, http.StatusNotFound, "AI provider not found")
		return
	}
	if err := a.reportDB.DeleteProvider(id); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

// fetchAIModels is the "test connection + list models" step used both when
// adding a new provider (key not yet saved -- host/api_key come inline) and
// when re-testing/editing an existing one (api_key left blank + provider_id
// set means "use the already-stored key").
func (a *API) fetchAIModels(w http.ResponseWriter, r *http.Request) {
	var req aiProviderReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	host, apiKey, kind := req.Host, req.APIKey, req.Kind
	if apiKey == "" && req.ProviderID != "" {
		existing, err := a.reportDB.GetProvider(req.ProviderID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if existing == nil {
			writeErr(w, http.StatusNotFound, "AI provider not found")
			return
		}
		if host == "" {
			host = existing.Host
		}
		if kind == "" {
			kind = existing.Kind
		}
		plain, err := decryptSecret(a.aiKey, existing.APIKeyEnc)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not decrypt stored API key")
			return
		}
		apiKey = plain
	}
	if host == "" || apiKey == "" {
		writeErr(w, http.StatusBadRequest, "host and api_key are required")
		return
	}
	models, err := fetchModels(r.Context(), a.httpClient, normalizeKind(kind), host, apiKey)
	if err != nil {
		writeAIError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"models": models})
}

func (a *API) getAIAnalysis(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := a.store.Get(id); !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	analysis, err := a.reportDB.GetAnalysis(id)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if analysis == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "none"})
		return
	}
	writeJSON(w, http.StatusOK, analysis)
}

type runAIAnalysisReq struct {
	ProviderID string `json:"provider_id"`
	Lang       string `json:"lang"` // "zh" or "en" (default); see normalizeAILang
}

func (a *API) runAIAnalysis(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := a.store.Get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	// One analysis per job at a time -- concurrent runs would interleave
	// their partial-content writes into the same row. Claimed before any
	// provider work begins and released on every exit path.
	if !a.beginAIRun(job.ID) {
		writeErr(w, http.StatusConflict, "an AI analysis is already running for this job")
		return
	}
	defer a.endAIRun(job.ID)

	var req runAIAnalysisReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ProviderID == "" {
		writeErr(w, http.StatusBadRequest, "provider_id is required")
		return
	}
	provider, err := a.reportDB.GetProvider(req.ProviderID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if provider == nil {
		writeErr(w, http.StatusNotFound, "selected AI provider no longer exists")
		return
	}
	apiKey, err := decryptSecret(a.aiKey, provider.APIKeyEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not decrypt stored API key")
		return
	}

	messages, promptMeta, err := buildAnalysisPrompt(a.reportDB, job.ID, req.Lang)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.reportDB.UpsertAnalysisRunning(job.ID, provider.ID, provider.Name, provider.Model); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}

	// headersSent tracks whether the response has switched into streaming
	// mode yet. A failure before the first delta (provider unreachable, bad
	// auth, exhausted retries, ...) has written nothing to the client yet,
	// so it can still be reported as an ordinary JSON error with a real
	// HTTP status -- exactly like the pre-streaming behavior. Only once
	// content has actually started streaming does a failure have to be
	// encoded as a trailing NDJSON event instead, since the status code and
	// headers are already committed by then.
	headersSent := false
	ensureHeaders := func() {
		if headersSent {
			return
		}
		headersSent = true
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
	}
	writeEvent := func(v any) {
		enc, _ := json.Marshal(v)
		w.Write(enc)
		w.Write([]byte("\n"))
		flusher.Flush()
	}

	var full strings.Builder
	lastPersist := time.Now()
	onDelta := func(delta string) {
		ensureHeaders()
		full.WriteString(delta)
		writeEvent(map[string]string{"type": "delta", "text": delta})
		if time.Since(lastPersist) >= aiStreamPersistInterval {
			a.reportDB.UpdateAnalysisContent(job.ID, full.String())
			lastPersist = time.Now()
		}
	}

	// Tool activity is surfaced as its own event type so the UI can show
	// what the model is fetching instead of an unexplained pause between
	// text bursts. Unknown event types are ignored by older frontends, so
	// this is a backward-compatible addition to the NDJSON contract.
	onTool := func(name, detail string) {
		ensureHeaders()
		writeEvent(map[string]string{"type": "tool", "name": name, "detail": detail})
	}

	sreq := streamRequest{
		Kind:      normalizeKind(provider.Kind),
		Host:      provider.Host,
		APIKey:    apiKey,
		Model:     provider.Model,
		MaxTokens: normalizeMaxTokens(provider.MaxTokens),
		Messages:  withToolInstruction(messages),
		Tools:     aiTools(),
	}
	stats, err := runAnalysisAgent(r.Context(), a.httpClient, a.reportDB, job.ID, sreq, onDelta, onTool)
	if err != nil {
		msg := aiErrorMessage(err, provider.Host)
		a.reportDB.FailAnalysis(job.ID, full.String(), msg)
		if !headersSent {
			writeAIError(w, err)
			return
		}
		writeEvent(map[string]string{"type": "error", "message": msg})
		return
	}

	// Fold the agent's accounting into prompt_meta so tool usage and its
	// cost (rounds each replay the growing conversation) are visible.
	promptMeta = withAgentStats(promptMeta, stats)

	if err := a.reportDB.CompleteAnalysis(job.ID, full.String(), promptMeta); err != nil {
		if !headersSent {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeEvent(map[string]string{"type": "error", "message": err.Error()})
		return
	}
	ensureHeaders() // defensive: a successful run always emits at least one delta (an empty stream is errEmptyChoices), so this is normally a no-op
	writeEvent(map[string]any{"type": "done", "prompt_meta": json.RawMessage(promptMeta)})
}

// withAgentStats merges the agent loop's counters into the prompt_meta
// blob. Done here rather than in buildAnalysisPrompt because the counts
// only exist once the run has finished.
func withAgentStats(promptMeta json.RawMessage, stats agentStats) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(promptMeta, &m) != nil || m == nil {
		m = map[string]any{}
	}
	m["tools_offered"] = stats.ToolsOffered
	m["tools_unsupported"] = stats.ToolsUnsupported
	m["tool_rounds"] = stats.ToolRounds
	m["tool_calls"] = stats.ToolCalls
	merged, err := json.Marshal(m)
	if err != nil {
		return promptMeta // keep the original rather than losing it
	}
	return merged
}

// aiStreamPersistInterval throttles how often a running analysis's partial
// content is written to SQLite while streaming -- writing on every single
// delta (which can arrive many times a second) would put needless pressure
// on the single-writer DB; this cadence still means a page reload mid-run
// only ever sees content a fraction of a second stale.
const aiStreamPersistInterval = 500 * time.Millisecond
