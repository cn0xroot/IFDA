package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// readFilePreview backs the Files tab's content-preview endpoint. Confirms
// it caps output at filePreviewCap with a truncated flag, and refuses to
// open anything that isn't a regular file -- the same "never open a device
// node/FIFO/socket" rule the Python core's tree-walkers follow, since
// opening one blocks forever rather than erroring.
func TestReadFilePreview(t *testing.T) {
	dir := t.TempDir()

	small := filepath.Join(dir, "small.sh")
	if err := os.WriteFile(small, []byte("#!/bin/sh\necho hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	content, truncated, err := readFilePreview(small)
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Error("small file must not be reported as truncated")
	}
	if content != "#!/bin/sh\necho hi\n" {
		t.Errorf("content = %q", content)
	}

	big := filepath.Join(dir, "big.conf")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", filePreviewCap+100)), 0o644); err != nil {
		t.Fatal(err)
	}
	content, truncated, err = readFilePreview(big)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Error("file over the cap must be reported as truncated")
	}
	if len(content) != filePreviewCap {
		t.Errorf("content length = %d, want %d", len(content), filePreviewCap)
	}

	// A directory is not a regular file -- must error, not hang or panic.
	if _, _, err := readFilePreview(dir); err == nil {
		t.Error("expected an error reading a directory as a file preview")
	}
}

func TestRunAIAnalysisJobNotCompleted(t *testing.T) {
	api, store, _ := newTestAPI(t)
	job := store.Create("/bin/ls", false) // default status: queued

	req := httptest.NewRequest(http.MethodPost, "/api/jobs/"+job.ID+"/ai-analysis",
		strings.NewReader(`{"provider_id":"whatever"}`))
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.runAIAnalysis(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body=%s", w.Code, http.StatusConflict, w.Body.String())
	}
}

func TestRunAIAnalysisUnknownProvider(t *testing.T) {
	api, store, _ := newTestAPI(t)
	job := store.Create("/bin/ls", false)
	store.update(job.ID, func(j *Job) { j.Status = StatusCompleted })

	req := httptest.NewRequest(http.MethodPost, "/api/jobs/"+job.ID+"/ai-analysis",
		strings.NewReader(`{"provider_id":"does-not-exist"}`))
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.runAIAnalysis(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d; body=%s", w.Code, http.StatusNotFound, w.Body.String())
	}
}

func TestRunAIAnalysisProviderUnreachable(t *testing.T) {
	api, store, reportDB := newTestAPI(t)
	job := store.Create("/bin/ls", false)
	store.update(job.ID, func(j *Job) { j.Status = StatusCompleted })

	// A closed server: connections to it are refused immediately, giving a
	// deterministic "provider unreachable" case with no real network access.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	dead.Close()

	enc, err := encryptSecret(api.aiKey, "sk-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := reportDB.CreateProvider(AIProvider{ID: "ai-dead", Name: "Dead", Host: dead.URL,
		APIKeyEnc: enc, KeyLast4: "test", Model: "gpt-test", CreatedAt: "now", UpdatedAt: "now"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/jobs/"+job.ID+"/ai-analysis",
		strings.NewReader(`{"provider_id":"ai-dead"}`))
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.runAIAnalysis(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d; body=%s", w.Code, http.StatusBadGateway, w.Body.String())
	}

	// The failed run must be recorded so a later GET shows the error instead
	// of silently reverting to "no analysis yet".
	analysis, err := reportDB.GetAnalysis(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if analysis == nil || analysis.Status != "error" {
		t.Errorf("GetAnalysis after a failed run = %+v", analysis)
	}
}

// The provider list/create endpoints must never leak the plaintext or
// encrypted API key to the browser -- only key_last4.
func TestProviderAPIKeyNeverReturnedInResponse(t *testing.T) {
	api, _, _ := newTestAPI(t)
	const secret = "sk-this-must-never-leak-1234567890"

	req := httptest.NewRequest(http.MethodPost, "/api/ai/providers",
		strings.NewReader(`{"name":"Test","host":"https://gw.example.com","api_key":"`+secret+`","model":"gpt-test"}`))
	w := httptest.NewRecorder()
	api.createAIProvider(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("createAIProvider status = %d, body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), secret) {
		t.Fatalf("createAIProvider response leaked the plaintext API key: %s", w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if _, ok := created["api_key"]; ok {
		t.Error("response must not contain an api_key field")
	}
	if _, ok := created["api_key_enc"]; ok {
		t.Error("response must not contain an api_key_enc field")
	}
	if created["key_last4"] != "7890" {
		t.Errorf("key_last4 = %v, want 7890", created["key_last4"])
	}

	w2 := httptest.NewRecorder()
	api.listAIProviders(w2, httptest.NewRequest(http.MethodGet, "/api/ai/providers", nil))
	if strings.Contains(w2.Body.String(), secret) {
		t.Fatalf("listAIProviders response leaked the plaintext API key: %s", w2.Body.String())
	}
}

// ndjsonEvents splits a runAIAnalysis streaming response body into its
// decoded per-line JSON events, in order.
func ndjsonEvents(t *testing.T, body string) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line == "" {
			continue
		}
		var evt map[string]any
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			t.Fatalf("could not parse NDJSON line %q: %v", line, err)
		}
		events = append(events, evt)
	}
	return events
}

// End-to-end through the actual handler (not just the provider-level
// streaming functions): a successful run must emit delta events that
// reconstruct the full text, a final done event carrying prompt_meta, and
// leave the completed analysis persisted in the DB.
func TestRunAIAnalysisStreamsAndPersists(t *testing.T) {
	api, store, reportDB := newTestAPI(t)
	job := store.Create("/bin/ls", false)
	store.update(job.ID, func(j *Job) { j.Status = StatusCompleted })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	enc, err := encryptSecret(api.aiKey, "sk-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := reportDB.CreateProvider(AIProvider{ID: "ai-stream", Name: "Stream Test", Host: srv.URL,
		APIKeyEnc: enc, KeyLast4: "test", Model: "gpt-test", Kind: "openai", CreatedAt: "now", UpdatedAt: "now"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/jobs/"+job.ID+"/ai-analysis",
		strings.NewReader(`{"provider_id":"ai-stream"}`))
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.runAIAnalysis(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
	}
	events := ndjsonEvents(t, w.Body.String())
	if len(events) != 3 {
		t.Fatalf("events = %+v, want 3 (2 deltas + done)", events)
	}
	var text string
	for _, e := range events[:2] {
		if e["type"] != "delta" {
			t.Errorf("event = %+v, want type=delta", e)
		}
		text += e["text"].(string)
	}
	if text != "hello world" {
		t.Errorf("assembled text = %q, want %q", text, "hello world")
	}
	last := events[2]
	if last["type"] != "done" {
		t.Errorf("last event = %+v, want type=done", last)
	}
	if last["prompt_meta"] == nil {
		t.Error("done event must carry prompt_meta")
	}

	analysis, err := reportDB.GetAnalysis(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if analysis == nil || analysis.Status != "done" || analysis.Content != "hello world" {
		t.Errorf("persisted analysis = %+v, want status=done content=%q", analysis, "hello world")
	}
}

// Two analyses of the same job running at once would interleave their
// partial-content writes into the same row (each writes its whole
// accumulated transcript every ~500ms), leaving stored content flapping
// between two different partial texts. The second concurrent run must be
// refused outright.
func TestRunAIAnalysisRefusesConcurrentRunOnSameJob(t *testing.T) {
	api, store, reportDB := newTestAPI(t)
	job := store.Create("/bin/ls", false)
	store.update(job.ID, func(j *Job) { j.Status = StatusCompleted })

	// Holds the first request inside the provider call until released, so
	// the second request provably overlaps it.
	release := make(chan struct{})
	started := make(chan struct{})
	var once sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { close(started) })
		<-release
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()

	enc, err := encryptSecret(api.aiKey, "sk-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := reportDB.CreateProvider(AIProvider{ID: "ai-1", Name: "P", Host: srv.URL,
		APIKeyEnc: enc, KeyLast4: "test", Model: "m", Kind: "openai", MaxTokens: 4096,
		CreatedAt: "now", UpdatedAt: "now"}); err != nil {
		t.Fatal(err)
	}

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/jobs/"+job.ID+"/ai-analysis",
			strings.NewReader(`{"provider_id":"ai-1"}`))
		req.SetPathValue("id", job.ID)
		return req
	}

	firstDone := make(chan int, 1)
	go func() {
		w := httptest.NewRecorder()
		api.runAIAnalysis(w, newReq())
		firstDone <- w.Code
	}()

	<-started // first run is now inside the provider call

	w2 := httptest.NewRecorder()
	api.runAIAnalysis(w2, newReq())
	if w2.Code != http.StatusConflict {
		t.Errorf("second concurrent run status = %d, want %d", w2.Code, http.StatusConflict)
	}

	close(release)
	if code := <-firstDone; code != http.StatusOK {
		t.Errorf("first run status = %d, want 200", code)
	}

	// Slot must be free again now the first run finished (`release` is
	// already closed, so the fake provider no longer blocks).
	w3 := httptest.NewRecorder()
	api.runAIAnalysis(w3, newReq())
	if w3.Code != http.StatusOK {
		t.Errorf("a run after the previous completed = %d, want 200 (slot must be released)", w3.Code)
	}
}

// A failure that happens after streaming has already begun (headers
// committed) must be encoded as a trailing NDJSON error event rather than
// an HTTP error status -- and the partial content streamed before the
// failure must still be persisted, not discarded.
func TestRunAIAnalysisMidStreamErrorPreservesPartialContent(t *testing.T) {
	api, store, reportDB := newTestAPI(t)
	job := store.Create("/bin/ls", false)
	store.update(job.ID, func(j *Job) { j.Status = StatusCompleted })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"partial answer\"}}\n\n")
		fmt.Fprint(w, "event: error\ndata: {\"error\":{\"message\":\"Overloaded\"}}\n\n")
	}))
	defer srv.Close()

	enc, err := encryptSecret(api.aiKey, "sk-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := reportDB.CreateProvider(AIProvider{ID: "ai-mid-error", Name: "Mid Error Test", Host: srv.URL,
		APIKeyEnc: enc, KeyLast4: "test", Model: "claude-x", Kind: "anthropic", CreatedAt: "now", UpdatedAt: "now"}); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/jobs/"+job.ID+"/ai-analysis",
		strings.NewReader(`{"provider_id":"ai-mid-error"}`))
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.runAIAnalysis(w, req)

	// Headers were already committed (status 200) by the time the mid-stream
	// error happened -- there's no changing that after the fact.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (headers already sent before the mid-stream failure)", w.Code)
	}
	events := ndjsonEvents(t, w.Body.String())
	if len(events) != 2 {
		t.Fatalf("events = %+v, want 2 (1 delta + error)", events)
	}
	if events[0]["type"] != "delta" || events[0]["text"] != "partial answer" {
		t.Errorf("events[0] = %+v", events[0])
	}
	if events[1]["type"] != "error" {
		t.Errorf("events[1] = %+v, want type=error", events[1])
	}

	analysis, err := reportDB.GetAnalysis(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if analysis == nil || analysis.Status != "error" || analysis.Content != "partial answer" {
		t.Errorf("persisted analysis = %+v, want status=error content=%q", analysis, "partial answer")
	}
}
