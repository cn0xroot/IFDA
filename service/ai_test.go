package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFetchModelsHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization header = %q", got)
		}
		if r.URL.Path != "/models" {
			t.Errorf("path = %q, want /models", r.URL.Path)
		}
		w.Write([]byte(`{"data":[{"id":"gpt-a"},{"id":"gpt-b"}]}`))
	}))
	defer srv.Close()

	models, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 2 || models[0] != "gpt-a" || models[1] != "gpt-b" {
		t.Errorf("models = %v", models)
	}
}

func TestFetchModelsHostTrailingSlash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "//") {
			t.Errorf("path has a doubled slash: %q", r.URL.Path)
		}
		w.Write([]byte(`{"data":[{"id":"gpt-a"}]}`))
	}))
	defer srv.Close()
	if _, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL+"/", "k"); err != nil {
		t.Fatal(err)
	}
}

func TestFetchModelsUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer srv.Close()
	_, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "bad-key")
	if !errors.Is(err, errProviderNotOK) {
		t.Errorf("err = %v, want errProviderNotOK", err)
	}
}

func TestFetchModelsMalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	if _, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "k"); err == nil {
		t.Error("expected an error for a malformed JSON response")
	}
}

func TestFetchModelsEmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	_, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "k")
	if !errors.Is(err, errNoModels) {
		t.Errorf("err = %v, want errNoModels", err)
	}
}

// collectDeltas runs streamChatCompletion and returns the concatenated text
// from every onDelta call, for tests that just want the assembled result.
func collectDeltas(t *testing.T, ctx context.Context, client *http.Client, kind, host, apiKey, model string, messages []chatMessage) (string, error) {
	t.Helper()
	text, _, err := collectStream(t, ctx, client, streamRequest{
		Kind: kind, Host: host, APIKey: apiKey, Model: model,
		MaxTokens: aiMaxOutputTokens, Messages: messages,
	})
	return text, err
}

// collectStream runs one provider turn and returns the concatenated text
// plus whatever else the turn produced (tool calls, stop reason).
func collectStream(t *testing.T, ctx context.Context, client *http.Client, sreq streamRequest) (string, streamResult, error) {
	t.Helper()
	var b strings.Builder
	res, err := streamChatCompletion(ctx, client, sreq, func(s string) { b.WriteString(s) })
	return b.String(), res, err
}

func TestStreamChatCompletionHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q", r.URL.Path)
		}
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["model"] != "gpt-test" {
			t.Errorf("model = %v", body["model"])
		}
		if body["stream"] != true {
			t.Errorf(`body["stream"] = %v, want true`, body["stream"])
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"the \"}}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"analysis\"}}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	content, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "gpt-test",
		[]chatMessage{{Role: "system", Content: "sys"}, {Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if content != "the analysis" {
		t.Errorf("content = %q, want %q (deltas concatenated)", content, "the analysis")
	}
}

func TestStreamChatCompletionTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"too late\"}}]}\n\n")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := collectDeltas(t, ctx, srv.Client(), "openai", srv.URL, "k", "gpt-test", []chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want context.DeadlineExceeded", err)
	}
}

// Regression: the outbound client must not impose a deadline on the whole
// request, because http.Client.Timeout also bounds reading the response
// body -- with a streaming completion that severs long generations
// mid-sentence. A 120s whole-request Timeout previously did exactly that
// to real analyses once max_tokens was raised. The guard is structural
// (rather than a multi-minute test): Timeout must stay zero, with the
// bounding done per-phase on the transport instead.
func TestAIHTTPClientHasNoWholeRequestTimeout(t *testing.T) {
	c := newAIHTTPClient()
	if c.Timeout != 0 {
		t.Errorf("http.Client.Timeout = %v, want 0 -- it bounds response-body reads too, "+
			"which truncates long streaming completions; bound the phases on the Transport instead", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", c.Transport)
	}
	if tr.ResponseHeaderTimeout == 0 {
		t.Error("ResponseHeaderTimeout must be set, so a provider that connects then goes silent still fails")
	}
	if tr.TLSHandshakeTimeout == 0 {
		t.Error("TLSHandshakeTimeout must be set")
	}
}

// Functional counterpart to the above: a response that starts promptly but
// then streams for longer than a short whole-request deadline would allow
// must complete in full. The control client (old shape) is asserted to
// fail on the very same server, so this test can't silently stop proving
// anything if the timing constants drift.
func TestStreamChatCompletionSurvivesSlowButHealthyStream(t *testing.T) {
	const chunks = 6
	const gap = 60 * time.Millisecond // ~360ms total, well past the control's 100ms
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // headers land immediately; only the body is slow
		for i := 0; i < chunks; i++ {
			time.Sleep(gap)
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n")
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	var got strings.Builder
	_, err := streamChatCompletion(context.Background(), newAIHTTPClient(), streamRequest{
		Kind: "openai", Host: srv.URL, APIKey: "k", Model: "m",
		MaxTokens: aiMaxOutputTokens, Messages: []chatMessage{{Role: "user", Content: "hi"}},
	}, func(s string) { got.WriteString(s) })
	if err != nil {
		t.Fatalf("a healthy stream that simply takes a while must not be cut off, got: %v", err)
	}
	if got.String() != strings.Repeat("x", chunks) {
		t.Errorf("content = %q, want %d chunks", got.String(), chunks)
	}

	// Control: the pre-fix client shape fails on this identical server.
	old := &http.Client{Timeout: 100 * time.Millisecond}
	_, controlErr := collectDeltas(t, context.Background(), old, "openai", srv.URL, "k", "m",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if controlErr == nil {
		t.Error("control with a whole-request Timeout should have failed on this stream; " +
			"if it now passes, the server is too fast for this test to be proving anything")
	}
}

func TestStreamChatCompletionEmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()
	_, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "m", []chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errEmptyChoices) {
		t.Errorf("err = %v, want errEmptyChoices", err)
	}
}

// Regression: a misconfigured Host URL (e.g. Anthropic's bare
// https://api.anthropic.com without the required /v1 path) commonly comes
// back as an HTML error page from a CDN/WAF rather than a JSON error body.
// json.Unmarshal's raw error ("invalid character '<' looking for beginning
// of value") must not be what reaches the user -- fetchModels/chatCompletion
// should say plainly that the response wasn't JSON.
func TestFetchModelsHTMLResponseGivesClearError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<!DOCTYPE html><html><body>404 Not Found</body></html>"))
	}))
	defer srv.Close()
	_, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "k")
	if !errors.Is(err, errNonJSONBody) {
		t.Fatalf("err = %v, want errNonJSONBody", err)
	}
	if strings.Contains(err.Error(), "invalid character") {
		t.Errorf("error should not leak the raw json.Unmarshal message, got: %v", err)
	}
}

// Regression: a 200-status response whose body is actually HTML (the same
// "wrong Host URL" symptom as the non-streaming path, e.g. a bare gateway
// domain serving its own web UI) must not silently look like "an SSE stream
// with no data in it" -- checkNotHTML must catch it on the first line.
func TestStreamChatCompletionHTMLResponseGivesClearError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "<html>not json</html>")
	}))
	defer srv.Close()
	_, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "m", []chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errNonJSONBody) {
		t.Errorf("err = %v, want errNonJSONBody", err)
	}
}

// Anthropic's Messages API: x-api-key + anthropic-version auth (no Bearer),
// POST {host}/messages with "stream": true, "system" pulled out of the
// messages array into its own top-level field, and an SSE event stream
// (event: content_block_delta / data: {...}) instead of an OpenAI-style
// "data:"-only stream. Non-text-delta events (message_start, ping, etc.)
// must be ignored, not misread as content.
func TestAnthropicStreamChatCompletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/messages" {
			t.Errorf("path = %q, want /messages", r.URL.Path)
		}
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key header = %q", got)
		}
		if got := r.Header.Get("anthropic-version"); got != anthropicVersion {
			t.Errorf("anthropic-version header = %q, want %q", got, anthropicVersion)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header must not be set for anthropic, got %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		json.Unmarshal(body, &decoded)
		if decoded["system"] != "sys prompt" {
			t.Errorf(`body["system"] = %v, want "sys prompt"`, decoded["system"])
		}
		if decoded["max_tokens"] == nil {
			t.Error("max_tokens must be set -- Anthropic requires it, unlike OpenAI")
		}
		if decoded["stream"] != true {
			t.Errorf(`body["stream"] = %v, want true`, decoded["stream"])
		}
		msgs, _ := decoded["messages"].([]any)
		if len(msgs) != 1 {
			t.Fatalf("messages = %v, want exactly 1 (system must be pulled out)", msgs)
		}
		fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n")
		fmt.Fprint(w, "event: ping\ndata: {\"type\":\"ping\"}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"world\"}}\n\n")
		fmt.Fprint(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	}))
	defer srv.Close()

	content, err := collectDeltas(t, context.Background(), srv.Client(), "anthropic", srv.URL, "test-key", "claude-x",
		[]chatMessage{{Role: "system", Content: "sys prompt"}, {Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if content != "hello world" {
		t.Errorf("content = %q, want %q (concatenated text_delta events, other events ignored)", content, "hello world")
	}
}

// Anthropic can report a failure mid-stream via an explicit "event: error"
// block rather than a non-2xx status -- this must surface as a real error,
// not be silently swallowed as "no delta this line, keep scanning".
func TestAnthropicStreamChatCompletionMidStreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n")
		fmt.Fprint(w, "event: error\ndata: {\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n")
	}))
	defer srv.Close()

	_, err := collectDeltas(t, context.Background(), srv.Client(), "anthropic", srv.URL, "test-key", "claude-x",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errProviderNotOK) {
		t.Fatalf("err = %v, want errProviderNotOK", err)
	}
	if !strings.Contains(err.Error(), "Overloaded") {
		t.Errorf("error should include the provider's message, got: %v", err)
	}
}

// Regression: a response cut off mid-sentence by the output token limit
// must be visibly flagged, not silently returned as if it were complete --
// this is what a real user hit (a long findings-triage narrative from
// claude-opus-5 truncating with no indication anything was cut off).
func TestAnthropicStreamChatCompletionAppendsTruncationNotice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"partial answer\"}}\n\n")
		fmt.Fprint(w, "event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"max_tokens\"}}\n\n")
	}))
	defer srv.Close()

	content, err := collectDeltas(t, context.Background(), srv.Client(), "anthropic", srv.URL, "test-key", "claude-x",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, "partial answer") || !strings.Contains(content, "truncated") {
		t.Errorf("content = %q, want the real text followed by a visible truncation notice", content)
	}
}

// A stream that produces zero text_delta events (the whole max_tokens
// budget consumed by extended thinking, or by any other cause) must still
// surface the provider's stop_reason in the error -- "AI provider returned
// an empty response" alone gives the user nothing to act on.
func TestAnthropicStreamChatCompletionEmptyWithStopReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"max_tokens\"}}\n\n")
	}))
	defer srv.Close()

	_, err := collectDeltas(t, context.Background(), srv.Client(), "anthropic", srv.URL, "test-key", "claude-x",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errEmptyChoices) {
		t.Fatalf("err = %v, want errEmptyChoices", err)
	}
	if !strings.Contains(err.Error(), "max_tokens") {
		t.Errorf("error should mention the captured stop_reason, got: %v", err)
	}
}

// Same truncation-notice/finish_reason behavior on the OpenAI dialect.
func TestOpenAIStreamChatCompletionAppendsTruncationNotice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["max_tokens"] == nil {
			t.Error("max_tokens must be set explicitly (some gateways default very low if omitted)")
		}
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"partial answer\"},\"finish_reason\":null}]}\n\n")
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"length\"}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	content, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "gpt-test",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(content, "partial answer") || !strings.Contains(content, "truncated") {
		t.Errorf("content = %q, want the real text followed by a visible truncation notice", content)
	}
}

func TestOpenAIStreamChatCompletionEmptyWithFinishReason(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"content_filter\"}]}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	_, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "gpt-test",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errEmptyChoices) {
		t.Fatalf("err = %v, want errEmptyChoices", err)
	}
	if !strings.Contains(err.Error(), "content_filter") {
		t.Errorf("error should mention the captured finish_reason, got: %v", err)
	}
}

func TestAnthropicFetchModelsUsesXAPIKeyAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("x-api-key"); got != "test-key" {
			t.Errorf("x-api-key header = %q", got)
		}
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization header must not be set for anthropic, got %q", got)
		}
		w.Write([]byte(`{"data":[{"type":"model","id":"claude-3-5-sonnet-20241022"}]}`))
	}))
	defer srv.Close()

	models, err := fetchModels(context.Background(), srv.Client(), "anthropic", srv.URL, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0] != "claude-3-5-sonnet-20241022" {
		t.Errorf("models = %v", models)
	}
}

// Regression: the most common real-world misconfiguration is a Host URL
// missing its API version path (e.g. a self-hosted gateway's bare domain
// serves that gateway's own web UI -- an HTML SPA shell -- at every
// unmatched path, including "/models"). fetchModels must self-heal by
// retrying under /v1 rather than surfacing the HTML-response error.
func TestFetchModelsFallsBackToV1WhenBareHostServesHTML(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		if r.URL.Path == "/v1/models" {
			w.Write([]byte(`{"data":[{"id":"gpt-a"}]}`))
			return
		}
		// Anything else (the bare-host attempt) falls through to the SPA
		// shell, same symptom as the original bug report.
		w.Write([]byte(`<!doctype html><html><body>app shell</body></html>`))
	}))
	defer srv.Close()

	models, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0] != "gpt-a" {
		t.Errorf("models = %v", models)
	}
	if want := []string{"/models", "/v1/models"}; !reflect.DeepEqual(requests, want) {
		t.Errorf("requests = %v, want %v (bare path first, then /v1 fallback)", requests, want)
	}
}

// A host that already includes /v1 must not get a second, redundant
// fallback attempt appended (there's nothing further to fall back to).
func TestFetchModelsNoFallbackWhenHostAlreadyHasV1(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.Write([]byte("<html>broken gateway</html>"))
	}))
	defer srv.Close()

	_, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL+"/v1", "k")
	if !errors.Is(err, errNonJSONBody) {
		t.Errorf("err = %v, want errNonJSONBody", err)
	}
	if requestCount != 1 {
		t.Errorf("requestCount = %d, want 1 (host already has /v1, no fallback base to try)", requestCount)
	}
}

// A real auth failure must not trigger the /v1 retry -- a wrong host and a
// wrong key look nothing alike, and doubling an already-failed request
// wastes time without any chance of succeeding.
func TestFetchModelsDoesNotRetryOnAuthError(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid api key"}`))
	}))
	defer srv.Close()

	_, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "bad-key")
	if !errors.Is(err, errProviderNotOK) {
		t.Errorf("err = %v, want errProviderNotOK", err)
	}
	if requestCount != 1 {
		t.Errorf("requestCount = %d, want 1 (a 401 is not a wrong-base-path signal, must not retry)", requestCount)
	}
}

// withFastRetryDelays shrinks transientRetryDelays for the duration of a
// test so retry-loop tests don't have to burn the real ~5s backoff budget,
// restoring the original delays afterward.
func withFastRetryDelays(t *testing.T) {
	t.Helper()
	orig := transientRetryDelays
	transientRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { transientRetryDelays = orig })
}

// Regression: a transient "503 Service temporarily unavailable" (or a
// rate-limit 429) from the provider is often gone a moment later -- it
// must be retried automatically rather than immediately surfaced as a
// failure, since the previous behavior turned a momentary gateway hiccup
// into a needless error on every AI-analysis click.
func TestFetchModelsRetriesOn503ThenSucceeds(t *testing.T) {
	withFastRetryDelays(t)
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":{"message":"Service temporarily unavailable","type":"api_error"}}`))
			return
		}
		w.Write([]byte(`{"data":[{"id":"gpt-a"}]}`))
	}))
	defer srv.Close()

	models, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "k")
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 1 || models[0] != "gpt-a" {
		t.Errorf("models = %v", models)
	}
	if requestCount != 3 {
		t.Errorf("requestCount = %d, want 3 (2 failed attempts + 1 success)", requestCount)
	}
}

// If the provider is consistently down, doProviderRequest must eventually
// give up (not retry forever) and the resulting error should say a retry
// was actually attempted, not look like an untried first failure.
func TestChatCompletionGivesUpAfterMaxRetriesOn503(t *testing.T) {
	withFastRetryDelays(t)
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":{"message":"Service temporarily unavailable","type":"api_error"}}`))
	}))
	defer srv.Close()

	_, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "m", []chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errProviderNotOK) {
		t.Fatalf("err = %v, want errProviderNotOK", err)
	}
	if !strings.Contains(err.Error(), "retried") {
		t.Errorf("error should mention that retries were attempted, got: %v", err)
	}
	wantAttempts := 1 + len(transientRetryDelays)
	if requestCount != wantAttempts {
		t.Errorf("requestCount = %d, want %d (1 initial + %d retries)", requestCount, wantAttempts, len(transientRetryDelays))
	}
}

// A 429 (rate limited) is retried the same way as a 5xx.
func TestFetchModelsRetriesOn429(t *testing.T) {
	withFastRetryDelays(t)
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if requestCount < 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		w.Write([]byte(`{"data":[{"id":"gpt-a"}]}`))
	}))
	defer srv.Close()

	if _, err := fetchModels(context.Background(), srv.Client(), "openai", srv.URL, "k"); err != nil {
		t.Fatal(err)
	}
	if requestCount != 2 {
		t.Errorf("requestCount = %d, want 2", requestCount)
	}
}

// The same /v1 self-healing must apply to the actual analysis call, not
// just model listing -- a user who got past model selection (perhaps by
// having fetched models against a provider_id that already worked) could
// still hit this if the stored host lacks /v1 and only the completions
// path is affected on a given gateway.
func TestChatCompletionFallsBackToV1WhenBareHostServesHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/chat/completions" {
			fmt.Fprint(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok via v1\"}}]}\n\ndata: [DONE]\n\n")
			return
		}
		fmt.Fprint(w, "<!doctype html><html><body>app shell</body></html>")
	}))
	defer srv.Close()

	content, err := collectDeltas(t, context.Background(), srv.Client(), "openai", srv.URL, "k", "gpt-test",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if err != nil {
		t.Fatal(err)
	}
	if content != "ok via v1" {
		t.Errorf("content = %q, want %q", content, "ok via v1")
	}
}

// Once a base has streamed at least one real delta, a later failure on that
// same attempt must not cause the outer loop to fall back and re-run
// against another base -- that would duplicate or reset content already
// handed to the caller. This exercises the emittedAny guard directly via a
// host that lacks /v1 (so a fallback base exists and would normally be
// eligible) whose first attempt streams content then reports a mid-stream
// Anthropic-style error.
func TestStreamChatCompletionDoesNotFallBackAfterPartialStream(t *testing.T) {
	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n")
		fmt.Fprint(w, "event: error\ndata: {\"error\":{\"message\":\"Overloaded\"}}\n\n")
	}))
	defer srv.Close()

	content, err := collectDeltas(t, context.Background(), srv.Client(), "anthropic", srv.URL, "k", "claude-x",
		[]chatMessage{{Role: "user", Content: "hi"}})
	if !errors.Is(err, errProviderNotOK) {
		t.Fatalf("err = %v, want errProviderNotOK", err)
	}
	if content != "partial" {
		t.Errorf("content = %q, want %q (the partial delta must still have been emitted)", content, "partial")
	}
	if requestCount != 1 {
		t.Errorf("requestCount = %d, want 1 (must not retry against /v1 after a partial stream)", requestCount)
	}
}

// buildAnalysisPrompt must cap findings at maxFindingsInPrompt, truncate
// oversized fields, and report accurate sent/total counts for the UI's
// "analysis covered N of M findings" hint.
func TestBuildAnalysisPromptTruncation(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	const nFindings = maxFindingsInPrompt + 15
	var findings []string
	longDesc := strings.Repeat("x", maxFieldLen+200)
	for i := 0; i < nFindings; i++ {
		// Each finding gets a distinct component so (component, rule) pairs
		// never repeat -- nothing should cluster/collapse here, this test is
		// specifically about the plain volume-truncation and long-field-
		// truncation behavior, not the clustering behavior (see the
		// TestClusterAndSelectFindings* tests for that).
		findings = append(findings, fmt.Sprintf(
			`{"id":"f%d","title":"t%d","vuln_class":"x","severity":"high","confidence":0.8,"component":"c%d","rule":"r","description":"%s"}`,
			i, i, i, longDesc))
	}
	reportJSON := []byte(fmt.Sprintf(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [],
		"findings": [%s]
	}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	messages, promptMeta, err := buildAnalysisPrompt(db, "job-1", "en")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 || messages[0].Role != "system" || messages[1].Role != "user" {
		t.Fatalf("messages = %+v", messages)
	}

	var meta struct {
		FindingCountSent  int  `json:"finding_count_sent"`
		FindingCountTotal int  `json:"finding_count_total"`
		Truncated         bool `json:"truncated"`
	}
	if err := json.Unmarshal(promptMeta, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.FindingCountTotal != nFindings {
		t.Errorf("FindingCountTotal = %d, want %d", meta.FindingCountTotal, nFindings)
	}
	if meta.FindingCountSent != maxFindingsInPrompt {
		t.Errorf("FindingCountSent = %d, want %d", meta.FindingCountSent, maxFindingsInPrompt)
	}
	if !meta.Truncated {
		t.Error("Truncated = false, want true")
	}
	if !strings.Contains(messages[1].Content, "further findings not represented") {
		t.Error("user message must mention the rolled-up remaining findings count")
	}
	if strings.Contains(messages[1].Content, longDesc) {
		t.Error("an oversized description field must be truncated, not embedded whole")
	}
	if !strings.Contains(messages[1].Content, "...[truncated]") {
		t.Error("truncated fields must carry a visible truncation marker")
	}
}

// Regression: this is the exact real-world failure mode that motivated the
// whole clustering/fairness rewrite -- cve-bin-tool matching one version
// string against one component and expanding it into dozens of individual
// CVE findings, which under plain severity sorting consumed nearly the
// entire finding budget and crowded out every other vulnerability class.
// A large group sharing (component, rule) must collapse into one summary
// entry instead.
func TestClusterAndSelectFindingsCollapsesLargeClusters(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	const n = 50
	var findings []string
	for i := 0; i < n; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"f%d","title":"t%d","vuln_class":"known_cve","severity":"critical","confidence":0.7,"component":"tcpdump@4.5.1","rule":"cve-bin-tool","cve_ids":["CVE-2017-%d"]}`,
			i, i, 13000+i))
	}
	reportJSON := []byte(fmt.Sprintf(`{"target":"/fw","tool_version":"test","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	items, total, represented, err := clusterAndSelectFindings(db, "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if total != n {
		t.Errorf("total = %d, want %d", total, n)
	}
	if len(items) != 1 {
		t.Fatalf("items = %+v, want exactly 1 collapsed entry for the whole cluster", items)
	}
	if !items[0].Collapsed || items[0].CollapsedCount != n {
		t.Errorf("items[0] = %+v, want Collapsed=true CollapsedCount=%d", items[0], n)
	}
	if len(items[0].CollapsedCVEs) != n {
		t.Errorf("CollapsedCVEs has %d entries, want %d (deduplicated union of the whole group)", len(items[0].CollapsedCVEs), n)
	}
	if represented != n {
		t.Errorf("findingsRepresented = %d, want %d (the collapsed entry still represents every original finding)", represented, n)
	}
}

// Regression: collapsing a cluster must not throw away its concrete
// evidence. For a CVE flood there is none to lose, but for a cluster of
// taint findings the taint path is precisely what the system prompt asks
// the model to weigh when separating real issues from pattern-matcher
// noise -- dropping it made the collapsed entry unjudgeable.
func TestCollapseClusterKeepsEvidenceAndPseudocode(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []string
	for i := 0; i < 10; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"t%d","title":"t","vuln_class":"command_injection","severity":"high","confidence":0.5,
			  "component":"/usr/sbin/httpd","rule":"taint","description":"tainted input reaches system()",
			  "pseudocode":"sink_%d(): system(buf);","evidence":[{"binary":"/usr/sbin/httpd","function":"handler_%d","taint_path":["recv","strcpy","system"]}]}`,
			i, i, i))
	}
	reportJSON := []byte(fmt.Sprintf(`{"target":"/fw","tool_version":"test","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	items, _, _, err := clusterAndSelectFindings(db, "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || !items[0].Collapsed {
		t.Fatalf("expected a single collapsed entry, got %+v", items)
	}
	if len(items[0].Evidence) == 0 {
		t.Error("collapsed cluster must carry the representative's evidence (the taint path)")
	}
	if items[0].Pseudocode == "" {
		t.Error("collapsed cluster must carry the representative's pseudocode")
	}

	// ...and it must actually reach the rendered prompt, not just the struct.
	messages, _, err := buildAnalysisPrompt(db, "job-1", "en")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(messages[1].Content, "taint_path") {
		t.Error("rendered prompt must include the collapsed cluster's evidence")
	}
	if !strings.Contains(messages[1].Content, "representative pseudocode") {
		t.Error("rendered prompt must include the collapsed cluster's pseudocode")
	}
}

// The entry cap alone doesn't bound prompt size -- each entry can carry
// several KB of description/pseudocode/evidence. The character budget must
// stop rendering before the prompt balloons, and must report what it
// dropped rather than silently omitting it.
func TestBuildAnalysisPromptRespectsCharBudget(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("y", maxFieldLen)
	var findings []string
	// Distinct component per finding so nothing collapses; each entry then
	// carries description+pseudocode+evidence at full length.
	for i := 0; i < maxFindingsInPrompt; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"f%d","title":"t","vuln_class":"c%d","severity":"high","confidence":0.5,"component":"comp%d","rule":"r",
			  "description":"%s","pseudocode":"%s","evidence":[{"binary":"b","snippet":"%s"}]}`,
			i, i%8, i, big, big, big))
	}
	reportJSON := []byte(fmt.Sprintf(`{"target":"/fw","tool_version":"test","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	messages, promptMeta, err := buildAnalysisPrompt(db, "job-1", "en")
	if err != nil {
		t.Fatal(err)
	}
	userLen := len(messages[1].Content)
	// Allow one entry's overshoot plus the trailing rollup lines.
	if userLen > maxPromptFindingsChars+4*maxFieldLen {
		t.Errorf("user message = %d chars, must stay near the %d budget", userLen, maxPromptFindingsChars)
	}

	var meta struct {
		EntriesShown int  `json:"entries_shown"`
		BudgetCapped bool `json:"budget_capped"`
		PromptChars  int  `json:"prompt_chars"`
	}
	if err := json.Unmarshal(promptMeta, &meta); err != nil {
		t.Fatal(err)
	}
	if !meta.BudgetCapped {
		t.Error("budget_capped must be reported when entries were dropped for size")
	}
	if meta.EntriesShown >= maxFindingsInPrompt {
		t.Errorf("entries_shown = %d, expected fewer than %d once the budget bit", meta.EntriesShown, maxFindingsInPrompt)
	}
	if meta.EntriesShown == 0 {
		t.Error("at least one entry must always be rendered")
	}
	if meta.PromptChars <= 0 {
		t.Error("prompt_chars must be reported for cost visibility")
	}
	if !strings.Contains(messages[1].Content, "prompt size budget") {
		t.Error("the prompt must say that entries were omitted for size, not drop them silently")
	}
}

// A normal-sized scan must be completely unaffected by the budget.
func TestBuildAnalysisPromptBudgetDoesNotBiteOnTypicalScan(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []string
	for i := 0; i < 20; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"f%d","title":"t","vuln_class":"c%d","severity":"high","confidence":0.5,"component":"comp%d","rule":"r","description":"a short description"}`,
			i, i%4, i))
	}
	reportJSON := []byte(fmt.Sprintf(`{"target":"/fw","tool_version":"test","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}
	_, promptMeta, err := buildAnalysisPrompt(db, "job-1", "en")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		EntriesShown int  `json:"entries_shown"`
		BudgetCapped bool `json:"budget_capped"`
	}
	json.Unmarshal(promptMeta, &meta)
	if meta.BudgetCapped {
		t.Error("a small scan must not hit the size budget")
	}
	if meta.EntriesShown != 20 {
		t.Errorf("entries_shown = %d, want all 20", meta.EntriesShown)
	}
}

// A vuln_class with only a handful of findings must not be crowded out by
// a much larger class, even when the larger class's findings individually
// outrank it on severity -- this is the actual fairness property a human
// reviewer provides for free (skipping past a CVE flood to look at the
// interesting stuff) that pure severity sorting did not.
func TestClusterAndSelectFindingsPerClassFairness(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []string
	for i := 0; i < 100; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"ci%d","title":"t","vuln_class":"command_injection","severity":"high","confidence":0.5,"component":"bin%d","rule":"taint"}`, i, i))
	}
	for i := 0; i < 5; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"hc%d","title":"t","vuln_class":"hardcoded_credential","severity":"medium","confidence":0.6,"component":"cred%d","rule":"secrets"}`, i, i))
	}
	reportJSON := []byte(fmt.Sprintf(`{"target":"/fw","tool_version":"test","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	items, _, _, err := clusterAndSelectFindings(db, "job-1")
	if err != nil {
		t.Fatal(err)
	}
	hcCount := 0
	for _, it := range items {
		if it.VulnClass == "hardcoded_credential" {
			hcCount++
		}
	}
	if hcCount != 5 {
		t.Errorf("hardcoded_credential entries in the prompt = %d, want all 5 present despite command_injection's higher severity and much larger volume", hcCount)
	}
	if len(items) > maxFindingsInPrompt {
		t.Errorf("len(items) = %d, must not exceed maxFindingsInPrompt (%d)", len(items), maxFindingsInPrompt)
	}
}

// Regression for a bug caught during review: the first implementation of
// the fairness pass greedily filled each class up to perVulnClassCap in
// global-severity order, then truncated the combined result back down to
// maxFindingsInPrompt when classes*cap exceeded the budget -- which
// silently re-introduced the "whichever class ranks highest by raw
// severity wins" bias for any scan with enough distinct vulnerability
// classes, since the truncation step cut low-severity classes' items
// first regardless of how the per-class caps had been intended to work.
// Round-robin allocation must instead give every class an equal number of
// rounds' worth of representation before any class gets extra.
func TestClusterAndSelectFindingsRoundRobinIsFairAcrossManyClasses(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	const classes = 10
	const perClass = 20
	var findings []string
	for c := 0; c < classes; c++ {
		// Half the classes are severity=critical, half severity=low -- if
		// selection were still biased by raw severity, the low classes
		// would get starved relative to the critical ones.
		sev := "critical"
		if c >= classes/2 {
			sev = "low"
		}
		for i := 0; i < perClass; i++ {
			findings = append(findings, fmt.Sprintf(
				`{"id":"c%d-%d","title":"t","vuln_class":"class%d","severity":"%s","confidence":0.5,"component":"comp%d-%d","rule":"r"}`,
				c, i, c, sev, c, i))
		}
	}
	reportJSON := []byte(fmt.Sprintf(`{"target":"/fw","tool_version":"test","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ",")))
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	items, _, _, err := clusterAndSelectFindings(db, "job-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != maxFindingsInPrompt {
		t.Fatalf("len(items) = %d, want exactly %d (evenly divides across %d classes)", len(items), maxFindingsInPrompt, classes)
	}
	counts := map[string]int{}
	for _, it := range items {
		counts[it.VulnClass]++
	}
	wantPerClass := maxFindingsInPrompt / classes
	for c := 0; c < classes; c++ {
		class := fmt.Sprintf("class%d", c)
		if counts[class] != wantPerClass {
			t.Errorf("counts[%s] = %d, want %d (round-robin must split evenly regardless of severity)", class, counts[class], wantPerClass)
		}
	}
}

func TestBuildAnalysisPromptEmptyJob(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	messages, promptMeta, err := buildAnalysisPrompt(db, "job-never-ingested", "en")
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Truncated bool `json:"truncated"`
	}
	json.Unmarshal(promptMeta, &meta)
	if meta.Truncated {
		t.Error("an empty/never-ingested job must not report truncation")
	}
	if len(messages) != 2 {
		t.Fatalf("messages = %+v", messages)
	}
}

// The requested output language must land in the system prompt as an
// explicit instruction, and be reported back in prompt_meta so the UI (or
// a later audit) can see what was actually requested. "zh" is the only
// recognized non-default value; anything else -- including empty, for
// older frontend builds that never send it -- falls back to English, the
// previous, only behavior.
func TestBuildAnalysisPromptLanguageDirective(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := db.Ingest("job-1", []byte(`{"target":"/fw","tool_version":"t","generated_at":"now",
		"binaries":[],"scripts":[],"components":[],"findings":[]}`), nil); err != nil {
		t.Fatal(err)
	}

	messages, promptMeta, err := buildAnalysisPrompt(db, "job-1", "zh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(messages[0].Content, "Simplified Chinese") {
		t.Errorf("system prompt should instruct Chinese output, got: %s", messages[0].Content)
	}
	var meta struct {
		Lang string `json:"lang"`
	}
	json.Unmarshal(promptMeta, &meta)
	if meta.Lang != "zh" {
		t.Errorf("prompt_meta lang = %q, want zh", meta.Lang)
	}

	for _, lang := range []string{"en", "", "fr", "ZH"} {
		messages, promptMeta, err := buildAnalysisPrompt(db, "job-1", lang)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(messages[0].Content, "Simplified Chinese") {
			t.Errorf("lang=%q must default to English, got Chinese instruction in: %s", lang, messages[0].Content)
		}
		var meta struct {
			Lang string `json:"lang"`
		}
		json.Unmarshal(promptMeta, &meta)
		if meta.Lang != "en" {
			t.Errorf("lang=%q: prompt_meta lang = %q, want en", lang, meta.Lang)
		}
	}
}

// newTestAPI builds a minimal API wired to a real (temp-file) Store and
// ReportDB with auth disabled, for handler-level tests that don't need the
// Worker/TriageStore (the AI handlers never touch either).
func newTestAPI(t *testing.T) (*API, *Store, *ReportDB) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "jobs"), "test")
	if err != nil {
		t.Fatal(err)
	}
	reportDB, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	aiKey, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(store, nil, nil, reportDB, filepath.Join(dir, "uploads"), dir, false, nil, aiKey)
	return api, store, reportDB
}
