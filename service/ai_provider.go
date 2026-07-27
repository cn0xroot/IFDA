package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

var (
	errNoModels      = errors.New("provider returned no models")
	errEmptyChoices  = errors.New("provider returned no choices")
	errProviderNotOK = errors.New("provider returned a non-2xx response")
	errNonJSONBody   = errors.New("provider returned a non-JSON response")
	// errStreamInterrupted is returned when the SSE stream ends without any
	// terminal marker -- no [DONE] and no finish_reason (OpenAI), or no
	// message_stop and no stop_reason (Anthropic). A well-formed stream always
	// signals how it ended; reaching EOF with none of those means the provider
	// (often a third-party gateway) cut the generation mid-output. bufio.Scanner
	// reports EOF as a clean end (Err()==nil), so without this check a truncated
	// stream would be passed off as a complete answer.
	errStreamInterrupted = errors.New("provider ended the stream without a completion signal (the generation was cut off mid-output -- often a gateway or upstream timeout dropping a long response)")
)

// anthropicVersion is Anthropic's required API-version header value. Pinned
// (not "latest") so a future Anthropic API revision can't silently change
// this integration's request/response shape out from under it.
const anthropicVersion = "2023-06-01"

// aiMaxOutputTokens is the requested max output length for one analysis
// call. Anthropic's Messages API requires this explicitly (no server-side
// default); OpenAI-compatible gateways don't require it, but plenty default
// to a low cap (a few hundred tokens) when it's omitted, so it's set on
// both dialects to avoid a symmetric truncation bug. A full findings-triage
// narrative over the current 60-finding prompt cap routinely runs several
// thousand tokens -- the previous 4096 cap was observed truncating
// responses mid-sentence, and on models that spend part of their budget on
// extended thinking before any answer text, could exhaust the entire
// budget before producing any visible content at all (surfacing as "AI
// provider returned an empty response" with no other symptom).
const aiMaxOutputTokens = 8192

// toolCall is one model-requested tool invocation. Args is the raw JSON
// object string exactly as the model emitted it (assembled from streamed
// fragments), decoded only when the tool actually runs -- a model can emit
// malformed JSON, and that should surface as a tool error fed back to it
// rather than breaking the stream.
type toolCall struct {
	ID   string
	Name string
	Args string
}

// chatMessage is the dialect-neutral conversation element. OpenAI and
// Anthropic express tool calls and results very differently (see
// openaiMessages/anthropicMessages), so this stays neutral and each
// dialect serializes it at request-build time.
//
// The zero values of the tool fields reproduce the original plain
// role+content behavior exactly, so the non-tool path is unchanged.
type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
	// ToolCalls is set on an assistant turn that requested tools.
	ToolCalls []toolCall `json:"-"`
	// ToolCallID identifies which call a Role=="tool" result answers.
	ToolCallID string `json:"-"`
}

// openaiMessages renders the conversation in the OpenAI dialect: an
// assistant turn carries a `tool_calls` array, and each result is its own
// message with role "tool" plus the `tool_call_id` it answers.
func openaiMessages(messages []chatMessage) []map[string]any {
	out := make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		switch {
		case m.Role == "tool":
			out = append(out, map[string]any{
				"role": "tool", "tool_call_id": m.ToolCallID, "content": m.Content,
			})
		case len(m.ToolCalls) > 0:
			calls := make([]map[string]any, 0, len(m.ToolCalls))
			for _, c := range m.ToolCalls {
				calls = append(calls, map[string]any{
					"id": c.ID, "type": "function",
					"function": map[string]any{"name": c.Name, "arguments": c.Args},
				})
			}
			msg := map[string]any{"role": m.Role, "tool_calls": calls}
			// OpenAI accepts (and some gateways require) content to be
			// present even when it's empty alongside tool_calls.
			msg["content"] = m.Content
			out = append(out, msg)
		default:
			out = append(out, map[string]any{"role": m.Role, "content": m.Content})
		}
	}
	return out
}

// anthropicMessages renders the conversation in Anthropic's dialect: the
// system prompt is hoisted to a top-level field (not a message), an
// assistant turn's content is an array of blocks that may mix text and
// `tool_use`, and results come back as `tool_result` blocks inside a user
// message.
func anthropicMessages(messages []chatMessage) (system string, msgs []map[string]any) {
	msgs = make([]map[string]any, 0, len(messages))
	for _, m := range messages {
		switch {
		case m.Role == "system":
			system = m.Content
		case m.Role == "tool":
			// Consecutive tool results belong in one user message; merge
			// into the previous one when it is already a tool_result turn.
			block := map[string]any{
				"type": "tool_result", "tool_use_id": m.ToolCallID, "content": m.Content,
			}
			if n := len(msgs); n > 0 && isAnthropicToolResultTurn(msgs[n-1]) {
				blocks := msgs[n-1]["content"].([]map[string]any)
				msgs[n-1]["content"] = append(blocks, block)
				continue
			}
			msgs = append(msgs, map[string]any{"role": "user", "content": []map[string]any{block}})
		case len(m.ToolCalls) > 0:
			blocks := make([]map[string]any, 0, len(m.ToolCalls)+1)
			if m.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			for _, c := range m.ToolCalls {
				input := map[string]any{}
				if c.Args != "" {
					// A malformed arguments blob must not corrupt the
					// replayed history; an empty object is the safe stand-in.
					if json.Unmarshal([]byte(c.Args), &input) != nil {
						input = map[string]any{}
					}
				}
				blocks = append(blocks, map[string]any{
					"type": "tool_use", "id": c.ID, "name": c.Name, "input": input,
				})
			}
			msgs = append(msgs, map[string]any{"role": m.Role, "content": blocks})
		default:
			msgs = append(msgs, map[string]any{"role": m.Role, "content": m.Content})
		}
	}
	return system, msgs
}

func isAnthropicToolResultTurn(msg map[string]any) bool {
	if msg["role"] != "user" {
		return false
	}
	blocks, ok := msg["content"].([]map[string]any)
	if !ok || len(blocks) == 0 {
		return false
	}
	return blocks[0]["type"] == "tool_result"
}

// normalizeHost trims a trailing slash so "{host}/models" never produces a
// doubled "//models".
func normalizeHost(host string) string {
	return strings.TrimRight(strings.TrimSpace(host), "/")
}

// decodeJSONResponse unmarshals body into v, but first checks whether the
// provider actually returned JSON at all. A wrong Host URL (missing a
// version path segment, a plain domain that only serves a web page, a
// misconfigured reverse proxy) commonly comes back as an HTML error page
// instead of a non-2xx JSON error -- json.Unmarshal's own error for that
// ("invalid character '<' looking for beginning of value") is technically
// correct but useless to a user configuring a provider, so surface the
// actual problem instead.
func decodeJSONResponse(body []byte, v any) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '<' {
		return fmt.Errorf("%w (looks like HTML) -- check the Host URL is correct (e.g. it may be missing an API version path like /v1): %s",
			errNonJSONBody, truncate(string(trimmed), 200))
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: %s: %s", errNonJSONBody, err.Error(), truncate(string(trimmed), 200))
	}
	return nil
}

// candidateBases returns the base URL(s) to try in order. Most gateways
// (and OpenAI/Anthropic themselves) expect the API mounted under /v1, but
// it's an easy thing for a user to leave off when they paste in a bare
// domain -- and a bare domain commonly serves that gateway's own web UI at
// every unmatched path (an SPA catch-all), which looks exactly like a
// "wrong Host" HTML response. If host doesn't already look versioned, also
// try {host}/v1 as a fallback so that common mistake self-heals instead of
// requiring the user to notice and fix it.
func candidateBases(host string) []string {
	h := normalizeHost(host)
	bases := []string{h}
	if !strings.HasSuffix(h, "/v1") && !strings.Contains(h, "/v1/") {
		bases = append(bases, h+"/v1")
	}
	return bases
}

// looksLikeWrongBasePath reports whether err is the signature of "this URL
// doesn't host the API" (an HTML response, or a plain 404) rather than a
// real problem with the request itself (bad key, rate limit, timeout) --
// only errors like this are worth retrying against the /v1 fallback base;
// retrying an auth failure at a different path wouldn't fix it and would
// just double the latency of a call that was always going to fail.
func looksLikeWrongBasePath(err error) bool {
	if errors.Is(err, errNonJSONBody) {
		return true
	}
	if errors.Is(err, errProviderNotOK) && strings.Contains(err.Error(), "HTTP 404") {
		return true
	}
	return false
}

// fetchModels calls GET {base}/models across candidateBases(host) in order,
// stopping at the first success or the first error that isn't itself a
// "wrong base path" signal. Returns the model ids advertised, for the "pick
// from a dropdown, don't hand-type it" requirement. kind selects the auth
// header style: OpenAI-compatible gateways use a Bearer token; Anthropic
// uses its own x-api-key + anthropic-version pair. The response shape
// (`{"data":[{"id":...}]}`) happens to match on both.
func fetchModels(ctx context.Context, client *http.Client, kind, host, apiKey string) ([]string, error) {
	bases := candidateBases(host)
	var lastErr error
	for i, base := range bases {
		models, err := fetchModelsAt(ctx, client, kind, base, apiKey)
		if err == nil {
			return models, nil
		}
		lastErr = err
		if i == len(bases)-1 || !looksLikeWrongBasePath(err) {
			break
		}
	}
	return nil, lastErr
}

// transientRetryDelays are the backoff delays between retries of a
// transient provider response (HTTP 429 rate-limited, or a 5xx server
// error like "503 Service temporarily unavailable"). Gateway hiccups and
// momentary overload are common and often gone within a few seconds, so
// retrying beats immediately surfacing a scary error for something that
// would likely have worked a moment later. Not retried: network-level
// errors (timeout, connection refused) and non-transient HTTP statuses
// (4xx other than 429) -- those won't be fixed by trying again.
var transientRetryDelays = []time.Duration{500 * time.Millisecond, 1500 * time.Millisecond, 3 * time.Second}

func isTransientStatus(code int) bool {
	return code == http.StatusTooManyRequests || (code >= 500 && code < 600)
}

// doProviderRequest performs one HTTP call and retries it while the
// response is transient (see isTransientStatus) and attempts remain,
// sleeping with backoff between tries. newReq is called fresh on every
// attempt (rather than reusing one *http.Request) since a request with a
// body can't be replayed once its reader has been consumed. attempts
// reports how many tries were actually made, so a final error can say so.
func doProviderRequest(ctx context.Context, client *http.Client, readLimit int64, newReq func() (*http.Request, error)) (status int, body []byte, attempts int, err error) {
	for attempt := 1; ; attempt++ {
		attempts = attempt
		req, err := newReq()
		if err != nil {
			return 0, nil, attempts, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, attempts, err
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, readLimit))
		resp.Body.Close()
		status = resp.StatusCode
		if !isTransientStatus(status) || attempt > len(transientRetryDelays) {
			return status, body, attempts, nil
		}
		select {
		case <-ctx.Done():
			return status, body, attempts, nil
		case <-time.After(transientRetryDelays[attempt-1]):
		}
	}
}

// retriedSuffix renders "(retried N times over ~Ts)" for an error message
// when doProviderRequest actually retried, so a persistent 503 reads as
// "we tried, it's really down" rather than looking like a first-attempt
// failure that was never given a chance to recover.
func retriedSuffix(attempts int) string {
	if attempts <= 1 {
		return ""
	}
	var total time.Duration
	for _, d := range transientRetryDelays[:attempts-1] {
		total += d
	}
	return fmt.Sprintf(" (retried %d times over ~%.0fs)", attempts-1, total.Seconds())
}

func fetchModelsAt(ctx context.Context, client *http.Client, kind, base, apiKey string) ([]string, error) {
	url := normalizeHost(base) + "/models"
	status, body, attempts, err := doProviderRequest(ctx, client, 1<<20, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		setProviderAuthHeaders(req, kind, apiKey)
		req.Header.Set("Accept", "application/json")
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%w: HTTP %d: %s%s", errProviderNotOK, status, truncate(string(body), 300), retriedSuffix(attempts))
	}

	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := decodeJSONResponse(body, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Data) == 0 {
		return nil, errNoModels
	}
	models := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		if m.ID != "" {
			models = append(models, m.ID)
		}
	}
	if len(models) == 0 {
		return nil, errNoModels
	}
	return models, nil
}

// setProviderAuthHeaders applies the auth scheme for kind ("openai", the
// default, or "anthropic").
func setProviderAuthHeaders(req *http.Request, kind, apiKey string) {
	if kind == "anthropic" {
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", anthropicVersion)
		return
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
}

// dialProviderStream opens a streaming provider connection: 2xx responses
// are returned with the body still open for the caller to scan incrementally
// (caller must close it); non-2xx responses are retried under the same
// transient-status/backoff policy as doProviderRequest before being turned
// into an errProviderNotOK. This retry/fallback machinery only ever runs
// before any content has reached the caller -- once a caller starts reading
// a 2xx body, there is no retrying a partially-consumed stream.
func dialProviderStream(ctx context.Context, client *http.Client, newReq func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 1; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<10))
		resp.Body.Close()
		if !isTransientStatus(resp.StatusCode) || attempt > len(transientRetryDelays) {
			return nil, fmt.Errorf("%w: HTTP %d: %s%s", errProviderNotOK, resp.StatusCode, truncate(string(body), 300), retriedSuffix(attempt))
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: HTTP %d: %s%s", errProviderNotOK, resp.StatusCode, truncate(string(body), 300), retriedSuffix(attempt))
		case <-time.After(transientRetryDelays[attempt-1]):
		}
	}
}

// streamChatCompletion runs the analysis call against the given provider
// kind, dispatching to the right wire format and streaming the assistant's
// response incrementally via onDelta -- OpenAI's chat/completions and
// Anthropic's Messages API use similar-in-spirit but incompatible SSE
// dialects (event framing, field names, whether "system" is a message or a
// top-level field). Tries candidateBases(host) in order, same /v1-fallback
// reasoning as fetchModels, guarded by emittedAny: once a given base has
// streamed even one delta to the caller, that attempt is committed to --
// falling back to another base after a partial stream would either
// duplicate or reset content already shown to the user.
// streamRequest bundles one provider call's parameters. A struct rather
// than a parameter list because tool support pushed this past the point
// where positional arguments stay readable.
type streamRequest struct {
	Kind      string // "openai" (default) | "anthropic"
	Host      string
	APIKey    string
	Model     string
	MaxTokens int
	Messages  []chatMessage
	// Tools, when non-empty, are offered to the model. Leaving it nil
	// reproduces the original tool-free request shape byte for byte, which
	// is what the no-tools fallback path relies on.
	Tools []aiToolDefinition
}

// streamResult reports what a turn produced besides streamed text.
type streamResult struct {
	// ToolCalls is non-empty when the model asked to invoke tools instead
	// of (or before) finishing its answer.
	ToolCalls  []toolCall
	StopReason string
}

// toolCallAccumulator assembles one tool call from streamed fragments;
// both dialects deliver the arguments JSON in pieces.
type toolCallAccumulator struct {
	ID   string
	Name string
	Args strings.Builder
}

// finalizeToolCalls flattens the per-index accumulators into calls ordered
// by block/choice index, which is the order the model intended.
func finalizeToolCalls(accum map[int]*toolCallAccumulator) []toolCall {
	if len(accum) == 0 {
		return nil
	}
	idxs := make([]int, 0, len(accum))
	for i := range accum {
		idxs = append(idxs, i)
	}
	sort.Ints(idxs)
	calls := make([]toolCall, 0, len(idxs))
	for _, i := range idxs {
		a := accum[i]
		if a.Name == "" {
			continue // an index that never named a tool isn't callable
		}
		calls = append(calls, toolCall{ID: a.ID, Name: a.Name, Args: a.Args.String()})
	}
	return calls
}

func streamChatCompletion(ctx context.Context, client *http.Client, sreq streamRequest, onDelta func(string)) (streamResult, error) {
	bases := candidateBases(sreq.Host)
	var lastErr error
	for i, base := range bases {
		emittedAny := false
		wrapped := func(s string) { emittedAny = true; onDelta(s) }
		var res streamResult
		var err error
		if sreq.Kind == "anthropic" {
			res, err = anthropicStreamChatCompletion(ctx, client, base, sreq, wrapped)
		} else {
			res, err = openaiStreamChatCompletion(ctx, client, base, sreq, wrapped)
		}
		if err == nil {
			return res, nil
		}
		lastErr = err
		if emittedAny || i == len(bases)-1 || !looksLikeWrongBasePath(err) {
			break
		}
	}
	return streamResult{}, lastErr
}

// sseScanner returns a bufio.Scanner over an SSE body with its line-buffer
// limit raised well past the default 64KB -- a single "data:" line can
// carry a large JSON payload (long pseudocode/description fields echoed
// back, etc.) that would otherwise make Scan silently truncate or error.
func sseScanner(r io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	return scanner
}

// checkNotHTML must be called with the first non-blank line of a would-be
// SSE stream. dialProviderStream only checks the status code -- a 200
// response whose body is actually an HTML page (the same "wrong Host URL"
// symptom decodeJSONResponse catches for the non-streaming path, e.g. a
// bare gateway domain serving its own web UI) would otherwise silently
// scan as "an SSE stream with no data lines in it" and surface as the far
// less actionable errEmptyChoices. Real SSE content never starts with '<',
// so this is a safe, cheap heuristic -- and since it wraps errNonJSONBody,
// looksLikeWrongBasePath still triggers the /v1 fallback for it same as
// non-streaming.
func checkNotHTML(firstLine string) error {
	trimmed := strings.TrimSpace(firstLine)
	if strings.HasPrefix(trimmed, "<") {
		return fmt.Errorf("%w (looks like HTML) -- check the Host URL is correct (e.g. it may be missing an API version path like /v1): %s",
			errNonJSONBody, truncate(trimmed, 200))
	}
	return nil
}

// truncationNotice is appended (as one final onDelta call) when the
// provider reports it stopped because it hit the output token limit, not
// because it finished -- otherwise a cut-off-mid-sentence response looks
// indistinguishable from a genuinely complete (if abrupt) answer.
const truncationNotice = "\n\n[Response truncated: the AI provider stopped at its maximum output length before finishing. The analysis above is incomplete.]"

// openaiStreamChatCompletion calls an OpenAI-compatible POST
// {base}/chat/completions with "stream": true and relays each
// choices[0].delta.content fragment to onDelta as it arrives. Malformed or
// unrecognized lines (keep-alives, comments) are skipped rather than
// treated as fatal -- normal behavior for an SSE consumer.
func openaiStreamChatCompletion(ctx context.Context, client *http.Client, base string, sreq streamRequest, onDelta func(string)) (streamResult, error) {
	url := normalizeHost(base) + "/chat/completions"
	body := map[string]any{
		"model":      sreq.Model,
		"messages":   openaiMessages(sreq.Messages),
		"stream":     true,
		"max_tokens": sreq.MaxTokens,
	}
	if len(sreq.Tools) > 0 {
		body["tools"] = openaiToolSpecs(sreq.Tools)
		body["tool_choice"] = "auto"
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return streamResult{}, err
	}
	resp, err := dialProviderStream(ctx, client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+sreq.APIKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		return req, nil
	})
	if err != nil {
		return streamResult{}, err
	}
	defer resp.Body.Close()

	scanner := sseScanner(resp.Body)
	gotAny := false
	sawDone := false
	checkedFirstLine := false
	var finishReason string
	// tool_calls arrive spread across chunks: the id and name usually land
	// in the first chunk for a given index, while `arguments` streams in as
	// string fragments that must be concatenated per index.
	accum := map[int]*toolCallAccumulator{}
	for scanner.Scan() {
		line := scanner.Text()
		if !checkedFirstLine && strings.TrimSpace(line) != "" {
			checkedFirstLine = true
			if err := checkNotHTML(line); err != nil {
				return streamResult{}, err
			}
		}
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" {
			continue
		}
		if payload == "[DONE]" {
			sawDone = true
			break
		}
		var chunk struct {
			Choices []struct {
				Delta struct {
					Content   string `json:"content"`
					ToolCalls []struct {
						Index    int    `json:"index"`
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(payload), &chunk) != nil {
			continue
		}
		for _, c := range chunk.Choices {
			if c.Delta.Content != "" {
				gotAny = true
				onDelta(c.Delta.Content)
			}
			for _, tc := range c.Delta.ToolCalls {
				a := accum[tc.Index]
				if a == nil {
					a = &toolCallAccumulator{}
					accum[tc.Index] = a
				}
				if tc.ID != "" {
					a.ID = tc.ID
				}
				if tc.Function.Name != "" {
					a.Name = tc.Function.Name
				}
				a.Args.WriteString(tc.Function.Arguments)
			}
			if c.FinishReason != nil && *c.FinishReason != "" {
				finishReason = *c.FinishReason
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return streamResult{}, err
	}

	calls := finalizeToolCalls(accum)
	// A turn that only requested tools legitimately produces no text, so
	// "no content" is only an error when no tool calls came either.
	if !gotAny && len(calls) == 0 {
		if finishReason != "" {
			return streamResult{}, fmt.Errorf("%w (provider finish_reason: %s)", errEmptyChoices, finishReason)
		}
		return streamResult{}, errEmptyChoices
	}
	// A compliant stream ends with a finish_reason on the last chunk and/or
	// the [DONE] sentinel. If it produced output but signalled neither, the
	// provider cut it off mid-generation -- report that rather than storing a
	// mid-sentence fragment as a finished analysis. (Gateways that omit
	// finish_reason but still send [DONE] are treated as complete, so this
	// does not misfire on merely terse-but-terminated streams.)
	if finishReason == "" && !sawDone {
		return streamResult{}, errStreamInterrupted
	}
	if finishReason == "length" {
		onDelta(truncationNotice)
	}
	return streamResult{ToolCalls: calls, StopReason: finishReason}, nil
}

// anthropicStreamChatCompletion calls Anthropic's POST {base}/messages with
// "stream": true and relays each content_block_delta's text to onDelta.
// Unlike the OpenAI dialect: auth is x-api-key + anthropic-version (no
// Authorization header), "system" is a top-level field, max_tokens is
// mandatory, and events are framed as "event: <type>" + "data: {...}" pairs
// rather than bare "data:" lines -- most event types (message_start,
// content_block_start, ping, message_stop) carry nothing onDelta cares
// about and are ignored; "message_delta" carries stop_reason (used to
// detect/flag truncation, see truncationNotice), and an explicit
// "event: error" is a provider-reported failure surfaced rather than
// swallowed. Note this does not handle extended-thinking content blocks
// (delta.type "thinking_delta") as visible text -- if a model spends its
// entire max_tokens budget on thinking before emitting any "text_delta",
// the run correctly reports errEmptyChoices with the captured stop_reason
// rather than silently returning nothing.
func anthropicStreamChatCompletion(ctx context.Context, client *http.Client, base string, sreq streamRequest, onDelta func(string)) (streamResult, error) {
	url := normalizeHost(base) + "/messages"
	system, msgs := anthropicMessages(sreq.Messages)
	body := map[string]any{
		"model":      sreq.Model,
		"max_tokens": sreq.MaxTokens,
		"system":     system,
		"messages":   msgs,
		"stream":     true,
	}
	if len(sreq.Tools) > 0 {
		body["tools"] = anthropicToolSpecs(sreq.Tools)
	}
	reqBody, err := json.Marshal(body)
	if err != nil {
		return streamResult{}, err
	}
	resp, err := dialProviderStream(ctx, client, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("x-api-key", sreq.APIKey)
		req.Header.Set("anthropic-version", anthropicVersion)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		return req, nil
	})
	if err != nil {
		return streamResult{}, err
	}
	defer resp.Body.Close()

	scanner := sseScanner(resp.Body)
	gotAny := false
	sawMessageStop := false
	checkedFirstLine := false
	var currentEvent, stopReason string
	// Anthropic frames tool calls as content blocks: a content_block_start
	// of type "tool_use" carries the id and name, then input_json_delta
	// fragments for that same block index carry the arguments JSON. Text
	// blocks share the same index space, so only indices seen starting as
	// tool_use are treated as tool calls.
	accum := map[int]*toolCallAccumulator{}
	for scanner.Scan() {
		line := scanner.Text()
		if !checkedFirstLine && strings.TrimSpace(line) != "" {
			checkedFirstLine = true
			if err := checkNotHTML(line); err != nil {
				return streamResult{}, err
			}
		}
		switch {
		case line == "":
			currentEvent = "" // blank line ends an SSE event block
		case strings.HasPrefix(line, "event:"):
			currentEvent = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			if currentEvent == "message_stop" {
				sawMessageStop = true // the stream's terminal event; its absence at EOF means a cut
			}
		case strings.HasPrefix(line, "data:"):
			payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if payload == "" {
				continue
			}
			switch currentEvent {
			case "content_block_start":
				var evt struct {
					Index        int `json:"index"`
					ContentBlock struct {
						Type string `json:"type"`
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"content_block"`
				}
				if json.Unmarshal([]byte(payload), &evt) == nil && evt.ContentBlock.Type == "tool_use" {
					accum[evt.Index] = &toolCallAccumulator{ID: evt.ContentBlock.ID, Name: evt.ContentBlock.Name}
				}
			case "content_block_delta":
				var evt struct {
					Index int `json:"index"`
					Delta struct {
						Type        string `json:"type"`
						Text        string `json:"text"`
						PartialJSON string `json:"partial_json"`
					} `json:"delta"`
				}
				if json.Unmarshal([]byte(payload), &evt) != nil {
					continue
				}
				switch evt.Delta.Type {
				case "text_delta":
					if evt.Delta.Text != "" {
						gotAny = true
						onDelta(evt.Delta.Text)
					}
				case "input_json_delta":
					if a := accum[evt.Index]; a != nil {
						a.Args.WriteString(evt.Delta.PartialJSON)
					}
				}
			case "message_delta":
				var evt struct {
					Delta struct {
						StopReason string `json:"stop_reason"`
					} `json:"delta"`
				}
				if json.Unmarshal([]byte(payload), &evt) == nil && evt.Delta.StopReason != "" {
					stopReason = evt.Delta.StopReason
				}
			case "error":
				var evt struct {
					Error struct {
						Message string `json:"message"`
					} `json:"error"`
				}
				json.Unmarshal([]byte(payload), &evt)
				msg := evt.Error.Message
				if msg == "" {
					msg = payload
				}
				return streamResult{}, fmt.Errorf("%w: %s", errProviderNotOK, msg)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return streamResult{}, err
	}

	calls := finalizeToolCalls(accum)
	// A tool-only turn produces no text, which is not an error.
	if !gotAny && len(calls) == 0 {
		if stopReason != "" {
			return streamResult{}, fmt.Errorf("%w (provider stop_reason: %s -- if this is \"max_tokens\", the output budget was exhausted before any answer text was produced, e.g. by extended thinking consuming the whole budget)", errEmptyChoices, stopReason)
		}
		return streamResult{}, errEmptyChoices
	}
	// A compliant Anthropic stream ends with message_delta (carrying
	// stop_reason) and a message_stop event. Output but neither of those means
	// the provider cut the generation mid-output -- surface it instead of
	// passing a mid-sentence fragment off as a finished analysis.
	if stopReason == "" && !sawMessageStop {
		return streamResult{}, errStreamInterrupted
	}
	if stopReason == "max_tokens" {
		onDelta(truncationNotice)
	}
	return streamResult{ToolCalls: calls, StopReason: stopReason}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// aiErrorMessage renders an outbound-call error into the user-facing string
// stored alongside a failed analysis run.
func aiErrorMessage(err error, host string) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "AI provider did not start responding in time"
	case errors.Is(err, errNoModels):
		return "provider returned no models -- check host URL and key"
	case errors.Is(err, errEmptyChoices):
		return "AI provider returned an empty response"
	case errors.Is(err, errStreamInterrupted):
		return "AI analysis was interrupted -- the provider cut the stream before finishing. " +
			"The partial analysis above is incomplete; re-run to try again. " +
			"If it recurs, the gateway/proxy in front of the model is likely timing out on long responses."
	case errors.Is(err, errNonJSONBody), errors.Is(err, errProviderNotOK):
		return err.Error()
	default:
		return "could not reach AI provider at " + host + ": " + err.Error()
	}
}

// writeAIError maps an outbound AI-provider-call error to an HTTP status +
// message pair for a direct API response (fetchAIModels / runAIAnalysis).
func writeAIError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		writeErr(w, http.StatusGatewayTimeout, "AI provider did not start responding in time")
	case errors.Is(err, errNoModels):
		writeErr(w, http.StatusBadGateway, "provider returned no models -- check host URL and key")
	case errors.Is(err, errEmptyChoices):
		writeErr(w, http.StatusBadGateway, "AI provider returned an empty response")
	case errors.Is(err, errStreamInterrupted):
		writeErr(w, http.StatusBadGateway, "AI provider cut the stream before finishing (the response was interrupted mid-output)")
	case errors.Is(err, errNonJSONBody), errors.Is(err, errProviderNotOK):
		writeErr(w, http.StatusBadGateway, err.Error())
	default:
		writeErr(w, http.StatusBadGateway, "could not reach AI provider: "+err.Error())
	}
}
