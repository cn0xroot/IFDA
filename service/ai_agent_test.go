package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// toolTestDB builds a scan with enough shape to exercise every tool: a
// couple of vulnerability classes, a finding carrying real evidence and
// pseudocode, init.d scripts, a busybox audit, and identified services.
func toolTestDB(t *testing.T) *ReportDB {
	t.Helper()
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	report := `{
      "target": "/fw", "tool_version": "test", "generated_at": "now",
      "binaries": [], "scripts": [], "components": [],
      "findings": [
        {"id":"ci1","title":"popen with unfiltered input","vuln_class":"command_injection","severity":"high",
         "confidence":0.8,"component":"/core/lib/libconn.so","rule":"unsafe-api",
         "description":"popen call reached from network handler",
         "pseudocode":"handler(): popen(cmd);",
         "evidence":[{"binary":"/core/lib/libconn.so","function":"handler","taint_path":["recv","strcpy","popen"]}]},
        {"id":"ci2","title":"system call","vuln_class":"command_injection","severity":"medium",
         "confidence":0.5,"component":"/core/bin/other","rule":"unsafe-api","description":"system() present"},
        {"id":"pk1","title":"private key","vuln_class":"private_key","severity":"critical",
         "confidence":0.95,"component":"/etc/ssh/ssh_host_key","rule":"secrets",
         "description":"BEGIN OPENSSH PRIVATE KEY"}
      ],
      "busybox_audit": {
        "has_busybox": true, "busybox_paths": ["/bin/busybox"],
        "compiled_in": ["ls","sh","cat"], "missing": ["telnetd","tftpd"],
        "extra_commands": [{"path":"/usr/sbin/vendord","name":"vendord","kind":"binary","dir":"/usr/sbin"}],
        "init_scripts": [
          {"path":"/etc/init.d/S50telnet","content":"#!/bin/sh\ntelnetd -l /bin/sh\n","truncated":false},
          {"path":"/etc/init.d/S10boot","content":"#!/bin/sh\necho boot\n","truncated":false}
        ]
      },
      "services": [
        {"name":"Dropbear SSH","category":"ssh","binary_path":"/usr/sbin/dropbear",
         "version":"2019.78","ports":[22],"port_source":"config","confidence":0.95}
      ]
    }`
	if _, _, _, err := db.Ingest("job-1", []byte(report), nil); err != nil {
		t.Fatal(err)
	}
	return db
}

func runTool(t *testing.T, db *ReportDB, name, args string) string {
	t.Helper()
	out, _ := executeAITool(db, "job-1", toolCall{ID: "c1", Name: name, Args: args})
	return out
}

func TestToolSearchFindings(t *testing.T) {
	db := toolTestDB(t)

	out := runTool(t, db, "search_findings", `{"vuln_class":"command_injection"}`)
	if !strings.Contains(out, "2 findings match") {
		t.Errorf("expected the class total, got: %s", out)
	}
	if !strings.Contains(out, "id=ci1") || !strings.Contains(out, "id=ci2") {
		t.Errorf("both command_injection findings should be listed: %s", out)
	}
	// The heavy fields must be summarized as flags, not inlined.
	if !strings.Contains(out, "has_evidence=true") || !strings.Contains(out, "has_pseudocode=true") {
		t.Errorf("expected evidence/pseudocode flags: %s", out)
	}
	if strings.Contains(out, "taint_path") {
		t.Error("search results must not inline evidence -- that's get_finding_detail's job")
	}

	// component filter
	out = runTool(t, db, "search_findings", `{"component_contains":"libconn"}`)
	if !strings.Contains(out, "id=ci1") || strings.Contains(out, "id=ci2") {
		t.Errorf("component filter should select only libconn: %s", out)
	}

	// severity filter
	out = runTool(t, db, "search_findings", `{"severity":["critical"]}`)
	if !strings.Contains(out, "id=pk1") || strings.Contains(out, "id=ci1") {
		t.Errorf("severity filter failed: %s", out)
	}
}

func TestToolGetFindingDetail(t *testing.T) {
	db := toolTestDB(t)

	// This is the capability that turns "needs manual triage" into a verdict.
	out := runTool(t, db, "get_finding_detail", `{"finding_ids":["ci1"]}`)
	if !strings.Contains(out, "taint_path") {
		t.Errorf("detail must include the evidence/taint path: %s", out)
	}
	if !strings.Contains(out, "popen(cmd)") {
		t.Errorf("detail must include pseudocode: %s", out)
	}

	if out := runTool(t, db, "get_finding_detail", `{"finding_ids":[]}`); !strings.Contains(out, "ERROR") {
		t.Errorf("empty ids should be an explanatory error: %s", out)
	}
	if out := runTool(t, db, "get_finding_detail", `{"finding_ids":["nope"]}`); !strings.Contains(out, "No findings matched") {
		t.Errorf("unknown id should say so: %s", out)
	}
}

func TestToolInitScripts(t *testing.T) {
	db := toolTestDB(t)

	out := runTool(t, db, "list_init_scripts", `{}`)
	if !strings.Contains(out, "S50telnet") || !strings.Contains(out, "S10boot") {
		t.Errorf("listing should name both scripts: %s", out)
	}
	if strings.Contains(out, "telnetd -l") {
		t.Error("the listing must not dump script bodies; that's read_init_script")
	}

	out = runTool(t, db, "read_init_script", `{"path":"/etc/init.d/S50telnet"}`)
	if !strings.Contains(out, "telnetd -l /bin/sh") {
		t.Errorf("reading should return the body: %s", out)
	}

	// A near-miss path should be helped along, not just rejected.
	out = runTool(t, db, "read_init_script", `{"path":"/etc/init.d/nope"}`)
	if !strings.Contains(out, "ERROR") || !strings.Contains(out, "S50telnet") {
		t.Errorf("a wrong path should list the available ones: %s", out)
	}
}

func TestToolBusyboxAudit(t *testing.T) {
	db := toolTestDB(t)

	out := runTool(t, db, "get_busybox_audit", `{"section":"overview"}`)
	if !strings.Contains(out, "compiled_in_applets=3") || !strings.Contains(out, "missing_applets=2") {
		t.Errorf("overview should report counts: %s", out)
	}
	if strings.Contains(out, "telnetd") {
		t.Error("overview must be counts only, not the lists")
	}

	if out := runTool(t, db, "get_busybox_audit", `{"section":"missing_applets"}`); !strings.Contains(out, "telnetd") {
		t.Errorf("missing_applets should list them: %s", out)
	}
	if out := runTool(t, db, "get_busybox_audit", `{"section":"extra_commands"}`); !strings.Contains(out, "vendord") {
		t.Errorf("extra_commands should list them: %s", out)
	}
	if out := runTool(t, db, "get_busybox_audit", `{"section":"bogus"}`); !strings.Contains(out, "ERROR") {
		t.Errorf("an invalid section should error: %s", out)
	}
}

func TestToolServices(t *testing.T) {
	out := runTool(t, toolTestDB(t), "get_services", `{}`)
	if !strings.Contains(out, "Dropbear SSH") || !strings.Contains(out, "ports=22") {
		t.Errorf("services should include name and ports: %s", out)
	}
}

// A model can emit malformed arguments or hallucinate a tool name; neither
// may abort the analysis -- both must come back as a correctable message.
func TestToolBadInputIsRecoverable(t *testing.T) {
	db := toolTestDB(t)
	if out := runTool(t, db, "search_findings", `{not json`); !strings.Contains(out, "ERROR") {
		t.Errorf("malformed arguments should return an error result: %s", out)
	}
	if out := runTool(t, db, "no_such_tool", `{}`); !strings.Contains(out, "unknown tool") {
		t.Errorf("unknown tool should return an error result: %s", out)
	}
}

// Every tool result is clamped, so one call can't blow the context window.
func TestToolResultIsClamped(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	big := strings.Repeat("z", 5000)
	var findings []string
	for i := 0; i < 50; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id":"f%d","title":"t","vuln_class":"x","severity":"high","confidence":0.5,
			  "component":"c%d","rule":"r","description":"%s"}`, i, i, big))
	}
	report := fmt.Sprintf(`{"target":"/fw","tool_version":"t","generated_at":"n",
		"binaries":[],"scripts":[],"components":[],"findings":[%s]}`, strings.Join(findings, ","))
	if _, _, _, err := db.Ingest("job-1", []byte(report), nil); err != nil {
		t.Fatal(err)
	}
	out, _ := executeAITool(db, "job-1", toolCall{Name: "search_findings", Args: `{"limit":50}`})
	if len(out) > maxToolResultChars+120 {
		t.Errorf("result length %d exceeds the clamp %d", len(out), maxToolResultChars)
	}
	if !strings.Contains(out, "truncated") {
		t.Error("a clamped result must say it was truncated")
	}
}

// --- streaming tool-call parsing ---

// OpenAI streams a tool call's `arguments` as fragments across chunks; they
// must be reassembled per index, not treated as separate calls.
func TestOpenAIStreamParsesFragmentedToolCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["tools"] == nil {
			t.Error("tools must be sent when the request offers them")
		}
		fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"search_findings","arguments":""}}]}}]}`+"\n\n")
		fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"vuln_"}}]}}]}`+"\n\n")
		fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"class\":\"x\"}"}}]}}]}`+"\n\n")
		fmt.Fprint(w, `data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	text, res, err := collectStream(t, context.Background(), srv.Client(), streamRequest{
		Kind: "openai", Host: srv.URL, APIKey: "k", Model: "m", MaxTokens: 1024,
		Messages: []chatMessage{{Role: "user", Content: "hi"}}, Tools: aiTools(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if text != "" {
		t.Errorf("a tool-only turn has no text, got %q", text)
	}
	if len(res.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v, want exactly 1 reassembled call", res.ToolCalls)
	}
	c := res.ToolCalls[0]
	if c.ID != "call_1" || c.Name != "search_findings" {
		t.Errorf("call id/name = %q/%q", c.ID, c.Name)
	}
	if c.Args != `{"vuln_class":"x"}` {
		t.Errorf("arguments = %q, want the fragments concatenated", c.Args)
	}
}

// Anthropic frames a tool call as a content block whose input JSON arrives
// as input_json_delta fragments; text blocks share the index space and must
// not be confused with it.
func TestAnthropicStreamParsesToolUseBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["tools"] == nil {
			t.Error("tools must be sent when the request offers them")
		}
		fmt.Fprint(w, "event: content_block_start\ndata: {\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"thinking \"}}\n\n")
		fmt.Fprint(w, "event: content_block_start\ndata: {\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_9\",\"name\":\"get_services\"}}\n\n")
		fmt.Fprint(w, "event: content_block_delta\ndata: {\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n")
		fmt.Fprint(w, "event: content_block_stop\ndata: {\"index\":1}\n\n")
		fmt.Fprint(w, "event: message_delta\ndata: {\"delta\":{\"stop_reason\":\"tool_use\"}}\n\n")
	}))
	defer srv.Close()

	text, res, err := collectStream(t, context.Background(), srv.Client(), streamRequest{
		Kind: "anthropic", Host: srv.URL, APIKey: "k", Model: "m", MaxTokens: 1024,
		Messages: []chatMessage{{Role: "user", Content: "hi"}}, Tools: aiTools(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if text != "thinking " {
		t.Errorf("text = %q, want the text block streamed through", text)
	}
	if len(res.ToolCalls) != 1 {
		t.Fatalf("tool calls = %+v, want 1", res.ToolCalls)
	}
	if res.ToolCalls[0].Name != "get_services" || res.ToolCalls[0].ID != "toolu_9" {
		t.Errorf("call = %+v", res.ToolCalls[0])
	}
	if res.StopReason != "tool_use" {
		t.Errorf("stop reason = %q", res.StopReason)
	}
}

// --- the loop ---

// The full round trip: the model asks for a tool, the server-side loop runs
// it, feeds the result back, and the model then produces prose.
func TestAgentRunsToolThenAnswers(t *testing.T) {
	db := toolTestDB(t)
	var sawToolResult string
	round := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role       string `json:"role"`
				Content    any    `json:"content"`
				ToolCallID string `json:"tool_call_id"`
			} `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		round++
		if round == 1 {
			fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"get_finding_detail","arguments":"{\"finding_ids\":[\"ci1\"]}"}}]}}]}`+"\n\n")
			fmt.Fprint(w, `data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		// Second round must carry the tool result back.
		for _, m := range body.Messages {
			if m.Role == "tool" {
				sawToolResult, _ = m.Content.(string)
			}
		}
		fmt.Fprint(w, `data: {"choices":[{"delta":{"content":"verdict: exploitable"}}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	var text strings.Builder
	var tools []string
	stats, err := runAnalysisAgent(context.Background(), srv.Client(), db, "job-1",
		streamRequest{Kind: "openai", Host: srv.URL, APIKey: "k", Model: "m", MaxTokens: 1024,
			Messages: withToolInstruction([]chatMessage{
				{Role: "system", Content: aiSystemPromptBase}, {Role: "user", Content: "analyze"}}),
			Tools: aiTools()},
		func(s string) { text.WriteString(s) },
		func(name, detail string) { tools = append(tools, name) })
	if err != nil {
		t.Fatal(err)
	}
	if text.String() != "verdict: exploitable" {
		t.Errorf("final text = %q", text.String())
	}
	if len(tools) != 1 || tools[0] != "get_finding_detail" {
		t.Errorf("tool activity = %v", tools)
	}
	if stats.ToolCalls != 1 || stats.ToolRounds != 1 {
		t.Errorf("stats = %+v, want 1 call in 1 round", stats)
	}
	if !strings.Contains(sawToolResult, "taint_path") {
		t.Errorf("the tool result fed back must contain the real data, got %q", sawToolResult)
	}
}

// A model that keeps asking for tools forever must still be made to answer:
// when the round budget runs out the loop retries with tools withheld.
func TestAgentRoundCapStillProducesAnswer(t *testing.T) {
	db := toolTestDB(t)
	toolsOfferedOnLastCall := true
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		requests++
		if body["tools"] != nil {
			// Insatiable: always ask for another tool while allowed to.
			fmt.Fprint(w, `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c","function":{"name":"get_services","arguments":"{}"}}]}}]}`+"\n\n")
			fmt.Fprint(w, `data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}`+"\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		toolsOfferedOnLastCall = false
		fmt.Fprint(w, `data: {"choices":[{"delta":{"content":"forced conclusion"}}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	var text strings.Builder
	stats, err := runAnalysisAgent(context.Background(), srv.Client(), db, "job-1",
		streamRequest{Kind: "openai", Host: srv.URL, APIKey: "k", Model: "m", MaxTokens: 1024,
			Messages: []chatMessage{{Role: "system", Content: "sys"}, {Role: "user", Content: "go"}},
			Tools:    aiTools()},
		func(s string) { text.WriteString(s) }, func(string, string) {})
	if err != nil {
		t.Fatal(err)
	}
	if text.String() != "forced conclusion" {
		t.Errorf("the run must end with prose, got %q", text.String())
	}
	if toolsOfferedOnLastCall {
		t.Error("the final round must withhold tools so the model has to answer")
	}
	if stats.ToolRounds > maxToolRounds {
		t.Errorf("ToolRounds = %d, must not exceed maxToolRounds %d", stats.ToolRounds, maxToolRounds)
	}
	if requests > maxToolRounds+2 {
		t.Errorf("made %d requests; the loop is not bounded tightly enough", requests)
	}
}

// Gateways that reject the tools field must not break the analysis: the run
// retries without tools and completes as the pre-tool version would.
func TestAgentFallsBackWhenToolsUnsupported(t *testing.T) {
	db := toolTestDB(t)
	sawToolRequest, sawToolFreeRequest := false, false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["tools"] != nil {
			sawToolRequest = true
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error":{"message":"this model does not support function calling"}}`)
			return
		}
		sawToolFreeRequest = true
		fmt.Fprint(w, `data: {"choices":[{"delta":{"content":"plain analysis"}}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	var text strings.Builder
	stats, err := runAnalysisAgent(context.Background(), srv.Client(), db, "job-1",
		streamRequest{Kind: "openai", Host: srv.URL, APIKey: "k", Model: "m", MaxTokens: 1024,
			Messages: withToolInstruction([]chatMessage{
				{Role: "system", Content: aiSystemPromptBase}, {Role: "user", Content: "go"}}),
			Tools: aiTools()},
		func(s string) { text.WriteString(s) }, func(string, string) {})
	if err != nil {
		t.Fatalf("a tool-hostile gateway must still yield an analysis, got: %v", err)
	}
	if !sawToolRequest || !sawToolFreeRequest {
		t.Errorf("expected a tools attempt then a tool-free retry (tools=%t, toolfree=%t)", sawToolRequest, sawToolFreeRequest)
	}
	if text.String() != "plain analysis" {
		t.Errorf("text = %q", text.String())
	}
	if !stats.ToolsUnsupported {
		t.Error("stats must record that the provider rejected tools")
	}
}

// The fallback must not fire once text has been streamed -- restarting then
// would duplicate content already shown to the user.
func TestAgentDoesNotFallBackAfterTextStreamed(t *testing.T) {
	db := toolTestDB(t)
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			// Stream some text, then fail in a way that looks tool-related.
			fmt.Fprint(w, `data: {"choices":[{"delta":{"content":"partial "}}]}`+"\n\n")
			w.(http.Flusher).Flush()
			fmt.Fprint(w, "event: error\ndata: {\"error\":{\"message\":\"tool failure\"}}\n\n")
			return
		}
		fmt.Fprint(w, `data: {"choices":[{"delta":{"content":"SHOULD NOT APPEAR"}}]}`+"\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	var text strings.Builder
	_, _ = runAnalysisAgent(context.Background(), srv.Client(), db, "job-1",
		streamRequest{Kind: "openai", Host: srv.URL, APIKey: "k", Model: "m", MaxTokens: 1024,
			Messages: []chatMessage{{Role: "system", Content: "sys"}, {Role: "user", Content: "go"}},
			Tools:    aiTools()},
		func(s string) { text.WriteString(s) }, func(string, string) {})
	if strings.Contains(text.String(), "SHOULD NOT APPEAR") {
		t.Error("must not restart the run after text was already streamed -- that duplicates output")
	}
}

// stripToolInstruction is what makes the fallback coherent: a model with no
// tools must not be told to use tools.
func TestStripToolInstruction(t *testing.T) {
	msgs := withToolInstruction([]chatMessage{
		{Role: "system", Content: aiSystemPromptBase}, {Role: "user", Content: "x"}})
	if !strings.Contains(msgs[0].Content, aiToolUsageInstruction) {
		t.Fatal("withToolInstruction should have attached the guidance")
	}
	stripped := stripToolInstruction(msgs)
	if strings.Contains(stripped[0].Content, aiToolUsageInstruction) {
		t.Error("stripToolInstruction must remove the tool guidance")
	}
	if !strings.Contains(stripped[0].Content, "security analyst assistant") {
		t.Error("stripping must keep the base system prompt intact")
	}
	if msgs[0].Content == stripped[0].Content {
		t.Error("stripToolInstruction must not mutate its input")
	}
}

// --- dialect serialization of a tool exchange ---

func TestOpenAIMessagesSerializesToolExchange(t *testing.T) {
	msgs := []chatMessage{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "go"},
		{Role: "assistant", ToolCalls: []toolCall{{ID: "c1", Name: "get_services", Args: "{}"}}},
		{Role: "tool", ToolCallID: "c1", Content: "one service"},
	}
	out := openaiMessages(msgs)
	if len(out) != 4 {
		t.Fatalf("got %d messages, want 4", len(out))
	}
	if out[0]["role"] != "system" {
		t.Error("system stays an ordinary message in the OpenAI dialect")
	}
	calls, ok := out[2]["tool_calls"].([]map[string]any)
	if !ok || len(calls) != 1 {
		t.Fatalf("assistant turn should carry tool_calls, got %+v", out[2])
	}
	if calls[0]["id"] != "c1" || calls[0]["type"] != "function" {
		t.Errorf("tool_call shape = %+v", calls[0])
	}
	if out[3]["role"] != "tool" || out[3]["tool_call_id"] != "c1" {
		t.Errorf("result message shape = %+v", out[3])
	}
}

func TestAnthropicMessagesSerializesToolExchange(t *testing.T) {
	msgs := []chatMessage{
		{Role: "system", Content: "sys"},
		{Role: "user", Content: "go"},
		{Role: "assistant", ToolCalls: []toolCall{
			{ID: "t1", Name: "get_services", Args: `{"a":1}`},
			{ID: "t2", Name: "list_init_scripts", Args: "{}"},
		}},
		{Role: "tool", ToolCallID: "t1", Content: "svc"},
		{Role: "tool", ToolCallID: "t2", Content: "scripts"},
	}
	system, out := anthropicMessages(msgs)
	if system != "sys" {
		t.Errorf("system must be hoisted out of messages, got %q", system)
	}
	if len(out) != 3 {
		t.Fatalf("want user + assistant + one merged tool_result turn, got %d: %+v", len(out), out)
	}
	blocks, ok := out[1]["content"].([]map[string]any)
	if !ok || len(blocks) != 2 {
		t.Fatalf("assistant content should be two tool_use blocks, got %+v", out[1])
	}
	if blocks[0]["type"] != "tool_use" || blocks[0]["id"] != "t1" {
		t.Errorf("first block = %+v", blocks[0])
	}
	// Arguments must be re-expanded to an object, not left as a string.
	if input, ok := blocks[0]["input"].(map[string]any); !ok || input["a"] == nil {
		t.Errorf("tool_use input should be the decoded object, got %+v", blocks[0]["input"])
	}
	// Consecutive results belong in ONE user turn per the Anthropic API.
	results, ok := out[2]["content"].([]map[string]any)
	if !ok || len(results) != 2 {
		t.Fatalf("consecutive tool results must merge into one user turn, got %+v", out[2])
	}
	if results[0]["type"] != "tool_result" || results[1]["tool_use_id"] != "t2" {
		t.Errorf("tool_result blocks = %+v", results)
	}
}

// A malformed arguments blob must not corrupt replayed Anthropic history.
func TestAnthropicMessagesToleratesMalformedToolArgs(t *testing.T) {
	_, out := anthropicMessages([]chatMessage{
		{Role: "assistant", ToolCalls: []toolCall{{ID: "t1", Name: "x", Args: "{not json"}}},
	})
	blocks := out[0]["content"].([]map[string]any)
	if input, ok := blocks[0]["input"].(map[string]any); !ok || len(input) != 0 {
		t.Errorf("malformed args should degrade to an empty object, got %+v", blocks[0]["input"])
	}
}

func TestFindingQueryIDsFilter(t *testing.T) {
	db := toolTestDB(t)
	items, _, err := db.ListFindings("job-1", FindingQuery{IDs: []string{"ci1", "pk1"}, NoLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("want exactly the 2 requested findings, got %d", len(items))
	}
	for _, it := range items {
		if id := strField(it, "id"); id != "ci1" && id != "pk1" {
			t.Errorf("unexpected id %q returned by an IDs-filtered query", id)
		}
	}
}
