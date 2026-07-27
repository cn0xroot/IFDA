package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// The tools the analysis model may call to pull scan data on demand.
//
// Why tools at all: the curated single-shot prompt (buildAnalysisPrompt)
// can only ever show a fixed sample, and real output kept stalling on
// "unproven as shown / needs manual triage" -- the model would correctly
// identify the most suspicious binary but had no way to go look at its
// call sites. It also physically cannot be fed everything: a real scan
// carries ~53k findings and a ~158KB busybox audit.
//
// Every tool is bounded (paginated, field-truncated, and finally clamped
// by maxToolResultChars) because an unbounded result would blow the
// context window and the token bill in one call.
const (
	// maxToolResultChars is the final hard clamp on any single tool result.
	maxToolResultChars = 12000
	// maxToolFindingRows bounds one search_findings page.
	maxToolFindingRows = 50
	// defaultToolFindingRows is used when the model omits `limit`.
	defaultToolFindingRows = 20
	// maxToolDetailIDs bounds get_finding_detail, whose rows are large
	// (full description + evidence + pseudocode each).
	maxToolDetailIDs = 5
	// maxInitScriptChars bounds one init.d script body.
	maxInitScriptChars = 8000
	// maxToolListRows bounds the paginated busybox list sections.
	maxToolListRows = 100
)

// aiToolDefinition is the dialect-neutral description of one tool. Both
// providers take a name/description/JSON-Schema triple; only the envelope
// around it differs (see openaiToolSpecs/anthropicToolSpecs).
type aiToolDefinition struct {
	Name        string
	Description string
	Schema      map[string]any
}

// JSON-Schema construction helpers. Prefixed rather than named `obj`/`str`
// because this is package main alongside the whole service.
func schemaObj(props map[string]any, required ...string) map[string]any {
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func schemaStr(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}
func schemaNum(desc string) map[string]any {
	return map[string]any{"type": "number", "description": desc}
}
func schemaInt(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// aiTools is the full tool surface. Descriptions are written for the model:
// they say what the data *is* and when it's worth pulling, since that's
// what determines whether the model uses them well.
func aiTools() []aiToolDefinition {
	return []aiToolDefinition{
		{
			Name: "search_findings",
			Description: "Search this scan's vulnerability findings. Returns compact rows plus the total match count, " +
				"without the large evidence/pseudocode fields (use get_finding_detail for those, guided by the " +
				"has_evidence / has_pseudocode flags). Use this to size up a vulnerability class, or to zero in on a " +
				"specific binary or library by name.",
			Schema: schemaObj(map[string]any{
				"vuln_class":         schemaStr("Exact vulnerability class, e.g. command_injection, buffer_overflow, hardcoded_credential, known_cve, private_key, weak_permissions."),
				"component_contains": schemaStr("Substring match on the component/binary path, e.g. 'libconnectivity' or '/core/bin/'."),
				"severity":           map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Filter to these severities: critical, high, medium, low, info."},
				"min_confidence":     schemaNum("Only findings at or above this confidence (0.0-1.0)."),
				"query":              schemaStr("Free-text match across title, description, component, CVE ids and evidence."),
				"limit":              schemaInt(fmt.Sprintf("Rows to return, default %d, max %d.", defaultToolFindingRows, maxToolFindingRows)),
				"offset":             schemaInt("Rows to skip, for paging through a large match set."),
			}),
		},
		{
			Name: "get_finding_detail",
			Description: "Fetch the full detail for specific findings by id: complete description, remediation, CVE ids, " +
				"evidence (including any taint path) and decompiled pseudocode. This is how you confirm whether a " +
				"flagged call site is actually reachable with attacker-controlled data instead of leaving it unproven.",
			Schema: schemaObj(map[string]any{
				"finding_ids": map[string]any{
					"type": "array", "items": map[string]any{"type": "string"},
					"description": fmt.Sprintf("Finding ids from search_findings, at most %d per call.", maxToolDetailIDs),
				},
			}, "finding_ids"),
		},
		{
			Name: "list_init_scripts",
			Description: "List the device's /etc/init.d (or vendor equivalent) startup scripts with their sizes. " +
				"Startup scripts are the most direct answer to 'what services does this device actually run at boot, " +
				"and with what arguments' -- and a common place for debug switches, telnet, and default credentials.",
			Schema: schemaObj(map[string]any{}),
		},
		{
			Name:        "read_init_script",
			Description: "Read the full text of one startup script listed by list_init_scripts.",
			Schema: schemaObj(map[string]any{
				"path": schemaStr("Exact script path as returned by list_init_scripts."),
			}, "path"),
		},
		{
			Name: "get_busybox_audit",
			Description: "Inspect what this firmware's BusyBox build provides versus a reference applet list, plus the " +
				"other executables present in bin/sbin. 'overview' returns counts only; 'missing_applets' lists " +
				"reference applets this build lacks; 'extra_commands' lists non-BusyBox executables, which is where " +
				"vendor tools and backdoor-ish helpers show up.",
			Schema: schemaObj(map[string]any{
				"section": map[string]any{
					"type": "string", "enum": []string{"overview", "missing_applets", "extra_commands"},
					"description": "Which part of the audit to return.",
				},
				"limit":  schemaInt(fmt.Sprintf("Rows for the list sections, max %d.", maxToolListRows)),
				"offset": schemaInt("Rows to skip, for paging."),
			}, "section"),
		},
		{
			Name: "get_services",
			Description: "List the network services statically identified in this firmware: software name, version " +
				"(read from an embedded banner, never guessed), inferred listening ports and how each port was " +
				"inferred. Use this to judge whether a vulnerability is actually reachable over the network.",
			Schema: schemaObj(map[string]any{}),
		},
	}
}

// openaiToolSpecs wraps the tool definitions in OpenAI's function envelope.
func openaiToolSpecs(defs []aiToolDefinition) []map[string]any {
	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name": d.Name, "description": d.Description, "parameters": d.Schema,
			},
		})
	}
	return out
}

// anthropicToolSpecs wraps the tool definitions in Anthropic's envelope,
// which puts the schema under `input_schema` and has no "function" nesting.
func anthropicToolSpecs(defs []aiToolDefinition) []map[string]any {
	out := make([]map[string]any, 0, len(defs))
	for _, d := range defs {
		out = append(out, map[string]any{
			"name": d.Name, "description": d.Description, "input_schema": d.Schema,
		})
	}
	return out
}

// toolArgs is the decoded argument object; every field is optional because
// the model may omit any of them (or emit nothing at all).
type toolArgs struct {
	VulnClass         string   `json:"vuln_class"`
	ComponentContains string   `json:"component_contains"`
	Severity          []string `json:"severity"`
	MinConfidence     float64  `json:"min_confidence"`
	Query             string   `json:"query"`
	Limit             int      `json:"limit"`
	Offset            int      `json:"offset"`
	FindingIDs        []string `json:"finding_ids"`
	Path              string   `json:"path"`
	Section           string   `json:"section"`
}

// executeAITool runs one model-requested tool against the scan data and
// returns the string fed back into the conversation. It never returns an
// error: a bad tool name, malformed arguments or a data-layer failure all
// come back as an explanatory result so the model can correct course
// (aborting the whole analysis over a mis-typed argument would be worse).
// The second return value reports a short human-readable summary for the
// UI activity line.
func executeAITool(reportDB *ReportDB, jobID string, call toolCall) (result, summary string) {
	var args toolArgs
	if strings.TrimSpace(call.Args) != "" {
		if err := json.Unmarshal([]byte(call.Args), &args); err != nil {
			return fmt.Sprintf("ERROR: could not parse arguments as JSON (%v). Re-issue the call with a valid JSON object.", err),
				call.Name + " (bad arguments)"
		}
	}

	var out string
	var sum string
	switch call.Name {
	case "search_findings":
		out, sum = toolSearchFindings(reportDB, jobID, args)
	case "get_finding_detail":
		out, sum = toolFindingDetail(reportDB, jobID, args)
	case "list_init_scripts":
		out, sum = toolListInitScripts(reportDB, jobID)
	case "read_init_script":
		out, sum = toolReadInitScript(reportDB, jobID, args)
	case "get_busybox_audit":
		out, sum = toolBusyboxAudit(reportDB, jobID, args)
	case "get_services":
		out, sum = toolServices(reportDB, jobID)
	default:
		return fmt.Sprintf("ERROR: unknown tool %q.", call.Name), call.Name + " (unknown)"
	}

	if len(out) > maxToolResultChars {
		out = out[:maxToolResultChars] + "\n...[tool result truncated; narrow the query or use paging]"
	}
	return out, sum
}

func toolSearchFindings(reportDB *ReportDB, jobID string, a toolArgs) (string, string) {
	limit := a.Limit
	if limit <= 0 {
		limit = defaultToolFindingRows
	}
	if limit > maxToolFindingRows {
		limit = maxToolFindingRows
	}
	fq := FindingQuery{
		Limit: limit, Offset: a.Offset, VulnClass: a.VulnClass,
		Severities: a.Severity, MinConf: a.MinConfidence, Sort: "severity",
	}
	// component_contains and query both map onto ListFindings' single LIKE
	// filter. When both are supplied, the component filter goes to SQL (it
	// is the more selective in practice) and the free text is applied as a
	// second pass over the returned page.
	postFilter := ""
	if a.ComponentContains != "" {
		fq.Q = a.ComponentContains
		postFilter = a.Query
	} else {
		fq.Q = a.Query
	}

	items, total, err := reportDB.ListFindings(jobID, fq)
	if err != nil {
		return "ERROR: " + err.Error(), "search_findings (failed)"
	}
	if postFilter != "" {
		kept := make([]map[string]any, 0, len(items))
		needle := strings.ToLower(postFilter)
		for _, it := range items {
			hay := strings.ToLower(strField(it, "title") + " " + strField(it, "description"))
			if strings.Contains(hay, needle) {
				kept = append(kept, it)
			}
		}
		items = kept
	}

	var b strings.Builder
	if postFilter != "" {
		// Be explicit that total counts the component filter only, so the
		// model doesn't read it as the count for both filters combined.
		fmt.Fprintf(&b, "%d findings match component_contains=%q (showing %d from offset %d that also match query=%q)\n\n",
			total, a.ComponentContains, len(items), a.Offset, postFilter)
	} else {
		fmt.Fprintf(&b, "%d findings match (showing %d from offset %d)\n\n", total, len(items), a.Offset)
	}
	for _, it := range items {
		cves := 0
		if raw, ok := it["cve_ids"].(json.RawMessage); ok && len(raw) > 2 {
			var ids []string
			json.Unmarshal(raw, &ids)
			cves = len(ids)
		}
		hasEv := false
		if raw, ok := it["evidence"].(json.RawMessage); ok && len(raw) > 2 {
			hasEv = true
		}
		conf, _ := it["confidence"].(float64)
		fmt.Fprintf(&b, "id=%s severity=%s confidence=%.2f vuln_class=%s component=%s rule=%s triage=%s cve_count=%d has_evidence=%t has_pseudocode=%t\n",
			strField(it, "id"), strField(it, "severity"), conf, strField(it, "vuln_class"),
			strField(it, "component"), strField(it, "rule"), strField(it, "triage"),
			cves, hasEv, strField(it, "pseudocode") != "")
		if d := strField(it, "description"); d != "" {
			fmt.Fprintf(&b, "    %s\n", truncate(d, 240))
		}
	}
	if len(items) == 0 {
		b.WriteString("(no findings matched these filters)\n")
	}
	return b.String(), fmt.Sprintf("search_findings → %d matches", total)
}

func toolFindingDetail(reportDB *ReportDB, jobID string, a toolArgs) (string, string) {
	if len(a.FindingIDs) == 0 {
		return "ERROR: finding_ids is required and must contain at least one id.", "get_finding_detail (no ids)"
	}
	ids := a.FindingIDs
	if len(ids) > maxToolDetailIDs {
		ids = ids[:maxToolDetailIDs]
	}
	items, _, err := reportDB.ListFindings(jobID, FindingQuery{IDs: ids, NoLimit: true})
	if err != nil {
		return "ERROR: " + err.Error(), "get_finding_detail (failed)"
	}
	if len(items) == 0 {
		return "No findings matched those ids. Ids come from search_findings' id= field.", "get_finding_detail → 0 found"
	}
	var b strings.Builder
	for _, it := range items {
		conf, _ := it["confidence"].(float64)
		fmt.Fprintf(&b, "=== id=%s ===\nseverity=%s confidence=%.2f vuln_class=%s component=%s rule=%s triage=%s\n",
			strField(it, "id"), strField(it, "severity"), conf, strField(it, "vuln_class"),
			strField(it, "component"), strField(it, "rule"), strField(it, "triage"))
		fmt.Fprintf(&b, "title: %s\n", strField(it, "title"))
		if d := strField(it, "description"); d != "" {
			fmt.Fprintf(&b, "description: %s\n", truncate(d, 2*maxFieldLen))
		}
		if rem := strField(it, "remediation"); rem != "" {
			fmt.Fprintf(&b, "remediation: %s\n", truncate(rem, maxFieldLen))
		}
		if raw, ok := it["cve_ids"].(json.RawMessage); ok && len(raw) > 2 {
			fmt.Fprintf(&b, "cve_ids: %s\n", truncate(string(raw), maxFieldLen))
		}
		if raw, ok := it["evidence"].(json.RawMessage); ok && len(raw) > 2 {
			fmt.Fprintf(&b, "evidence: %s\n", truncate(string(raw), 2*maxFieldLen))
		}
		if ps := strField(it, "pseudocode"); ps != "" {
			fmt.Fprintf(&b, "pseudocode:\n%s\n", truncate(ps, 2*maxFieldLen))
		}
		b.WriteString("\n")
	}
	return b.String(), fmt.Sprintf("get_finding_detail → %d finding(s)", len(items))
}

// busyboxAudit is the subset of the stored audit blob these tools read.
type busyboxAudit struct {
	HasBusybox    bool     `json:"has_busybox"`
	BusyboxPaths  []string `json:"busybox_paths"`
	CompiledIn    []string `json:"compiled_in"`
	Missing       []string `json:"missing"`
	ExtraCommands []struct {
		Path string `json:"path"`
		Name string `json:"name"`
		Kind string `json:"kind"`
		Dir  string `json:"dir"`
	} `json:"extra_commands"`
	InitScripts []struct {
		Path      string `json:"path"`
		Content   string `json:"content"`
		Truncated bool   `json:"truncated"`
	} `json:"init_scripts"`
}

func loadBusyboxAudit(reportDB *ReportDB, jobID string) (*busyboxAudit, error) {
	raw, err := reportDB.GetBusyboxAudit(jobID)
	if err != nil {
		return nil, err
	}
	var a busyboxAudit
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

func toolListInitScripts(reportDB *ReportDB, jobID string) (string, string) {
	a, err := loadBusyboxAudit(reportDB, jobID)
	if err != nil {
		return "ERROR: " + err.Error(), "list_init_scripts (failed)"
	}
	if len(a.InitScripts) == 0 {
		return "No init.d scripts were found in this firmware.", "list_init_scripts → 0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d startup script(s):\n", len(a.InitScripts))
	for _, s := range a.InitScripts {
		fmt.Fprintf(&b, "  %s (%d bytes%s)\n", s.Path, len(s.Content),
			map[bool]string{true: ", stored copy truncated", false: ""}[s.Truncated])
	}
	b.WriteString("\nUse read_init_script with an exact path to read one.\n")
	return b.String(), fmt.Sprintf("list_init_scripts → %d script(s)", len(a.InitScripts))
}

func toolReadInitScript(reportDB *ReportDB, jobID string, args toolArgs) (string, string) {
	if args.Path == "" {
		return "ERROR: path is required.", "read_init_script (no path)"
	}
	a, err := loadBusyboxAudit(reportDB, jobID)
	if err != nil {
		return "ERROR: " + err.Error(), "read_init_script (failed)"
	}
	for _, s := range a.InitScripts {
		if s.Path == args.Path {
			return fmt.Sprintf("%s:\n%s", s.Path, truncate(s.Content, maxInitScriptChars)),
				"read_init_script " + shortToolPath(s.Path)
		}
	}
	// Be helpful rather than just failing: a near-miss on the path is the
	// likely cause, so show what is actually available.
	var avail []string
	for _, s := range a.InitScripts {
		avail = append(avail, s.Path)
	}
	return fmt.Sprintf("ERROR: no init script at %q. Available paths:\n  %s",
		args.Path, strings.Join(avail, "\n  ")), "read_init_script (not found)"
}

func toolBusyboxAudit(reportDB *ReportDB, jobID string, args toolArgs) (string, string) {
	a, err := loadBusyboxAudit(reportDB, jobID)
	if err != nil {
		return "ERROR: " + err.Error(), "get_busybox_audit (failed)"
	}
	limit := args.Limit
	if limit <= 0 || limit > maxToolListRows {
		limit = maxToolListRows
	}
	page := func(items []string) string {
		if args.Offset >= len(items) {
			return "(offset past the end)"
		}
		end := args.Offset + limit
		if end > len(items) {
			end = len(items)
		}
		return strings.Join(items[args.Offset:end], "\n  ")
	}

	switch args.Section {
	case "overview":
		var b strings.Builder
		fmt.Fprintf(&b, "has_busybox=%t\nbusybox_paths: %s\ncompiled_in_applets=%d\nmissing_applets=%d\nextra_commands=%d\ninit_scripts=%d\n",
			a.HasBusybox, strings.Join(a.BusyboxPaths, ", "), len(a.CompiledIn), len(a.Missing),
			len(a.ExtraCommands), len(a.InitScripts))
		b.WriteString("\nUse section=missing_applets or section=extra_commands (both paged) for the lists.\n")
		return b.String(), "get_busybox_audit (overview)"
	case "missing_applets":
		return fmt.Sprintf("%d reference applets are absent from this BusyBox build (showing from offset %d):\n  %s\n",
			len(a.Missing), args.Offset, page(a.Missing)), fmt.Sprintf("get_busybox_audit missing → %d", len(a.Missing))
	case "extra_commands":
		rows := make([]string, 0, len(a.ExtraCommands))
		for _, c := range a.ExtraCommands {
			rows = append(rows, fmt.Sprintf("%s (name=%s kind=%s dir=%s)", c.Path, c.Name, c.Kind, c.Dir))
		}
		return fmt.Sprintf("%d executables in bin/sbin are not applets of this BusyBox build (showing from offset %d):\n  %s\n",
			len(rows), args.Offset, page(rows)), fmt.Sprintf("get_busybox_audit extra → %d", len(rows))
	default:
		return "ERROR: section must be one of: overview, missing_applets, extra_commands.", "get_busybox_audit (bad section)"
	}
}

func toolServices(reportDB *ReportDB, jobID string) (string, string) {
	raw, err := reportDB.GetServices(jobID)
	if err != nil {
		return "ERROR: " + err.Error(), "get_services (failed)"
	}
	var services []struct {
		Name       string  `json:"name"`
		Category   string  `json:"category"`
		BinaryPath string  `json:"binary_path"`
		Version    string  `json:"version"`
		Ports      []int   `json:"ports"`
		PortSource string  `json:"port_source"`
		Confidence float64 `json:"confidence"`
	}
	if err := json.Unmarshal(raw, &services); err != nil {
		return "ERROR: could not parse stored services: " + err.Error(), "get_services (failed)"
	}
	if len(services) == 0 {
		return "No known network services were identified in this firmware.", "get_services → 0"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d identified network service(s). Ports are statically inferred, not observed:\n", len(services))
	for _, s := range services {
		ports := "unknown"
		if len(s.Ports) > 0 {
			strs := make([]string, 0, len(s.Ports))
			for _, p := range s.Ports {
				strs = append(strs, fmt.Sprint(p))
			}
			ports = strings.Join(strs, ",")
		}
		version := s.Version
		if version == "" {
			version = "(no banner found)"
		}
		fmt.Fprintf(&b, "  %s [%s] version=%s ports=%s port_source=%s confidence=%.2f binary=%s\n",
			s.Name, s.Category, version, ports, s.PortSource, s.Confidence, s.BinaryPath)
	}
	return b.String(), fmt.Sprintf("get_services → %d service(s)", len(services))
}

// shortToolPath trims a long absolute path for the UI activity line.
func shortToolPath(p string) string {
	if len(p) <= 42 {
		return p
	}
	return "…" + p[len(p)-41:]
}
