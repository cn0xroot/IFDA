package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// A real 3000+-finding scan hit this: cve-bin-tool occasionally reports the
// same product/version/CVE via more than one detection path with identical
// evidence, so two distinct Finding objects in one report can legitimately
// share the same fingerprint id (Finding.fingerprint() in ifda/model.py is
// deliberately independent of severity/description precisely so that kind
// of duplicate collapses onto one identity). The findings table's PRIMARY
// KEY is (job_id, id), so a plain INSERT crashed the whole ingest on the
// first duplicate instead of just keeping one row.
func TestIngestDuplicateFindingID(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}

	reportJSON := []byte(`{
		"target": "/fw",
		"tool_version": "test",
		"generated_at": "now",
		"binaries": [{"path": "/fw/bin/a"}, {"path": "/fw/bin/a"}],
		"scripts": [],
		"components": [],
		"findings": [
			{"id": "dup1", "title": "first",  "vuln_class": "known_cve", "severity": "high", "confidence": 0.7, "component": "x@1", "rule": "cve-bin-tool"},
			{"id": "dup1", "title": "second", "vuln_class": "known_cve", "severity": "high", "confidence": 0.7, "component": "x@1", "rule": "cve-bin-tool"},
			{"id": "uniq", "title": "third",  "vuln_class": "known_cve", "severity": "critical", "confidence": 0.9, "component": "y@2", "rule": "cve-bin-tool"}
		]
	}`)

	bins, finds, highCrit, err := db.Ingest("job-1", reportJSON, nil)
	if err != nil {
		t.Fatalf("Ingest failed (this is the bug: UNIQUE constraint on findings.job_id,id): %v", err)
	}
	if bins != 1 {
		t.Errorf("bins = %d, want 1 (duplicate binary path should collapse)", bins)
	}
	if finds != 2 {
		t.Errorf("finds = %d, want 2 (dup1 x2 + uniq should collapse to 2 rows)", finds)
	}
	if highCrit != 2 {
		t.Errorf("highCrit = %d, want 2 (both surviving rows are high/critical)", highCrit)
	}

	items, total, err := db.ListFindings("job-1", FindingQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("ListFindings total = %d, want 2", total)
	}
	titles := map[string]bool{}
	for _, it := range items {
		titles[it["title"].(string)] = true
	}
	if titles["first"] {
		t.Error("expected the first dup1 row to be replaced by the second (OR REPLACE keeps the last write), but 'first' is still present")
	}
	if !titles["second"] || !titles["third"] {
		t.Errorf("expected 'second' and 'third' present, got titles=%v", titles)
	}
}

// The busybox_audit column carries a JSON object (compiled_in/missing
// applets, bin/sbin extra commands, init.d script dump -- see
// ifda/inventory/busybox_audit.py), stored and read back verbatim rather
// than modeled further in Go. Confirms it survives Ingest -> GetBusyboxAudit
// and Ingest -> ExportFull, and that a job ingested without one (or never
// ingested at all) degrades to "{}" rather than an error or null.
func TestBusyboxAuditRoundTrip(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}

	reportJSON := []byte(`{
		"target": "/fw",
		"tool_version": "test",
		"generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": [],
		"busybox_audit": {
			"has_busybox": true,
			"compiled_in": ["ls", "sh"],
			"missing": ["telnetd"],
			"extra_commands": [{"path": "/fw/usr/sbin/vendord", "name": "vendord", "kind": "binary", "dir": "/usr/sbin"}],
			"init_scripts": [{"path": "/fw/etc/init.d/S50network", "content": "#!/bin/sh\necho hi\n", "truncated": false}]
		}
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetBusyboxAudit("job-1")
	if err != nil {
		t.Fatal(err)
	}
	var audit struct {
		HasBusybox    bool     `json:"has_busybox"`
		CompiledIn    []string `json:"compiled_in"`
		Missing       []string `json:"missing"`
		ExtraCommands []struct {
			Name string `json:"name"`
			Dir  string `json:"dir"`
		} `json:"extra_commands"`
		InitScripts []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"init_scripts"`
	}
	if err := json.Unmarshal(got, &audit); err != nil {
		t.Fatalf("GetBusyboxAudit returned invalid JSON: %v (%s)", err, got)
	}
	if !audit.HasBusybox || len(audit.CompiledIn) != 2 || len(audit.Missing) != 1 {
		t.Errorf("GetBusyboxAudit = %+v, want has_busybox=true, 2 compiled_in, 1 missing", audit)
	}
	if len(audit.ExtraCommands) != 1 || audit.ExtraCommands[0].Dir != "/usr/sbin" {
		t.Errorf("extra_commands = %+v", audit.ExtraCommands)
	}
	if len(audit.InitScripts) != 1 || !strings.Contains(audit.InitScripts[0].Content, "echo hi") {
		t.Errorf("init_scripts = %+v", audit.InitScripts)
	}

	full, err := db.ExportFull("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), `"vendord"`) {
		t.Error("ExportFull does not include busybox_audit content")
	}

	// A job with no busybox_audit at all (or no report ingested) must
	// degrade to "{}", not an error or a null the frontend would choke on.
	got2, err := db.GetBusyboxAudit("job-never-ingested")
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != "{}" {
		t.Errorf("GetBusyboxAudit for unknown job = %q, want {}", got2)
	}
}

// Network service identification (ifda/inventory/service_id.py's
// detect_services()) round-trips through report_meta the same way
// busybox_audit does, plus feeds the dashboard's service_count/
// open_port_count aggregates.
func TestServicesRoundTrip(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}

	reportJSON := []byte(`{
		"target": "/fw",
		"tool_version": "test",
		"generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": [],
		"services": [
			{"name": "nginx", "category": "web", "binary_path": "/fw/usr/sbin/nginx",
			 "version": "1.18.0", "ports": [80], "port_source": "default", "confidence": 0.95},
			{"name": "Dropbear SSH", "category": "ssh", "binary_path": "/fw/usr/sbin/dropbear",
			 "version": "2019.78", "ports": [22], "port_source": "config", "confidence": 0.95}
		]
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetServices("job-1")
	if err != nil {
		t.Fatal(err)
	}
	var services []struct {
		Name string `json:"name"`
		Port []int  `json:"ports"`
	}
	if err := json.Unmarshal(got, &services); err != nil {
		t.Fatalf("GetServices returned invalid JSON: %v (%s)", err, got)
	}
	if len(services) != 2 {
		t.Fatalf("GetServices = %+v, want 2 services", services)
	}

	summary, err := db.GetSummary("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if summary.ServiceCount != 2 {
		t.Errorf("ServiceCount = %d, want 2", summary.ServiceCount)
	}
	if summary.OpenPortCount != 2 {
		t.Errorf("OpenPortCount = %d, want 2", summary.OpenPortCount)
	}

	full, err := db.ExportFull("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), `"Dropbear SSH"`) {
		t.Error("ExportFull does not include services content")
	}

	// A job with no services at all must degrade to "[]", not an error or a
	// null the frontend would choke on.
	got2, err := db.GetServices("job-never-ingested")
	if err != nil {
		t.Fatal(err)
	}
	if string(got2) != "[]" {
		t.Errorf("GetServices for unknown job = %q, want []", got2)
	}
}

// Dashboard cert_count/rsa_cert_count (ifda/inventory/secrets.py's
// count_certificates()) round-trip through report_meta the same way
// kernel_version/file_count already do.
func TestCertCountsRoundTrip(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON := []byte(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": [],
		"cert_count": 169, "rsa_cert_count": 152
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	summary, err := db.GetSummary("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if summary.CertCount != 169 || summary.RsaCertCount != 152 {
		t.Errorf("CertCount=%d RsaCertCount=%d, want 169/152", summary.CertCount, summary.RsaCertCount)
	}

	full, err := db.ExportFull("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), `"cert_count":169`) || !strings.Contains(string(full), `"rsa_cert_count":152`) {
		t.Errorf("ExportFull does not include cert counts: %s", full)
	}
}

// A job ingested before cert_count/rsa_cert_count existed (or a report that
// simply omits them) must degrade to 0, not error or a NULL that breaks the
// dashboard's arithmetic.
func TestCertCountsDefaultToZero(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON := []byte(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": []
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}
	summary, err := db.GetSummary("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if summary.CertCount != 0 || summary.RsaCertCount != 0 {
		t.Errorf("CertCount=%d RsaCertCount=%d, want 0/0", summary.CertCount, summary.RsaCertCount)
	}
}

// FileKnown gates the Files tab's content-preview endpoint -- it must only
// ever confirm paths the scan itself recorded, and must be job-scoped (a
// path from a different job's scan is not "known" here even if the string
// happens to match).
func TestFileKnown(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON := []byte(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": [],
		"files": [{"path": "/fw/etc/config", "kind": "other", "size": 5, "md5": "x"}]
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	known, err := db.FileKnown("job-1", "/fw/etc/config")
	if err != nil {
		t.Fatal(err)
	}
	if !known {
		t.Error("expected /fw/etc/config to be known for job-1")
	}

	known, err = db.FileKnown("job-1", "/fw/etc/does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	if known {
		t.Error("expected an unrecorded path to be unknown")
	}

	known, err = db.FileKnown("job-other", "/fw/etc/config")
	if err != nil {
		t.Fatal(err)
	}
	if known {
		t.Error("FileKnown must be job-scoped -- a different job's path match must not count")
	}
}

// The Files tab's Kind filter (All/Binary/Script/Config/Symlink/Other) is a
// plain SQL WHERE on the files table's own "kind" column (extracted from
// each entry's JSON at Ingest), not a client-side filter over every row --
// this is the query path that backs it.
func TestListFilesByKind(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON := []byte(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": [],
		"files": [
			{"path": "/fw/etc/dnsmasq.conf", "kind": "config", "size": 5, "md5": "a"},
			{"path": "/fw/etc/config/dhcp", "kind": "config", "size": 5, "md5": "b"},
			{"path": "/fw/bin/busybox", "kind": "binary", "size": 5, "md5": "c"},
			{"path": "/fw/bin/sh", "kind": "symlink", "size": 0, "md5": ""}
		]
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	items, total, err := db.ListFiles("job-1", "config", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(items) != 2 {
		t.Errorf("kind=config: total=%d len(items)=%d, want 2/2", total, len(items))
	}

	items, total, err = db.ListFiles("job-1", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || len(items) != 4 {
		t.Errorf("kind='' (all): total=%d len(items)=%d, want 4/4", total, len(items))
	}

	all, err := db.ListFilesAll("job-1", "binary")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Errorf("ListFilesAll(kind=binary) = %d rows, want 1", len(all))
	}
}

// Regression: a database created before the files.kind column existed (an
// upgrade, not a fresh install) must not fail to open -- migrate()'s ALTER
// TABLE has to run before the index that depends on the column, and ignore
// the "duplicate column" error a database that already has it produces.
func TestMigrateAddsFilesKindColumnToExistingDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "reports.db")

	// Simulate a pre-upgrade database: files table without a kind column.
	pre, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pre.Exec(`CREATE TABLE files (job_id TEXT, path TEXT, data TEXT, PRIMARY KEY (job_id, path))`); err != nil {
		t.Fatal(err)
	}
	if _, err := pre.Exec(`INSERT INTO files (job_id, path, data) VALUES (?, ?, ?)`,
		"job-1", "/fw/etc/x.conf", `{"path":"/fw/etc/x.conf","kind":"config"}`); err != nil {
		t.Fatal(err)
	}
	if err := pre.Close(); err != nil {
		t.Fatal(err)
	}

	// NewReportDB's migrate() must add the column (and its index) without error.
	db, err := NewReportDB(dbPath)
	if err != nil {
		t.Fatalf("NewReportDB on a pre-upgrade database failed: %v", err)
	}
	items, total, err := db.ListFiles("job-1", "", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 {
		t.Errorf("total=%d len(items)=%d, want 1/1 (old row survives the upgrade)", total, len(items))
	}
}

// Regression: a real 537-binary/3000+-finding scan has more rows than the
// interactive pagination page-size caps (findings: 1000, binaries/scripts/
// files: 2000). ExportFull and the "export filtered" UI buttons must return
// every matching row regardless -- an export silently truncated to a page
// size is wrong, not just inconvenient.
func TestExportFullDoesNotTruncateLargeReports(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}

	const nFindings = 1500 // > ListFindings' 1000 cap
	const nFiles = 2200    // > paginateRaw's 2000 cap

	var findings []string
	for i := 0; i < nFindings; i++ {
		findings = append(findings, fmt.Sprintf(
			`{"id": "f%d", "title": "t%d", "vuln_class": "x", "severity": "medium", "confidence": 0.5, "component": "c", "rule": "r"}`, i, i))
	}
	var files []string
	for i := 0; i < nFiles; i++ {
		files = append(files, fmt.Sprintf(`{"path": "/fw/file%d", "kind": "other", "size": 1, "md5": "x"}`, i))
	}
	reportJSON := []byte(fmt.Sprintf(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [],
		"findings": [%s],
		"files": [%s]
	}`, strings.Join(findings, ","), strings.Join(files, ",")))

	if _, _, _, err := db.Ingest("job-big", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	// The paginated API (no ?all=1 equivalent) is still capped -- that's
	// intentional, this just documents the boundary.
	_, total, err := db.ListFindings("job-big", FindingQuery{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if total != nFindings {
		t.Errorf("ListFindings total = %d, want %d (total count itself must not be capped)", total, nFindings)
	}

	// NoLimit (what ExportFull and ?all=1 use) must return everything.
	all, _, err := db.ListFindings("job-big", FindingQuery{NoLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != nFindings {
		t.Errorf("ListFindings with NoLimit returned %d rows, want %d -- export would be silently truncated", len(all), nFindings)
	}

	allFiles, err := listAllRaw(db.db, "files", "job-big")
	if err != nil {
		t.Fatal(err)
	}
	if len(allFiles) != nFiles {
		t.Errorf("listAllRaw(files) returned %d rows, want %d", len(allFiles), nFiles)
	}

	full, err := db.ExportFull("job-big")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
		Files    []json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(full, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != nFindings {
		t.Errorf("ExportFull findings = %d, want %d", len(doc.Findings), nFindings)
	}
	if len(doc.Files) != nFiles {
		t.Errorf("ExportFull files = %d, want %d", len(doc.Files), nFiles)
	}
}

// AI provider profiles round-trip through the encrypted-key columns, and
// ListProviders never surfaces api_key_enc (only GetProvider, used
// internally by the analysis handler, does).
func TestAIProviderCRUD(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, aiKeySize)
	enc, err := encryptSecret(key, "sk-original-secret")
	if err != nil {
		t.Fatal(err)
	}
	now := "2026-01-01T00:00:00Z"
	p := AIProvider{ID: "ai-1", Name: "Test Gateway", Host: "https://gw.example.com", APIKeyEnc: enc,
		KeyLast4: keyLast4("sk-original-secret"), Model: "gpt-test", MaxTokens: 4096, CreatedAt: now, UpdatedAt: now}
	if err := db.CreateProvider(p); err != nil {
		t.Fatal(err)
	}

	list, err := db.ListProviders()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "Test Gateway" {
		t.Fatalf("ListProviders = %+v", list)
	}

	got, err := db.GetProvider("ai-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("GetProvider returned nil for an existing id")
	}
	if got.MaxTokens != 4096 {
		t.Errorf("MaxTokens = %d, want 4096", got.MaxTokens)
	}
	plain, err := decryptSecret(key, got.APIKeyEnc)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "sk-original-secret" {
		t.Errorf("decrypted key = %q, want sk-original-secret", plain)
	}
	if got.KeyLast4 != "cret" {
		t.Errorf("KeyLast4 = %q, want %q", got.KeyLast4, "cret")
	}

	// Update without touching the key (nil pointers) must leave it decryptable
	// to the same original plaintext -- this is the "leave the key field
	// blank to keep it unchanged" contract the edit form relies on.
	if err := db.UpdateProvider("ai-1", "Renamed", "https://gw2.example.com", "gpt-test-2", "anthropic", 16384, nil, nil); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetProvider("ai-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Renamed" || got.Host != "https://gw2.example.com" || got.Model != "gpt-test-2" {
		t.Errorf("after UpdateProvider (no key change) = %+v", got)
	}
	if got.Kind != "anthropic" {
		t.Errorf("Kind = %q, want anthropic", got.Kind)
	}
	if got.MaxTokens != 16384 {
		t.Errorf("MaxTokens = %d, want 16384", got.MaxTokens)
	}
	plain, err = decryptSecret(key, got.APIKeyEnc)
	if err != nil || plain != "sk-original-secret" {
		t.Errorf("key must survive a no-key-change update, got plain=%q err=%v", plain, err)
	}

	// Update with a new key must replace both api_key_enc and key_last4.
	newEnc, _ := encryptSecret(key, "sk-rotated-key")
	newLast4 := keyLast4("sk-rotated-key")
	if err := db.UpdateProvider("ai-1", "Renamed", "https://gw2.example.com", "gpt-test-2", "openai", 16384, &newEnc, &newLast4); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetProvider("ai-1")
	if got.KeyLast4 != "-key" {
		t.Errorf("KeyLast4 after rotation = %q, want -key", got.KeyLast4)
	}
	if got.Kind != "openai" {
		t.Errorf("Kind after second update = %q, want openai", got.Kind)
	}
	plain, _ = decryptSecret(key, got.APIKeyEnc)
	if plain != "sk-rotated-key" {
		t.Errorf("decrypted key after rotation = %q, want sk-rotated-key", plain)
	}

	if err := db.DeleteProvider("ai-1"); err != nil {
		t.Fatal(err)
	}
	if got, err := db.GetProvider("ai-1"); err != nil || got != nil {
		t.Errorf("GetProvider after delete = %+v, err=%v, want nil, nil", got, err)
	}
}

// The AI analysis cache goes running -> done (or running -> error), and
// GetAnalysis on a job that was never analyzed returns (nil, nil) rather
// than an error, mirroring GetSummary's "not ingested yet" convention.
// Regression: a streaming analysis is driven entirely by one in-flight
// HTTP request, so if the service dies mid-stream nothing remains to move
// that row off 'running' -- leaving the UI spinning on that job forever.
// Reopening the database (i.e. the next process start) must close such
// rows out, while preserving whatever partial content had been persisted.
func TestReopeningDBReconcilesInterruptedAnalyses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reports.db")
	db, err := NewReportDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAnalysisRunning("job-1", "ai-1", "Gateway", "gpt-test"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateAnalysisContent("job-1", "half an analysis"); err != nil {
		t.Fatal(err)
	}
	// A completed run from before must not be disturbed by reconciliation.
	if err := db.UpsertAnalysisRunning("job-2", "ai-1", "Gateway", "gpt-test"); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteAnalysis("job-2", "a finished analysis", nil); err != nil {
		t.Fatal(err)
	}
	db.db.Close() // simulate the process going away mid-stream

	reopened, err := NewReportDB(path)
	if err != nil {
		t.Fatal(err)
	}

	got, err := reopened.GetAnalysis("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" {
		t.Errorf("interrupted run status = %q, want error (a 'running' row can never be resumed by a new process)", got.Status)
	}
	if got.Content != "half an analysis" {
		t.Errorf("content = %q, want the partial content preserved", got.Content)
	}
	if got.Error == "" {
		t.Error("interrupted run must carry an explanatory error message")
	}
	if got.FinishedAt == "" {
		t.Error("interrupted run must be given a finished_at timestamp")
	}

	done, err := reopened.GetAnalysis("job-2")
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "done" || done.Content != "a finished analysis" {
		t.Errorf("an already-completed analysis must be left alone, got %+v", done)
	}
}

func TestAIAnalysisCache(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}

	if got, err := db.GetAnalysis("job-never-analyzed"); err != nil || got != nil {
		t.Fatalf("GetAnalysis for a never-analyzed job = %+v, err=%v, want nil, nil", got, err)
	}

	if err := db.UpsertAnalysisRunning("job-1", "ai-1", "Test Gateway", "gpt-test"); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAnalysis("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Status != "running" {
		t.Fatalf("after UpsertAnalysisRunning, GetAnalysis = %+v", got)
	}

	if err := db.CompleteAnalysis("job-1", "the analysis text", json.RawMessage(`{"finding_count_sent":1}`)); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetAnalysis("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "done" || got.Content != "the analysis text" {
		t.Errorf("after CompleteAnalysis, GetAnalysis = %+v", got)
	}

	// Re-running (a fresh UpsertAnalysisRunning) must clear the prior
	// content/error -- a page load mid-run shouldn't show a stale result.
	if err := db.UpsertAnalysisRunning("job-1", "ai-1", "Test Gateway", "gpt-test"); err != nil {
		t.Fatal(err)
	}
	got, _ = db.GetAnalysis("job-1")
	if got.Status != "running" || got.Content != "" {
		t.Errorf("re-running must clear prior content, got %+v", got)
	}

	// UpdateAnalysisContent (the streaming partial-persist path) must update
	// only content, leaving status/error untouched.
	if err := db.UpdateAnalysisContent("job-1", "partial text so far"); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetAnalysis("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "running" || got.Content != "partial text so far" {
		t.Errorf("after UpdateAnalysisContent, GetAnalysis = %+v", got)
	}

	// FailAnalysis must preserve whatever content had already streamed in
	// before the failure, not discard it.
	if err := db.FailAnalysis("job-1", "partial text so far", "provider unreachable"); err != nil {
		t.Fatal(err)
	}
	got, err = db.GetAnalysis("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "error" || got.Error != "provider unreachable" || got.Content != "partial text so far" {
		t.Errorf("after FailAnalysis, GetAnalysis = %+v", got)
	}
}

// Deleting a provider must not delete cached analyses it produced -- the
// analysis text is still meaningful to show even once its provider config
// is gone -- but provider_id must be nulled out since re-running with it is
// no longer possible.
func TestDeleteProviderNullsAnalysisReference(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, aiKeySize)
	enc, _ := encryptSecret(key, "sk-x")
	if err := db.CreateProvider(AIProvider{ID: "ai-1", Name: "Gateway", Host: "https://gw.example.com",
		APIKeyEnc: enc, KeyLast4: "sk-x", Model: "gpt-test", CreatedAt: "now", UpdatedAt: "now"}); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertAnalysisRunning("job-1", "ai-1", "Gateway", "gpt-test"); err != nil {
		t.Fatal(err)
	}
	if err := db.CompleteAnalysis("job-1", "some analysis", nil); err != nil {
		t.Fatal(err)
	}

	if err := db.DeleteProvider("ai-1"); err != nil {
		t.Fatal(err)
	}

	got, err := db.GetAnalysis("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("cached analysis must survive its provider being deleted")
	}
	if got.ProviderID != nil {
		t.Errorf("ProviderID = %v, want nil after the provider was deleted", *got.ProviderID)
	}
	if got.ProviderName != "Gateway" || got.Content != "some analysis" {
		t.Errorf("provider_name/content snapshot must survive, got %+v", got)
	}
}
