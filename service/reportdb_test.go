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
