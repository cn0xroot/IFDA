package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

// ReportDB stores per-job scan results (findings, binaries, scripts,
// components) in SQLite instead of one flat JSON blob per job. The old
// approach — the whole report shipped to the browser in a single response,
// rendered in full by Alpine's reactivity — is what crashed the tab on a
// large scan (thousands of findings, megabytes of extracted strings); this
// lets the API serve paginated, filtered slices instead.
//
// Job lifecycle metadata (Store, in job.go) stays JSON-file-backed: it's
// small and bounded by job count, not by scan size, so it was never the
// crash source and doesn't need to move.
type ReportDB struct {
	mu sync.Mutex // serializes writes; modernc.org/sqlite allows one writer at a time anyway
	db *sql.DB
}

// rawReport mirrors ifda/model.py's AnalysisReport.to_dict() shape closely
// enough to unmarshal; nested list-valued fields are kept as RawMessage and
// stored as JSON text columns rather than modeled further in Go, since the
// API only ever needs to hand them back to the browser verbatim.
type rawReport struct {
	Target        string            `json:"target"`
	ToolVersion   string            `json:"tool_version"`
	GeneratedAt   string            `json:"generated_at"`
	KernelVersion string            `json:"kernel_version"`
	ArchSummary   string            `json:"arch_summary"`
	EndianSummary string            `json:"endian_summary"`
	FileCount     int               `json:"file_count"`
	FirmwareSize  int64             `json:"firmware_size"`
	CertCount     int               `json:"cert_count"`
	RsaCertCount  int               `json:"rsa_cert_count"`
	Binaries      []json.RawMessage `json:"binaries"`
	Scripts       []json.RawMessage `json:"scripts"`
	Components    []json.RawMessage `json:"components"`
	Findings      []rawFinding      `json:"findings"`
	Files         []json.RawMessage `json:"files"`
	BusyboxAudit  json.RawMessage   `json:"busybox_audit"`
	Services      json.RawMessage   `json:"services"`
}

type rawFinding struct {
	ID          string          `json:"id"`
	Title       string          `json:"title"`
	VulnClass   string          `json:"vuln_class"`
	Severity    string          `json:"severity"`
	Confidence  float64         `json:"confidence"`
	Component   string          `json:"component"`
	Rule        string          `json:"rule"`
	Description string          `json:"description"`
	Remediation string          `json:"remediation"`
	CVEIDs      json.RawMessage `json:"cve_ids"`
	Evidence    json.RawMessage `json:"evidence"`
	Triage      string          `json:"triage"`
	Pseudocode  string          `json:"pseudocode"`
}

func NewReportDB(path string) (*ReportDB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// One writer at a time regardless of Go-level goroutines (mu above already
	// serializes our own writes; this also protects against sqlite's own
	// "database is locked" errors under WAL from concurrent readers).
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return nil, err
	}
	r := &ReportDB{db: db}
	if err := r.migrate(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *ReportDB) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS report_meta (
			job_id TEXT PRIMARY KEY,
			target TEXT, tool_version TEXT, generated_at TEXT,
			kernel_version TEXT, arch_summary TEXT, endian_summary TEXT,
			file_count INTEGER, firmware_size INTEGER,
			busybox_audit TEXT,
			cert_count INTEGER, rsa_cert_count INTEGER,
			services TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS findings (
			job_id TEXT, id TEXT, title TEXT, vuln_class TEXT, severity TEXT,
			confidence REAL, component TEXT, rule TEXT, description TEXT,
			remediation TEXT, cve_ids TEXT, evidence TEXT, triage TEXT, pseudocode TEXT,
			PRIMARY KEY (job_id, id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_job ON findings(job_id)`,
		`CREATE INDEX IF NOT EXISTS idx_findings_job_sev ON findings(job_id, severity)`,
		`CREATE TABLE IF NOT EXISTS binaries (
			job_id TEXT, path TEXT, data TEXT,
			PRIMARY KEY (job_id, path)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_binaries_job ON binaries(job_id)`,
		`CREATE TABLE IF NOT EXISTS scripts (
			job_id TEXT, path TEXT, data TEXT,
			PRIMARY KEY (job_id, path)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scripts_job ON scripts(job_id)`,
		`CREATE TABLE IF NOT EXISTS components (
			job_id TEXT, seq INTEGER, data TEXT,
			PRIMARY KEY (job_id, seq)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_components_job ON components(job_id)`,
		// Every file under the scanned target (FR-INV), not just the ELF
		// binaries/recognized scripts subset -- what actually answers "did
		// the scan cover this whole directory" for a human looking at results.
		`CREATE TABLE IF NOT EXISTS files (
			job_id TEXT, path TEXT, kind TEXT, data TEXT,
			PRIMARY KEY (job_id, path)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_files_job ON files(job_id)`,
	}
	for _, s := range stmts {
		if _, err := r.db.Exec(s); err != nil {
			return fmt.Errorf("migrate: %s: %w", s, err)
		}
	}

	// CREATE TABLE IF NOT EXISTS above only adds new columns for a brand new
	// database file; a database created before a column existed needs an
	// explicit ALTER TABLE. SQLite has no "ADD COLUMN IF NOT EXISTS", so
	// just ignore the "duplicate column" error a database that already has
	// it produces. Must run before idx_files_job_kind below -- that index
	// depends on the "kind" column existing, which for an upgraded (not
	// brand new) database is only true after this ALTER TABLE runs.
	alters := []string{
		`ALTER TABLE report_meta ADD COLUMN busybox_audit TEXT`,
		`ALTER TABLE files ADD COLUMN kind TEXT`,
		`ALTER TABLE report_meta ADD COLUMN cert_count INTEGER`,
		`ALTER TABLE report_meta ADD COLUMN rsa_cert_count INTEGER`,
		`ALTER TABLE report_meta ADD COLUMN services TEXT`,
	}
	for _, s := range alters {
		if _, err := r.db.Exec(s); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return fmt.Errorf("migrate: %s: %w", s, err)
		}
	}

	if _, err := r.db.Exec(`CREATE INDEX IF NOT EXISTS idx_files_job_kind ON files(job_id, kind)`); err != nil {
		return fmt.Errorf("migrate: create idx_files_job_kind: %w", err)
	}
	return nil
}

// Ingest parses one job's report.json and replaces any existing rows for
// jobID with its contents, applying triageOverlay (fingerprint id -> state)
// so a decision made on an earlier scan of the same content is immediately
// reflected rather than reverting to "new". Returns (binaries, findings,
// highCrit) counts, replacing the old file-based summarize().
func (r *ReportDB) Ingest(jobID string, reportJSON []byte, triageOverlay map[string]string) (bins, finds, highCrit int, err error) {
	var rep rawReport
	if err = json.Unmarshal(reportJSON, &rep); err != nil {
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tx, err := r.db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()

	if err = deleteJobRows(tx, jobID); err != nil {
		return
	}

	_, err = tx.Exec(`INSERT INTO report_meta
		(job_id, target, tool_version, generated_at, kernel_version, arch_summary, endian_summary, file_count, firmware_size, busybox_audit, cert_count, rsa_cert_count, services)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jobID, rep.Target, rep.ToolVersion, rep.GeneratedAt,
		rep.KernelVersion, rep.ArchSummary, rep.EndianSummary, rep.FileCount, rep.FirmwareSize,
		string(orEmptyObject(rep.BusyboxAudit)), rep.CertCount, rep.RsaCertCount,
		string(orEmptyArray(rep.Services)))
	if err != nil {
		return
	}

	// OR REPLACE, not a plain INSERT: Finding.fingerprint() (ifda/model.py) is
	// deliberately independent of severity/description so unrelated findings
	// that reduce to the same (rule, vuln_class, evidence, cve_ids) tuple are
	// meant to collapse onto one id -- e.g. cve-bin-tool occasionally reports
	// the same product/version/CVE via more than one detection path with
	// identical evidence. A real large scan hit exactly this (3000+ findings)
	// and the plain INSERT's PRIMARY KEY (job_id, id) violation crashed the
	// whole ingest instead of just keeping the last of the duplicate rows.
	findingStmt, err := tx.Prepare(`INSERT OR REPLACE INTO findings
		(job_id, id, title, vuln_class, severity, confidence, component, rule, description, remediation, cve_ids, evidence, triage, pseudocode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return
	}
	defer findingStmt.Close()

	for _, f := range rep.Findings {
		triage := f.Triage
		if st, ok := triageOverlay[f.ID]; ok {
			triage = st
		}
		if _, err = findingStmt.Exec(jobID, f.ID, f.Title, f.VulnClass, f.Severity, f.Confidence,
			f.Component, f.Rule, f.Description, f.Remediation,
			string(orEmptyArray(f.CVEIDs)), string(orEmptyArray(f.Evidence)), triage, f.Pseudocode); err != nil {
			return
		}
	}

	// OR REPLACE here too: same defensive reasoning as findings above, in
	// case a symlink/hardlink or an extraction quirk ever yields the same
	// path twice in one report.
	binStmt, err := tx.Prepare(`INSERT OR REPLACE INTO binaries (job_id, path, data) VALUES (?, ?, ?)`)
	if err != nil {
		return
	}
	defer binStmt.Close()
	for _, b := range rep.Binaries {
		path := jsonStringField(b, "path")
		if _, err = binStmt.Exec(jobID, path, string(b)); err != nil {
			return
		}
	}

	scriptStmt, err := tx.Prepare(`INSERT OR REPLACE INTO scripts (job_id, path, data) VALUES (?, ?, ?)`)
	if err != nil {
		return
	}
	defer scriptStmt.Close()
	for _, s := range rep.Scripts {
		path := jsonStringField(s, "path")
		if _, err = scriptStmt.Exec(jobID, path, string(s)); err != nil {
			return
		}
	}

	compStmt, err := tx.Prepare(`INSERT INTO components (job_id, seq, data) VALUES (?, ?, ?)`)
	if err != nil {
		return
	}
	defer compStmt.Close()
	for i, c := range rep.Components {
		if _, err = compStmt.Exec(jobID, i, string(c)); err != nil {
			return
		}
	}

	fileStmt, err := tx.Prepare(`INSERT OR REPLACE INTO files (job_id, path, kind, data) VALUES (?, ?, ?, ?)`)
	if err != nil {
		return
	}
	defer fileStmt.Close()
	for _, f := range rep.Files {
		path := jsonStringField(f, "path")
		kind := jsonStringField(f, "kind")
		if _, err = fileStmt.Exec(jobID, path, kind, string(f)); err != nil {
			return
		}
	}

	// Counted from the actual rows, not the loops above: OR REPLACE means a
	// duplicate id/path in the source report collapses to one row, and a
	// loop-iteration count would over-report relative to what's really there.
	if err = tx.QueryRow(`SELECT COUNT(*) FROM binaries WHERE job_id = ?`, jobID).Scan(&bins); err != nil {
		return
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM findings WHERE job_id = ?`, jobID).Scan(&finds); err != nil {
		return
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM findings WHERE job_id = ? AND severity IN ('critical','high')`, jobID).Scan(&highCrit); err != nil {
		return
	}

	err = tx.Commit()
	return
}

func orEmptyArray(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("[]")
	}
	return raw
}

func orEmptyObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

func jsonStringField(raw json.RawMessage, field string) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	var s string
	json.Unmarshal(m[field], &s)
	return s
}

func deleteJobRows(tx *sql.Tx, jobID string) error {
	for _, table := range []string{"report_meta", "findings", "binaries", "scripts", "components", "files"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE job_id = ?`, jobID); err != nil {
			return err
		}
	}
	return nil
}

// DeleteJob removes every row belonging to jobID (job deletion/cleanup).
func (r *ReportDB) DeleteJob(jobID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := deleteJobRows(tx, jobID); err != nil {
		return err
	}
	return tx.Commit()
}

// CopyJob duplicates every row from fromID to toID (dedup cache-hit path:
// the new job's target was byte-identical to a previously-completed one, so
// its results are too — copying keeps "every job owns its own report rows"
// true everywhere else in this file without a special-cased alias path).
func (r *ReportDB) CopyJob(fromID, toID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := deleteJobRows(tx, toID); err != nil {
		return err
	}
	stmts := []struct{ table, cols string }{
		{"report_meta", "target, tool_version, generated_at, kernel_version, arch_summary, endian_summary, file_count, firmware_size, busybox_audit, cert_count, rsa_cert_count, services"},
		{"findings", "id, title, vuln_class, severity, confidence, component, rule, description, remediation, cve_ids, evidence, triage, pseudocode"},
		{"binaries", "path, data"},
		{"scripts", "path, data"},
		{"components", "seq, data"},
		{"files", "path, kind, data"},
	}
	for _, s := range stmts {
		q := fmt.Sprintf(`INSERT INTO %s (job_id, %s) SELECT ?, %s FROM %s WHERE job_id = ?`,
			s.table, s.cols, s.cols, s.table)
		if _, err := tx.Exec(q, toID, fromID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Summary is the lightweight, always-fully-loaded aggregate the dashboard
// renders from, replacing client-side `findings.length`/`.filter().length`
// now that the full findings array isn't held in the browser anymore.
type Summary struct {
	Target        string         `json:"target"`
	ToolVersion   string         `json:"tool_version"`
	GeneratedAt   string         `json:"generated_at"`
	KernelVersion string         `json:"kernel_version"`
	ArchSummary   string         `json:"arch_summary"`
	EndianSummary string         `json:"endian_summary"`
	FileCount     int            `json:"file_count"`
	FirmwareSize  int64          `json:"firmware_size"`
	CertCount     int            `json:"cert_count"`
	RsaCertCount  int            `json:"rsa_cert_count"`
	Findings      int            `json:"findings"`
	Binaries      int            `json:"binaries"`
	Scripts       int            `json:"scripts"`
	Components    int            `json:"components"`
	BySeverity    map[string]int `json:"by_severity"`
	ByVulnClass   map[string]int `json:"by_vuln_class"`
	CVECount      int            `json:"cve_count"`
	ServiceCount  int            `json:"service_count"`
	OpenPortCount int            `json:"open_port_count"`
}

func (r *ReportDB) GetSummary(jobID string) (*Summary, error) {
	s := &Summary{BySeverity: map[string]int{}, ByVulnClass: map[string]int{}}
	row := r.db.QueryRow(`SELECT target, tool_version, generated_at, kernel_version, arch_summary,
		endian_summary, file_count, firmware_size, cert_count, rsa_cert_count, services FROM report_meta WHERE job_id = ?`, jobID)
	var kv, as, es, svc sql.NullString
	var fc, fs, cc, rcc sql.NullInt64
	if err := row.Scan(&s.Target, &s.ToolVersion, &s.GeneratedAt, &kv, &as, &es, &fc, &fs, &cc, &rcc, &svc); err != nil {
		if err == sql.ErrNoRows {
			return s, nil // report not ingested (yet) — empty summary, not an error
		}
		return nil, err
	}
	s.KernelVersion, s.ArchSummary, s.EndianSummary = kv.String, as.String, es.String
	s.FileCount, s.FirmwareSize = int(fc.Int64), fs.Int64
	s.CertCount, s.RsaCertCount = int(cc.Int64), int(rcc.Int64)
	if svc.Valid && svc.String != "" {
		var services []struct {
			Ports []int `json:"ports"`
		}
		if json.Unmarshal([]byte(svc.String), &services) == nil {
			s.ServiceCount = len(services)
			distinctPorts := map[int]struct{}{}
			for _, svc := range services {
				for _, p := range svc.Ports {
					distinctPorts[p] = struct{}{}
				}
			}
			s.OpenPortCount = len(distinctPorts)
		}
	}

	rows, err := r.db.Query(`SELECT severity, COUNT(*) FROM findings WHERE job_id = ? GROUP BY severity`, jobID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int
		if rows.Scan(&sev, &n) == nil {
			s.BySeverity[sev] = n
			s.Findings += n
		}
	}
	rows.Close()

	rows, err = r.db.Query(`SELECT vuln_class, COUNT(*) FROM findings WHERE job_id = ? GROUP BY vuln_class`, jobID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var vc string
		var n int
		if rows.Scan(&vc, &n) == nil {
			s.ByVulnClass[vc] = n
		}
	}
	rows.Close()

	r.db.QueryRow(`SELECT COUNT(*) FROM binaries WHERE job_id = ?`, jobID).Scan(&s.Binaries)
	r.db.QueryRow(`SELECT COUNT(*) FROM scripts WHERE job_id = ?`, jobID).Scan(&s.Scripts)
	r.db.QueryRow(`SELECT COUNT(*) FROM components WHERE job_id = ?`, jobID).Scan(&s.Components)
	// A finding "has a CVE" iff cve_ids is a non-empty JSON array ("[]" means none).
	r.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE job_id = ? AND cve_ids != '[]' AND cve_ids != ''`, jobID).Scan(&s.CVECount)

	return s, nil
}

// FindingQuery is the paginated/filtered findings request, mirroring what the
// findings tab's filter bar used to do entirely client-side.
type FindingQuery struct {
	Offset     int
	Limit      int
	NoLimit    bool     // export paths: return every matching row, not just one page
	Severities []string // empty = all
	VulnClass  string
	Triage     string
	MinConf    float64
	Q          string // free-text match against title/description/component
	Sort       string // "severity" | "confidence" | "component"
}

// ListFindings returns (page, total matching the filters) — total is what
// the frontend needs to render "page X of Y" / know when to stop paging.
func (r *ReportDB) ListFindings(jobID string, q FindingQuery) ([]map[string]any, int, error) {
	where := []string{"job_id = ?"}
	args := []any{jobID}

	if len(q.Severities) > 0 {
		ph := make([]string, len(q.Severities))
		for i, sev := range q.Severities {
			ph[i] = "?"
			args = append(args, sev)
		}
		where = append(where, "severity IN ("+strings.Join(ph, ",")+")")
	}
	if q.VulnClass != "" {
		where = append(where, "vuln_class = ?")
		args = append(args, q.VulnClass)
	}
	if q.Triage != "" {
		where = append(where, "triage = ?")
		args = append(args, q.Triage)
	}
	if q.MinConf > 0 {
		where = append(where, "confidence >= ?")
		args = append(args, q.MinConf)
	}
	if q.Q != "" {
		where = append(where, "(title LIKE ? OR description LIKE ? OR component LIKE ? OR cve_ids LIKE ? OR evidence LIKE ?)")
		like := "%" + q.Q + "%"
		args = append(args, like, like, like, like, like)
	}
	whereClause := strings.Join(where, " AND ")

	var total int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE `+whereClause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	orderBy := "component ASC"
	switch q.Sort {
	case "confidence":
		orderBy = "confidence DESC"
	case "severity":
		orderBy = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, confidence DESC`
	}

	query := `SELECT id, title, vuln_class, severity, confidence, component, rule,
		description, remediation, cve_ids, evidence, triage, pseudocode FROM findings
		WHERE ` + whereClause + ` ORDER BY ` + orderBy
	queryArgs := args
	if q.NoLimit {
		// Export paths (ExportFull, "export filtered" in the UI): every
		// matching row, however many there are -- no LIMIT clause at all,
		// not just a bigger one, since a firmware with thousands of
		// findings must not have its export silently truncated.
	} else {
		limit := q.Limit
		if limit <= 0 || limit > 1000 {
			limit = 100
		}
		query += ` LIMIT ? OFFSET ?`
		queryArgs = append(args, limit, q.Offset)
	}
	rows, err := r.db.Query(query, queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var id, title, vclass, sev, component, rule, desc, remediation, triage, pseudocode string
		var conf float64
		var cveIDs, evidence string
		if err := rows.Scan(&id, &title, &vclass, &sev, &conf, &component, &rule,
			&desc, &remediation, &cveIDs, &evidence, &triage, &pseudocode); err != nil {
			return nil, 0, err
		}
		m := map[string]any{
			"id": id, "title": title, "vuln_class": vclass, "severity": sev,
			"confidence": conf, "component": component, "rule": rule,
			"description": desc, "remediation": remediation, "triage": triage,
			"pseudocode": pseudocode,
		}
		m["cve_ids"] = json.RawMessage(cveIDs)
		m["evidence"] = json.RawMessage(evidence)
		out = append(out, m)
	}
	return out, total, nil
}

// SetTriageEverywhere updates every stored finding row (across all jobs)
// whose fingerprint id matches, so a triage decision applies uniformly
// across re-scans of the same content (FR-VUL-8) without needing a
// serve-time overlay pass anymore.
func (r *ReportDB) SetTriageEverywhere(findingID, state string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := r.db.Exec(`UPDATE findings SET triage = ? WHERE id = ?`, state, findingID)
	return err
}

func paginateRaw(db *sql.DB, table, jobID string, offset, limit int) ([]json.RawMessage, int, error) {
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE job_id = ?`, jobID).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	orderCol := "path"
	if table == "components" {
		orderCol = "seq"
	}
	rows, err := db.Query(`SELECT data FROM `+table+` WHERE job_id = ? ORDER BY `+orderCol+` LIMIT ? OFFSET ?`,
		jobID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, 0, err
		}
		out = append(out, json.RawMessage(data))
	}
	return out, total, nil
}

// listAllRaw returns every row for jobID in table, in one shot -- no LIMIT
// at all, unlike paginateRaw (which is for the interactive paginated views
// and caps out at 2000). Used only by ExportFull, where "export" has to mean
// every row however many there are.
func listAllRaw(db *sql.DB, table, jobID string) ([]json.RawMessage, error) {
	orderCol := "path"
	if table == "components" {
		orderCol = "seq"
	}
	rows, err := db.Query(`SELECT data FROM `+table+` WHERE job_id = ? ORDER BY `+orderCol, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(data))
	}
	return out, nil
}

func (r *ReportDB) ListBinaries(jobID string, offset, limit int) ([]json.RawMessage, int, error) {
	return paginateRaw(r.db, "binaries", jobID, offset, limit)
}

func (r *ReportDB) ListScripts(jobID string, offset, limit int) ([]json.RawMessage, int, error) {
	return paginateRaw(r.db, "scripts", jobID, offset, limit)
}

func (r *ReportDB) ListComponents(jobID string, offset, limit int) ([]json.RawMessage, int, error) {
	return paginateRaw(r.db, "components", jobID, offset, limit)
}

// ListFiles returns one page of the `files` table, optionally restricted to
// a single `kind` ("" = every kind). kind is its own column (extracted from
// each entry's JSON at Ingest, see jsonStringField(f, "kind") in Ingest)
// specifically so this is a plain indexed SQL WHERE, not a per-row JSON
// decode -- lets the Files tab's Kind filter (All/Binary/Script/Config/
// Symlink/Other) work without loading every row to filter client-side.
func (r *ReportDB) ListFiles(jobID, kind string, offset, limit int) ([]json.RawMessage, int, error) {
	where := "job_id = ?"
	args := []any{jobID}
	if kind != "" {
		where += " AND kind = ?"
		args = append(args, kind)
	}
	var total int
	if err := r.db.QueryRow(`SELECT COUNT(*) FROM files WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	rows, err := r.db.Query(`SELECT data FROM files WHERE `+where+` ORDER BY path LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, 0, err
		}
		out = append(out, json.RawMessage(data))
	}
	return out, total, nil
}

// ListFilesAll is ListFiles' "?all=1" counterpart: every matching row, no
// LIMIT at all (same "export must mean everything" reasoning as listAllRaw).
func (r *ReportDB) ListFilesAll(jobID, kind string) ([]json.RawMessage, error) {
	where := "job_id = ?"
	args := []any{jobID}
	if kind != "" {
		where += " AND kind = ?"
		args = append(args, kind)
	}
	rows, err := r.db.Query(`SELECT data FROM files WHERE `+where+` ORDER BY path`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		out = append(out, json.RawMessage(data))
	}
	return out, nil
}

// FileKnown reports whether path was recorded as one of jobID's scanned
// files (the `files` table, built from the full file listing) -- the Files
// tab's content-preview endpoint checks this before ever reading from disk,
// so a preview request can only ever read a path the scan itself already
// found and already exposed metadata (path/size/md5) for, not an arbitrary
// server-side path.
func (r *ReportDB) FileKnown(jobID, path string) (bool, error) {
	var one int
	err := r.db.QueryRow(`SELECT 1 FROM files WHERE job_id = ? AND path = ? LIMIT 1`, jobID, path).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetBinary returns one binary's full record (including its potentially
// large strings/functions arrays) by path, for the strings-tab drill-down —
// deliberately not part of the paginated list response, which callers should
// assume may omit or truncate large per-item fields in the future.
func (r *ReportDB) GetBinary(jobID, path string) (json.RawMessage, error) {
	var data string
	err := r.db.QueryRow(`SELECT data FROM binaries WHERE job_id = ? AND path = ?`, jobID, path).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// GetBusyboxAudit returns the busybox-applet audit + bin/sbin extra-command
// list + /etc/init.d script dump attached to this job's report (see
// ifda/inventory/busybox_audit.py) -- small and un-filtered, unlike
// findings/files, so it's always returned whole rather than paginated.
func (r *ReportDB) GetBusyboxAudit(jobID string) (json.RawMessage, error) {
	var data sql.NullString
	err := r.db.QueryRow(`SELECT busybox_audit FROM report_meta WHERE job_id = ?`, jobID).Scan(&data)
	if err == sql.ErrNoRows || !data.Valid || data.String == "" {
		return json.RawMessage("{}"), nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data.String), nil
}

// GetServices returns the identified network services (web/SSH/FTP/Telnet/
// SOAP/DNS/SNMP/UPnP/WiFi daemons -- see ifda/inventory/service_id.py) for
// one job, whole -- small enough (typically single digits to a few dozen
// entries) that, like busybox_audit, it never needed pagination.
func (r *ReportDB) GetServices(jobID string) (json.RawMessage, error) {
	var data sql.NullString
	err := r.db.QueryRow(`SELECT services FROM report_meta WHERE job_id = ?`, jobID).Scan(&data)
	if err == sql.ErrNoRows || !data.Valid || data.String == "" {
		return json.RawMessage("[]"), nil
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(data.String), nil
}

// ExportFull reconstructs the full AnalysisReport JSON shape (all rows, no
// pagination) for the download/export path (?format=json&download=1, plus
// the md/sbom renders which need the whole thing) — used rarely, unlike the
// interactive views above.
func (r *ReportDB) ExportFull(jobID string) ([]byte, error) {
	var meta struct {
		Target, ToolVersion, GeneratedAt          string
		KernelVersion, ArchSummary, EndianSummary sql.NullString
		FileCount                                 sql.NullInt64
		FirmwareSize                              sql.NullInt64
		BusyboxAudit                              sql.NullString
		CertCount, RsaCertCount                   sql.NullInt64
		Services                                  sql.NullString
	}
	err := r.db.QueryRow(`SELECT target, tool_version, generated_at, kernel_version, arch_summary,
		endian_summary, file_count, firmware_size, busybox_audit, cert_count, rsa_cert_count, services
		FROM report_meta WHERE job_id = ?`, jobID).Scan(
		&meta.Target, &meta.ToolVersion, &meta.GeneratedAt, &meta.KernelVersion, &meta.ArchSummary,
		&meta.EndianSummary, &meta.FileCount, &meta.FirmwareSize, &meta.BusyboxAudit,
		&meta.CertCount, &meta.RsaCertCount, &meta.Services)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no report for job %s", jobID)
	}
	if err != nil {
		return nil, err
	}

	// listAllRaw, not paginateRaw: paginateRaw caps its limit at 2000
	// (falling back to 500 above that) since it backs the interactive
	// paginated views, but a full export must mean *everything*, however
	// large the scan was -- a firmware with >500 binaries/scripts/files
	// would otherwise have its JSON export silently truncated.
	findings, _, err := r.ListFindings(jobID, FindingQuery{NoLimit: true})
	if err != nil {
		return nil, err
	}
	binaries, err := listAllRaw(r.db, "binaries", jobID)
	if err != nil {
		return nil, err
	}
	scripts, err := listAllRaw(r.db, "scripts", jobID)
	if err != nil {
		return nil, err
	}
	components, err := listAllRaw(r.db, "components", jobID)
	if err != nil {
		return nil, err
	}
	files, err := listAllRaw(r.db, "files", jobID)
	if err != nil {
		return nil, err
	}

	doc := map[string]any{
		"target":       meta.Target,
		"tool_version": meta.ToolVersion,
		"generated_at": meta.GeneratedAt,
		"binaries":     rawMessagesOrEmpty(binaries),
		"scripts":      rawMessagesOrEmpty(scripts),
		"components":   rawMessagesOrEmpty(components),
		"files":        rawMessagesOrEmpty(files),
		"findings":     findings,
	}
	if meta.BusyboxAudit.Valid && meta.BusyboxAudit.String != "" {
		doc["busybox_audit"] = json.RawMessage(meta.BusyboxAudit.String)
	}
	if meta.KernelVersion.Valid {
		doc["kernel_version"] = meta.KernelVersion.String
	}
	if meta.ArchSummary.Valid {
		doc["arch_summary"] = meta.ArchSummary.String
	}
	if meta.EndianSummary.Valid {
		doc["endian_summary"] = meta.EndianSummary.String
	}
	if meta.FileCount.Valid {
		doc["file_count"] = meta.FileCount.Int64
	}
	if meta.FirmwareSize.Valid {
		doc["firmware_size"] = meta.FirmwareSize.Int64
	}
	if meta.CertCount.Valid {
		doc["cert_count"] = meta.CertCount.Int64
	}
	if meta.RsaCertCount.Valid {
		doc["rsa_cert_count"] = meta.RsaCertCount.Int64
	}
	if meta.Services.Valid && meta.Services.String != "" {
		doc["services"] = json.RawMessage(meta.Services.String)
	}
	return json.Marshal(doc)
}

func rawMessagesOrEmpty(v []json.RawMessage) []json.RawMessage {
	if v == nil {
		return []json.RawMessage{}
	}
	return v
}
