package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// API exposes the REST surface (FR-INT-1) over the store + worker.
type API struct {
	store      *Store
	worker     *Worker
	triage     *TriageStore
	reportDB   *ReportDB
	uploadDir  string
	coreDir    string        // repo root containing the ifda package (for static reference data like vuln_db.json)
	ghidra     bool          // whether the core's Ghidra decompile enrichment is usable
	authStore  *AuthStore    // nil means login is disabled
	captcha    *CaptchaStore // only meaningful when authStore != nil
	aiKey      []byte        // local key encrypting AI provider API keys at rest, see aicrypto.go
	httpClient *http.Client  // shared outbound client for calling AI providers

	// aiRuns tracks which jobs currently have an analysis streaming, so a
	// second concurrent run on the same job is refused rather than allowed
	// to interleave its partial-content writes with the first one's (both
	// write the whole accumulated text to the same row every ~500ms, so
	// two in flight would leave the stored content flapping between two
	// different partial transcripts). Process-local, which is the right
	// scope: it guards the writers, and the writers live in this process.
	aiRunsMu sync.Mutex
	aiRuns   map[string]bool
}

// beginAIRun claims the analysis slot for jobID, reporting false if one is
// already in flight. Every successful claim must be paired with endAIRun.
func (a *API) beginAIRun(jobID string) bool {
	a.aiRunsMu.Lock()
	defer a.aiRunsMu.Unlock()
	if a.aiRuns[jobID] {
		return false
	}
	if a.aiRuns == nil {
		a.aiRuns = map[string]bool{}
	}
	a.aiRuns[jobID] = true
	return true
}

func (a *API) endAIRun(jobID string) {
	a.aiRunsMu.Lock()
	defer a.aiRunsMu.Unlock()
	delete(a.aiRuns, jobID)
}

func NewAPI(store *Store, worker *Worker, triage *TriageStore, reportDB *ReportDB, uploadDir, coreDir string, ghidra bool, authStore *AuthStore, aiKey []byte) *API {
	return &API{store: store, worker: worker, triage: triage, reportDB: reportDB, uploadDir: uploadDir, coreDir: coreDir, ghidra: ghidra,
		authStore: authStore, captcha: NewCaptchaStore(), aiKey: aiKey, httpClient: newAIHTTPClient(),
		aiRuns: map[string]bool{}}
}

// newAIHTTPClient builds the outbound client used for AI provider calls.
//
// Deliberately NOT http.Client{Timeout: ...}: that field bounds the whole
// request lifecycle *including reading the response body*, which for a
// streaming completion means the entire generation has to finish inside it
// or the stream is severed mid-sentence. A long findings-triage narrative
// at the current max_tokens default routinely takes several minutes at
// typical generation speeds, so a whole-request deadline is exactly the
// wrong shape here (an earlier 120s Timeout did cut real analyses off, and
// reported it as "provider did not respond in time" even though the
// provider had been streaming perfectly well the entire time).
//
// What actually needs bounding is a provider that accepts the connection
// and then says nothing -- so the limits are per-phase (connect / TLS /
// response headers) plus an idle-between-chunks limit, all of which leave
// a healthily-streaming response free to take as long as it legitimately
// needs. Overall cancellation still works: every request is built with
// r.Context(), so a browser disconnect aborts the upstream call promptly.
func newAIHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: aiResponseHeaderTimeout,
			// Guards the gap *between* streamed chunks, not the total
			// duration -- a stalled stream still fails, a slow-but-alive
			// one doesn't.
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}
}

// aiResponseHeaderTimeout bounds how long a provider may take to start
// responding (send headers) before we give up. Generous enough to absorb
// queueing/cold-start on a busy gateway, but far short of the multi-minute
// span a long generation may legitimately occupy once it has started.
const aiResponseHeaderTimeout = 90 * time.Second

// auth wraps a handler to require a valid session when login is enabled.
// /healthz and /api/login stay open; every other /api/* route that can read
// or mutate server state goes through this. Accepts the session token either
// as `Authorization: Bearer <token>` (used by fetch() calls) or `?token=`
// (needed for EventSource and plain <a href> download links, neither of
// which can set a custom header).
func (a *API) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.authStore == nil {
			next(w, r)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if _, ok := a.authStore.Check(got); !ok {
			writeErr(w, http.StatusUnauthorized, "login required")
			return
		}
		next(w, r)
	}
}

func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/captcha", a.getCaptcha)
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.logout)
	mux.HandleFunc("POST /api/change-password", a.changePassword)
	mux.HandleFunc("POST /api/jobs", a.auth(a.createJob))
	mux.HandleFunc("GET /api/jobs", a.auth(a.listJobs))
	mux.HandleFunc("GET /api/jobs/{id}", a.auth(a.getJob))
	mux.HandleFunc("GET /api/jobs/{id}/report", a.auth(a.getReport))
	mux.HandleFunc("GET /api/jobs/{id}/summary", a.auth(a.getSummary))
	mux.HandleFunc("GET /api/jobs/{id}/findings", a.auth(a.getFindings))
	mux.HandleFunc("GET /api/jobs/{id}/binaries", a.auth(a.getBinaries))
	mux.HandleFunc("GET /api/jobs/{id}/binary", a.auth(a.getBinary))
	mux.HandleFunc("GET /api/jobs/{id}/scripts", a.auth(a.getScripts))
	mux.HandleFunc("GET /api/jobs/{id}/components", a.auth(a.getComponents))
	mux.HandleFunc("GET /api/jobs/{id}/files", a.auth(a.getFiles))
	mux.HandleFunc("GET /api/jobs/{id}/file-content", a.auth(a.getFileContent))
	mux.HandleFunc("GET /api/jobs/{id}/busybox", a.auth(a.getBusyboxAudit))
	mux.HandleFunc("GET /api/jobs/{id}/services", a.auth(a.getServices))
	mux.HandleFunc("GET /api/jobs/{id}/events", a.auth(a.events))
	mux.HandleFunc("POST /api/jobs/{id}/triage", a.auth(a.setTriage))
	mux.HandleFunc("POST /api/jobs/{id}/pause", a.auth(a.pauseJob))
	mux.HandleFunc("POST /api/jobs/{id}/resume", a.auth(a.resumeJob))
	mux.HandleFunc("POST /api/jobs/{id}/stop", a.auth(a.stopJob))
	mux.HandleFunc("DELETE /api/jobs/{id}", a.auth(a.deleteJob))
	mux.HandleFunc("POST /api/jobs/batch-delete", a.auth(a.batchDeleteJobs))
	mux.HandleFunc("GET /api/triage/history", a.auth(a.triageHistory))
	mux.HandleFunc("GET /api/vulndb", a.auth(a.getVulnDB))
	mux.HandleFunc("POST /api/upload", a.auth(a.upload))
	mux.HandleFunc("GET /api/ai/providers", a.auth(a.listAIProviders))
	mux.HandleFunc("POST /api/ai/providers", a.auth(a.createAIProvider))
	mux.HandleFunc("PUT /api/ai/providers/{id}", a.auth(a.updateAIProvider))
	mux.HandleFunc("DELETE /api/ai/providers/{id}", a.auth(a.deleteAIProvider))
	mux.HandleFunc("POST /api/ai/models", a.auth(a.fetchAIModels))
	mux.HandleFunc("GET /api/jobs/{id}/ai-analysis", a.auth(a.getAIAnalysis))
	mux.HandleFunc("POST /api/jobs/{id}/ai-analysis", a.auth(a.runAIAnalysis))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ghidra_available": a.ghidra, "login_required": a.authStore != nil})
	})
}

// getCaptcha issues a fresh challenge. The login form fetches one on load
// and again after every failed attempt (each is one-time-use).
func (a *API) getCaptcha(w http.ResponseWriter, r *http.Request) {
	id, img := a.captcha.New()
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "image": img})
}

type loginReq struct {
	Username      string `json:"username"`
	Password      string `json:"password"`
	CaptchaID     string `json:"captcha_id"`
	CaptchaAnswer string `json:"captcha_answer"`
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	if a.authStore == nil {
		writeErr(w, http.StatusBadRequest, "login is not enabled on this server")
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	// Checked before touching credentials at all: a script that doesn't solve
	// the captcha never gets to try a password, and a solved-but-wrong
	// captcha still consumes it (one-time use) so it can't be replayed.
	if !a.captcha.Verify(req.CaptchaID, req.CaptchaAnswer) {
		writeErr(w, http.StatusBadRequest, "incorrect captcha")
		return
	}
	if wait, locked := a.authStore.Locked(req.Username); locked {
		writeErr(w, http.StatusTooManyRequests,
			fmt.Sprintf("too many failed attempts; try again in %d seconds", int(wait.Seconds())+1))
		return
	}
	session, ok := a.authStore.Login(req.Username, req.Password)
	if !ok {
		a.authStore.RecordFailure(req.Username)
		writeErr(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	a.authStore.RecordSuccess(req.Username)
	writeJSON(w, http.StatusOK, map[string]string{"session": session, "username": req.Username})
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	if a.authStore == nil {
		writeErr(w, http.StatusBadRequest, "login is not enabled on this server")
		return
	}
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	username, ok := a.authStore.Check(got)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "login required")
		return
	}
	var req changePasswordReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if len(req.NewPassword) < 8 {
		writeErr(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}
	if !a.authStore.verify(username, req.OldPassword) {
		writeErr(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	a.authStore.SetPassword(username, req.NewPassword)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if a.authStore != nil {
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		a.authStore.Logout(got)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type createReq struct {
	Target    string `json:"target"`
	Decompile bool   `json:"decompile"`
}

func (a *API) createJob(w http.ResponseWriter, r *http.Request) {
	var req createReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	req.Target = strings.TrimSpace(req.Target)
	if req.Target == "" {
		writeErr(w, http.StatusBadRequest, "target is required")
		return
	}
	if _, err := os.Stat(req.Target); err != nil {
		writeErr(w, http.StatusBadRequest, "target not found on the server filesystem: "+req.Target)
		return
	}
	job := a.store.Create(req.Target, req.Decompile)
	a.worker.Submit(job)
	writeJSON(w, http.StatusAccepted, job)
}

func (a *API) listJobs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.List())
}

func (a *API) getJob(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// getReport serves the findings report, with triage decisions overlaid. The
// ?format= query selects json (default), md, or sbom for download/export.
func (a *API) getReport(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted || job.reportPath == "" {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	switch r.URL.Query().Get("format") {
	case "md", "markdown":
		serveFile(w, job.mdPath, "text/markdown; charset=utf-8",
			"ifda-"+job.ID+".md")
	case "sbom":
		serveFile(w, job.sbomPath, "application/json",
			"ifda-"+job.ID+".sbom.json")
	default:
		// Full-document export only (download link) — the interactive UI
		// uses /summary + the paginated /findings, /binaries, /scripts,
		// /components endpoints below instead of ever loading this at once.
		data, err := a.reportDB.ExportFull(job.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "report unavailable: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("download") != "" {
			w.Header().Set("Content-Disposition",
				`attachment; filename="ifda-`+job.ID+`.json"`)
		}
		w.Write(data)
	}
}

// getSummary is the lightweight, always-fully-loaded aggregate the dashboard
// renders from (counts by severity/vuln-class, totals) — safe to load in
// full regardless of how large the underlying scan was.
func (a *API) getSummary(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	summary, err := a.reportDB.GetSummary(job.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// getFindings serves one page of findings, filtered/sorted server-side —
// replacing the old approach of shipping every finding to the browser and
// filtering with Alpine reactivity, which is what crashed the tab on a scan
// with thousands of findings.
//
// Query params: offset, limit, sev (repeatable), vclass, triage, min_conf, q,
// sort, all (all=1 returns every matching row with no LIMIT at all — for the
// "export filtered" buttons, which must mean *every* match, not just a page).
func (a *API) getFindings(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	q := r.URL.Query()
	minConf, _ := strconv.ParseFloat(q.Get("min_conf"), 64)
	fq := FindingQuery{
		Offset:     atoiDefault(q.Get("offset"), 0),
		Limit:      atoiDefault(q.Get("limit"), 100),
		NoLimit:    q.Get("all") == "1",
		Severities: q["sev"],
		VulnClass:  q.Get("vclass"),
		Triage:     q.Get("triage"),
		MinConf:    minConf,
		Q:          q.Get("q"),
		Sort:       q.Get("sort"),
	}
	items, total, err := a.reportDB.ListFindings(job.ID, fq)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": itemsOrEmpty(items), "total": total, "offset": fq.Offset, "limit": fq.Limit,
	})
}

func (a *API) getBinaries(w http.ResponseWriter, r *http.Request) {
	a.pagedList(w, r, "binaries", func(jobID string, offset, limit int) ([]json.RawMessage, int, error) {
		return a.reportDB.ListBinaries(jobID, offset, limit)
	})
}

func (a *API) getScripts(w http.ResponseWriter, r *http.Request) {
	a.pagedList(w, r, "scripts", func(jobID string, offset, limit int) ([]json.RawMessage, int, error) {
		return a.reportDB.ListScripts(jobID, offset, limit)
	})
}

func (a *API) getComponents(w http.ResponseWriter, r *http.Request) {
	a.pagedList(w, r, "components", func(jobID string, offset, limit int) ([]json.RawMessage, int, error) {
		return a.reportDB.ListComponents(jobID, offset, limit)
	})
}

// getFiles serves one page of the files table, like the other pagedList-
// backed endpoints, but doesn't go through pagedList itself: it's the only
// one of the four with a server-side filter (?kind=), so it needs its own
// ListFiles/ListFilesAll pair rather than the generic table-name-only
// list()/listAllRaw() signature the others share.
func (a *API) getFiles(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	q := r.URL.Query()
	kind := q.Get("kind")
	if q.Get("all") == "1" {
		items, err := a.reportDB.ListFilesAll(job.ID, kind)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": rawItemsOrEmpty(items), "total": len(items), "offset": 0, "limit": len(items),
		})
		return
	}
	offset := atoiDefault(q.Get("offset"), 0)
	limit := atoiDefault(q.Get("limit"), 500)
	items, total, err := a.reportDB.ListFiles(job.ID, kind, offset, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": rawItemsOrEmpty(items), "total": total, "offset": offset, "limit": limit,
	})
}

// filePreviewCap bounds how much of a file the Files tab's preview reads --
// generous for a config/script (the only kinds the UI offers preview for)
// while not letting a request against a mislabeled multi-GB "other" file
// block a worker goroutine reading it into memory.
const filePreviewCap = 256 * 1024

// getFileContent serves one file's raw content for the Files tab's preview
// (config files, shell scripts, ...) on demand -- not baked into the report
// at scan time, which would bloat storage for the thousands of files most
// scans have and nobody ever opens. Reads directly from the original
// scanned target on disk, so it only works as long as that tree is still
// there, the same assumption re-scanning/the dedup cache already makes.
func (a *API) getFileContent(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}
	// Only a path the scan itself already recorded for this job is
	// readable here -- never an arbitrary server-side path a caller might
	// otherwise be able to pass in.
	known, err := a.reportDB.FileKnown(job.ID, path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !known {
		writeErr(w, http.StatusNotFound, "not a file recorded for this job's scan")
		return
	}
	content, truncated, err := readFilePreview(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError,
			"could not read file (it may have moved or been deleted since scanning): "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"content": content, "truncated": truncated})
}

// readFilePreview reads up to filePreviewCap bytes of path, refusing
// anything that isn't a plain regular file -- the same "never open a device
// node/FIFO/socket" rule every reader in the Python core already follows,
// here so a preview request can't be used to block on e.g. /dev/console.
func readFilePreview(path string) (content string, truncated bool, err error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", false, err
	}
	if !fi.Mode().IsRegular() {
		return "", false, fmt.Errorf("not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	buf := make([]byte, filePreviewCap+1)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return "", false, err
	}
	truncated = n > filePreviewCap
	if truncated {
		n = filePreviewCap
	}
	return string(buf[:n]), truncated, nil
}

// getBusyboxAudit serves the busybox-applet audit + bin/sbin extra-command
// list + /etc/init.d script dump whole (see ReportDB.GetBusyboxAudit) --
// small enough that, unlike findings/files, it never needed pagination.
func (a *API) getBusyboxAudit(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	data, err := a.reportDB.GetBusyboxAudit(job.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// getServices serves the identified network services (web/SSH/FTP/Telnet/
// SOAP/DNS/SNMP/UPnP/WiFi daemons) whole (see ReportDB.GetServices) — small
// enough that, like busybox_audit, it never needed pagination.
func (a *API) getServices(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	data, err := a.reportDB.GetServices(job.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// pagedList serves one page of table's rows, or (with ?all=1) every row —
// same "export must mean everything" reasoning as getFindings' `all` param:
// a firmware with more files/binaries than the normal page-size cap would
// otherwise have its listing silently truncated.
func (a *API) pagedList(w http.ResponseWriter, r *http.Request, table string, list func(jobID string, offset, limit int) ([]json.RawMessage, int, error)) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	if job.Status != StatusCompleted {
		writeErr(w, http.StatusConflict, "report not ready (job "+string(job.Status)+")")
		return
	}
	q := r.URL.Query()
	if q.Get("all") == "1" {
		items, err := listAllRaw(a.reportDB.db, table, job.ID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": rawItemsOrEmpty(items), "total": len(items), "offset": 0, "limit": len(items),
		})
		return
	}
	offset := atoiDefault(q.Get("offset"), 0)
	limit := atoiDefault(q.Get("limit"), 500)
	items, total, err := list(job.ID, offset, limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": rawItemsOrEmpty(items), "total": total, "offset": offset, "limit": limit,
	})
}

// getBinary returns one binary's full record (including its potentially
// large strings/functions arrays) by path (?path=), for the strings-tab
// drill-down from the (deliberately lighter) paginated binaries list.
func (a *API) getBinary(w http.ResponseWriter, r *http.Request) {
	job, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	path := r.URL.Query().Get("path")
	if path == "" {
		writeErr(w, http.StatusBadRequest, "path is required")
		return
	}
	data, err := a.reportDB.GetBinary(job.ID, path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if data == nil {
		writeErr(w, http.StatusNotFound, "binary not found in this report")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func itemsOrEmpty(v []map[string]any) []map[string]any {
	if v == nil {
		return []map[string]any{}
	}
	return v
}

func rawItemsOrEmpty(v []json.RawMessage) []json.RawMessage {
	if v == nil {
		return []json.RawMessage{}
	}
	return v
}

type triageReq struct {
	FindingID string `json:"finding_id"`
	State     string `json:"state"`
	Actor     string `json:"actor,omitempty"`
}

func (a *API) setTriage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.store.Get(r.PathValue("id")); !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	var req triageReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if !a.triage.Set(req.FindingID, req.State, strings.TrimSpace(req.Actor)) {
		writeErr(w, http.StatusBadRequest,
			"invalid finding_id or state (new|confirmed|false_positive|accepted_risk)")
		return
	}
	// Applies across every job whose findings include this fingerprint id
	// (FR-VUL-8: a decision persists across re-scans of the same content),
	// so SQL stays the single source of truth for future paginated reads
	// instead of needing a serve-time overlay pass.
	if err := a.reportDB.SetTriageEverywhere(req.FindingID, req.State); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"finding_id": req.FindingID, "state": req.State})
}

// triageHistory returns the full triage audit log, optionally filtered to one
// finding via ?finding_id=, newest first.
func (a *API) triageHistory(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.triage.History(r.URL.Query().Get("finding_id")))
}

// getVulnDB reports what CVE-correlation coverage actually is (FR-VUL-1):
// the small curated offline DB (ifda/data/vuln_db.json) plus, since
// cve-bin-tool is now a required dependency, its own much broader checker
// set (350+ components across NVD/OSV/RedHat/GitLab Advisory/Curl) — so the
// web UI doesn't imply coverage is only the curated DB's handful of entries.
// Shells out to `python3 -m ifda.cli vulndb`, which just introspects the
// installed cve-bin-tool package (no network, no live scan) — fast, so no
// caching needed.
func (a *API) getVulnDB(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-m", "ifda.cli", "vulndb")
	cmd.Dir = a.coreDir
	out, err := cmd.Output()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "vulndb unavailable: "+err.Error())
		return
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(out, &doc); err != nil {
		writeErr(w, http.StatusInternalServerError, "vulndb output is not valid JSON")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (a *API) pauseJob(w http.ResponseWriter, r *http.Request) {
	a.controlJob(w, r, a.store.Pause)
}

func (a *API) resumeJob(w http.ResponseWriter, r *http.Request) {
	a.controlJob(w, r, a.store.Resume)
}

func (a *API) stopJob(w http.ResponseWriter, r *http.Request) {
	a.controlJob(w, r, a.store.Cancel)
}

func (a *API) deleteJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := a.store.Delete(id)
	switch {
	case err == nil:
		a.reportDB.DeleteJob(id)
		writeJSON(w, http.StatusOK, map[string]string{"id": id})
	case errors.Is(err, ErrJobNotFound):
		writeErr(w, http.StatusNotFound, "job not found")
	case errors.Is(err, ErrInvalidState):
		writeErr(w, http.StatusConflict, "job is still active; stop it first")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

type batchDeleteReq struct {
	IDs []string `json:"ids"`
}

// batchDeleteJobs deletes several jobs in one call. Per-id, not all-or-nothing:
// each id gets its own result so a still-active job in the batch (refused)
// doesn't block deleting the rest.
func (a *API) batchDeleteJobs(w http.ResponseWriter, r *http.Request) {
	var req batchDeleteReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	results := make(map[string]string, len(req.IDs))
	for _, id := range req.IDs {
		if err := a.store.Delete(id); err != nil {
			results[id] = err.Error()
		} else {
			a.reportDB.DeleteJob(id)
			results[id] = "deleted"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (a *API) controlJob(w http.ResponseWriter, r *http.Request, action func(string) error) {
	id := r.PathValue("id")
	err := action(id)
	switch {
	case err == nil:
		job, _ := a.store.Get(id)
		writeJSON(w, http.StatusOK, job)
	case errors.Is(err, ErrJobNotFound):
		writeErr(w, http.StatusNotFound, "job not found")
	case errors.Is(err, ErrInvalidState):
		writeErr(w, http.StatusConflict, "job is not in a state that allows this action")
	default:
		writeErr(w, http.StatusInternalServerError, err.Error())
	}
}

// events streams job progress as Server-Sent Events until the job is terminal,
// so the UI updates live without client polling.
func (a *API) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming unsupported")
		return
	}
	id := r.PathValue("id")
	if _, ok := a.store.Get(id); !ok {
		writeErr(w, http.StatusNotFound, "job not found")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()
	last := ""
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			job, ok := a.store.Get(id)
			if !ok {
				return
			}
			snap := fmt.Sprintf("%s|%d|%s", job.Status, job.Progress, job.Stage)
			if snap != last {
				last = snap
				b, _ := json.Marshal(job)
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			}
			if job.Status == StatusCompleted || job.Status == StatusFailed || job.Status == StatusCancelled {
				return
			}
		}
	}
}

// upload stores an uploaded artifact server-side and returns its path, which the
// client then submits as a job target. Extraction (FR-EXT) is out of scope here.
func (a *API) upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(256 << 20); err != nil { // 256 MiB
		writeErr(w, http.StatusBadRequest, "could not parse upload")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "missing 'file' field")
		return
	}
	defer file.Close()

	if err := os.MkdirAll(a.uploadDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "upload dir unavailable")
		return
	}
	safe := filepath.Base(hdr.Filename)
	if safe == "" || safe == "." || safe == "/" {
		safe = "upload.bin"
	}
	dst := filepath.Join(a.uploadDir, fmt.Sprintf("%d-%s", time.Now().UnixNano(), safe))
	out, err := os.Create(dst)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not store upload")
		return
	}
	defer out.Close()
	if _, err := io.Copy(out, file); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not write upload")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"target": dst, "name": safe})
}

func serveFile(w http.ResponseWriter, path, ctype, filename string) {
	data, err := os.ReadFile(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "file not available")
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Write(data)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
