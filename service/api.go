package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// API exposes the REST surface (FR-INT-1) over the store + worker.
type API struct {
	store     *Store
	worker    *Worker
	triage    *TriageStore
	uploadDir string
	coreDir   string        // repo root containing the ifda package (for static reference data like vuln_db.json)
	ghidra    bool          // whether the core's Ghidra decompile enrichment is usable
	authStore *AuthStore    // nil means login is disabled
	captcha   *CaptchaStore // only meaningful when authStore != nil
}

func NewAPI(store *Store, worker *Worker, triage *TriageStore, uploadDir, coreDir string, ghidra bool, authStore *AuthStore) *API {
	return &API{store: store, worker: worker, triage: triage, uploadDir: uploadDir, coreDir: coreDir, ghidra: ghidra,
		authStore: authStore, captcha: NewCaptchaStore()}
}

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
		data, err := os.ReadFile(job.reportPath)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "report file unavailable")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("download") != "" {
			w.Header().Set("Content-Disposition",
				`attachment; filename="ifda-`+job.ID+`.json"`)
		}
		w.Write(a.triage.Overlay(data))
	}
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
