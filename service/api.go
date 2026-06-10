package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
}

func NewAPI(store *Store, worker *Worker, triage *TriageStore, uploadDir string) *API {
	return &API{store: store, worker: worker, triage: triage, uploadDir: uploadDir}
}

func (a *API) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/jobs", a.createJob)
	mux.HandleFunc("GET /api/jobs", a.listJobs)
	mux.HandleFunc("GET /api/jobs/{id}", a.getJob)
	mux.HandleFunc("GET /api/jobs/{id}/report", a.getReport)
	mux.HandleFunc("GET /api/jobs/{id}/events", a.events)
	mux.HandleFunc("POST /api/jobs/{id}/triage", a.setTriage)
	mux.HandleFunc("POST /api/upload", a.upload)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

type createReq struct {
	Target string `json:"target"`
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
	job := a.store.Create(req.Target)
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
	if !a.triage.Set(req.FindingID, req.State) {
		writeErr(w, http.StatusBadRequest,
			"invalid finding_id or state (new|confirmed|false_positive|accepted_risk)")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"finding_id": req.FindingID, "state": req.State})
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
			if job.Status == StatusCompleted || job.Status == StatusFailed {
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
