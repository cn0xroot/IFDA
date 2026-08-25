package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dir_breakdown/dir_chart_renderer are stored as opaque JSON/text columns
// (see rawReport.DirBreakdown, mirroring the cert_count pattern) -- this
// confirms they round-trip through Ingest -> GetSummary/ExportFull intact,
// the same shape ifda/inventory/firmware_meta.py's top_level_dir_breakdown()
// and ifda/report/piechart.py's render_dir_pie_chart() produce.
func TestDirBreakdownRoundTrip(t *testing.T) {
	db, err := NewReportDB(filepath.Join(t.TempDir(), "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	reportJSON := []byte(`{
		"target": "/fw", "tool_version": "test", "generated_at": "now",
		"binaries": [], "scripts": [], "components": [], "findings": [],
		"dir_breakdown": [
			{"name": "/usr", "bytes": 800, "pct": 80.0},
			{"name": "/etc", "bytes": 200, "pct": 20.0}
		],
		"dir_chart_renderer": "cuda"
	}`)
	if _, _, _, err := db.Ingest("job-1", reportJSON, nil); err != nil {
		t.Fatal(err)
	}

	summary, err := db.GetSummary("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if summary.DirChartRenderer != "cuda" {
		t.Errorf("DirChartRenderer = %q, want %q", summary.DirChartRenderer, "cuda")
	}
	if !strings.Contains(string(summary.DirBreakdown), `"/usr"`) || !strings.Contains(string(summary.DirBreakdown), `"/etc"`) {
		t.Errorf("DirBreakdown missing expected entries: %s", summary.DirBreakdown)
	}

	full, err := db.ExportFull("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(full), `"dir_chart_renderer":"cuda"`) {
		t.Errorf("ExportFull does not include dir_chart_renderer: %s", full)
	}
}

// A job ingested before dir_breakdown/dir_chart_renderer existed (or a
// report that simply omits them, e.g. a single-file target with no rootfs
// to break down) must degrade to an empty array / empty string, not error.
func TestDirBreakdownDefaultsToEmpty(t *testing.T) {
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
	if summary.DirChartRenderer != "" {
		t.Errorf("DirChartRenderer = %q, want empty", summary.DirChartRenderer)
	}
	if strings.TrimSpace(string(summary.DirBreakdown)) != "[]" {
		t.Errorf("DirBreakdown = %s, want []", summary.DirBreakdown)
	}
}

// getDirChart is the <img>-facing endpoint (no Content-Disposition, unlike
// the download-oriented getReport/getBinaries) -- confirms it serves the
// exact PNG bytes ifda/report/piechart.py wrote to job.chartPath, with the
// right content type, and that an incomplete job is a 409 (not a confusing
// 404 for a file that will exist once the job finishes).
func TestGetDirChartServesPNG(t *testing.T) {
	api, store, _ := newTestAPI(t)

	pngBytes := []byte("\x89PNG\r\n\x1a\nnot a real PNG but fine for byte-equality")
	chartPath := filepath.Join(t.TempDir(), "dirchart.png")
	if err := os.WriteFile(chartPath, pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	job := store.Create("/fw", false)
	store.update(job.ID, func(j *Job) {
		j.Status = StatusCompleted
		j.chartPath = chartPath
	})

	req := httptest.NewRequest(http.MethodGet, "/api/jobs/"+job.ID+"/dir-chart", nil)
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.getDirChart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); cd != "" {
		t.Errorf("Content-Disposition = %q, want empty (inline display, not a download)", cd)
	}
	if w.Body.String() != string(pngBytes) {
		t.Errorf("body = %q, want %q", w.Body.String(), pngBytes)
	}
}

func TestGetDirChartNotReady(t *testing.T) {
	api, store, _ := newTestAPI(t)
	job := store.Create("/fw", false) // default status: queued, no chartPath yet

	req := httptest.NewRequest(http.MethodGet, "/api/jobs/"+job.ID+"/dir-chart", nil)
	req.SetPathValue("id", job.ID)
	w := httptest.NewRecorder()
	api.getDirChart(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d; body=%s", w.Code, http.StatusConflict, w.Body.String())
	}
}

// renderPieChart is the stateless, on-demand chart endpoint the compare-scan
// function-diff visualization uses (the diff itself runs client-side over
// two already-fetched reports, so there's no job to attach a stored PNG to
// -- see the comment on the handler). Confirms it actually shells out to
// `python3 -m ifda.cli chart` and returns a real PNG; skipped where python3
// or the ifda package isn't available (e.g. a bare CI runner).
func TestRenderPieChart(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	coreDir := findCoreDir()
	if coreDir == "" {
		t.Skip("ifda core dir not found from test cwd")
	}

	api, _, _ := newTestAPI(t)
	api.coreDir = coreDir

	body := `{"slices":[{"name":"unchanged","value":40},{"name":"modified","value":5},{"name":"added","value":3},{"name":"removed","value":1}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/chart/pie", strings.NewReader(body))
	w := httptest.NewRecorder()
	api.renderPieChart(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "image/png" {
		t.Errorf("Content-Type = %q, want image/png", ct)
	}
	if !bytes.HasPrefix(w.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
		t.Errorf("body does not start with a PNG signature (%d bytes)", w.Body.Len())
	}
}

func TestRenderPieChartRejectsEmptySlices(t *testing.T) {
	api, _, _ := newTestAPI(t)
	req := httptest.NewRequest(http.MethodPost, "/api/chart/pie", strings.NewReader(`{"slices":[]}`))
	w := httptest.NewRecorder()
	api.renderPieChart(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}
