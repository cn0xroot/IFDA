package main

import (
	"archive/tar"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTestTar builds a tiny, self-contained tar archive moria can actually
// identify and extract -- avoids depending on any local firmware fixture.
func writeTestTar(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	defer tw.Close()
	content := []byte("hello moria")
	if err := tw.WriteHeader(&tar.Header{Name: "hello.txt", Size: int64(len(content)), Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
}

// End-to-end "extract" job through the real Worker: a real moria subprocess
// (skipped if not installed), real @@IFDA@@ progress streaming, real
// job.Regions population from ifda/ingest's merged region JSON. Exercises
// the same runExtract/runSubprocess code path production traffic hits.
func TestExtractJobRealMoria(t *testing.T) {
	if _, err := exec.LookPath("moria"); err != nil {
		t.Skip("moria not installed")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	coreDir := findCoreDir()
	if coreDir == "" {
		t.Skip("ifda core dir not found from test cwd")
	}

	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "jobs"), "test")
	if err != nil {
		t.Fatal(err)
	}
	reportDB, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	triage := NewTriageStore(filepath.Join(dir, "triage.json"))
	worker := NewWorker(store, coreDir, 1, 4, reportDB, triage, 30*time.Second)

	tarPath := filepath.Join(dir, "test.tar")
	writeTestTar(t, tarPath)

	job := store.CreateExtract(tarPath)
	if job.Kind != "extract" {
		t.Fatalf("Kind = %q, want extract", job.Kind)
	}
	worker.Submit(job, false)

	deadline := time.Now().Add(20 * time.Second)
	var final *Job
	for time.Now().Before(deadline) {
		cur, ok := store.Get(job.ID)
		if !ok {
			t.Fatal("job disappeared from store")
		}
		if cur.Status == StatusCompleted || cur.Status == StatusFailed {
			final = cur
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if final == nil {
		t.Fatal("extract job did not finish within the deadline")
	}
	if final.Status != StatusCompleted {
		t.Fatalf("status = %s, error = %s", final.Status, final.Error)
	}
	if len(final.Regions) != 1 {
		t.Fatalf("Regions = %+v, want exactly 1", final.Regions)
	}
	r := final.Regions[0]
	if r.Type != "tar" || !r.Usable || r.Path == "" {
		t.Errorf("region = %+v, want usable tar region with a path", r)
	}
	if r.RegionSize == 0 {
		t.Error("RegionSize = 0, want the tar's on-disk footprint from moria's identify pass")
	}
	extractedFile := filepath.Join(r.Path, "hello.txt")
	got, err := os.ReadFile(extractedFile)
	if err != nil {
		t.Fatalf("extracted file missing: %v", err)
	}
	if string(got) != "hello moria" {
		t.Errorf("extracted content = %q, want %q", got, "hello moria")
	}
}

// newTestAPIWithBareWorker is like newTestAPI but wires a real (non-nil)
// Worker so createJob's unconditional Submit() call doesn't nil-deref --
// the Worker's queue has no consumer (no goroutines started), so a job
// lands on the channel and nothing actually executes, which is exactly
// what these two tests want: checking createJob's own validation/dispatch,
// not a real run.
func newTestAPIWithBareWorker(t *testing.T) (*API, *Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := NewStore(filepath.Join(dir, "jobs"), "test")
	if err != nil {
		t.Fatal(err)
	}
	reportDB, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	aiKey, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{store: store, queue: make(chan string, 4)}
	api := NewAPI(store, worker, nil, reportDB, filepath.Join(dir, "uploads"), dir, false, "", nil, aiKey)
	return api, store
}

func TestCreateJobRejectsInvalidKind(t *testing.T) {
	api, _ := newTestAPIWithBareWorker(t)
	req := httptest.NewRequest(http.MethodPost, "/api/jobs",
		strings.NewReader(`{"kind":"bogus","target":"/bin/ls"}`))
	w := httptest.NewRecorder()
	api.createJob(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestCreateJobExtractKindSetsJobKind(t *testing.T) {
	api, store := newTestAPIWithBareWorker(t)
	req := httptest.NewRequest(http.MethodPost, "/api/jobs",
		strings.NewReader(`{"kind":"extract","target":"/bin"}`))
	w := httptest.NewRecorder()
	api.createJob(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusAccepted, w.Body.String())
	}
	jobs := store.List()
	if len(jobs) != 1 || jobs[0].Kind != "extract" {
		t.Fatalf("jobs = %+v, want exactly 1 with Kind=extract", jobs)
	}
}
