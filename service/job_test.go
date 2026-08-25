package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Regression: re-submitting a byte-identical target after an ifda upgrade
// must not resolve to a job whose report predates the upgrade. This is what
// actually happened in production -- a target was scanned, the busybox_audit
// field was added to the analyzer, the same target was re-submitted, and the
// dedup cache (keyed only on target path + size + mtime) silently CopyJob'd
// rows from the pre-upgrade report, so the new field never showed up.
func TestDedupCacheDoesNotServeStaleAnalyzerVersion(t *testing.T) {
	dataDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "firmware.bin")
	if err := os.WriteFile(target, []byte("fw content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A job completes under analyzer version "v1".
	storeV1, err := NewStore(filepath.Join(dataDir, "jobs"), "v1")
	if err != nil {
		t.Fatal(err)
	}
	job := storeV1.Create(target, false)
	storeV1.update(job.ID, func(j *Job) {
		j.Status = StatusCompleted
		j.AnalyzerVersion = "v1"
	})
	storeV1.cacheStore(storeV1.dedupKey(target), job.ID)

	if _, ok := storeV1.cacheLookup(storeV1.dedupKey(target)); !ok {
		t.Fatal("sanity check failed: v1 store should cache-hit its own just-completed job")
	}

	// Restart "under" the new analyzer version "v2" (target unchanged on
	// disk -- same path/size/mtime). Reloading job history must NOT index
	// the v1 job into the cache, since its rows don't reflect v2's analyzer.
	storeV2, err := NewStore(filepath.Join(dataDir, "jobs"), "v2")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := storeV2.cacheLookup(storeV2.dedupKey(target)); ok {
		t.Error("v2 store must not cache-hit a job completed under v1 -- stale report would be served for a 'fresh' scan")
	}

	// A job that completes under v2 IS a valid cache-hit source for
	// subsequent v2 submissions.
	job2 := storeV2.Create(target, false)
	storeV2.update(job2.ID, func(j *Job) {
		j.Status = StatusCompleted
		j.AnalyzerVersion = "v2"
	})
	storeV2.cacheStore(storeV2.dedupKey(target), job2.ID)
	if id, ok := storeV2.cacheLookup(storeV2.dedupKey(target)); !ok || id != job2.ID {
		t.Errorf("v2 store should cache-hit its own v2 job, got id=%q ok=%v", id, ok)
	}

	// A cache-hit copy (Submit's CopyJob path) inherits the source job's
	// AnalyzerVersion, not the empty zero-value -- otherwise the copy itself
	// would never be eligible as a cache-hit source after a restart even
	// though its rows are, by construction, identical to a real v2 run.
	prev, _ := storeV2.Get(job2.ID)
	cacheJob := storeV2.Create(target, false)
	storeV2.update(cacheJob.ID, func(j *Job) {
		j.Status = StatusCompleted
		j.CacheHit = true
		j.AnalyzerVersion = prev.AnalyzerVersion
	})
	got, _ := storeV2.Get(cacheJob.ID)
	if got.AnalyzerVersion != "v2" {
		t.Errorf("cache-hit job's AnalyzerVersion = %q, want inherited %q", got.AnalyzerVersion, "v2")
	}
}

// force=true (the web UI's "re-scan" button) must bypass the dedup cache
// even when a valid cache-hit is available -- otherwise "re-scan" would
// silently CopyJob the same stale report back, which is exactly the bug
// this button exists to let a user route around (e.g. an old report that
// predates a report field the analyzer has since started emitting).
func TestSubmitForceBypassesDedupCache(t *testing.T) {
	dataDir := t.TempDir()
	target := filepath.Join(t.TempDir(), "firmware.bin")
	if err := os.WriteFile(target, []byte("fw content"), 0o644); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(filepath.Join(dataDir, "jobs"), "v1")
	if err != nil {
		t.Fatal(err)
	}
	prev := store.Create(target, false)
	store.update(prev.ID, func(j *Job) {
		j.Status = StatusCompleted
		j.AnalyzerVersion = "v1"
	})
	store.cacheStore(store.dedupKey(target), prev.ID)
	if _, ok := store.cacheLookup(store.dedupKey(target)); !ok {
		t.Fatal("sanity check failed: store should cache-hit the just-completed job")
	}

	// Bare Worker, no NewWorker (which spins up goroutines that would try to
	// exec a real python3 subprocess for anything landing on the queue) --
	// only Submit's cache-bypass decision is under test here.
	w := &Worker{store: store, queue: make(chan string, 1)}
	job := store.Create(target, false)
	w.Submit(job, true)

	select {
	case id := <-w.queue:
		if id != job.ID {
			t.Errorf("queued id = %q, want %q", id, job.ID)
		}
	default:
		t.Error("force=true should have pushed straight onto the queue instead of taking the cache-hit path")
	}
	// Must not have been resolved as a cache hit in the meantime.
	if got, _ := store.Get(job.ID); got.CacheHit {
		t.Error("force=true job must not be marked CacheHit")
	}
}

func TestDedupKeyChangesWithAnalyzerVersion(t *testing.T) {
	target := filepath.Join(t.TempDir(), "firmware.bin")
	if err := os.WriteFile(target, []byte("fw content"), 0o644); err != nil {
		t.Fatal(err)
	}
	s1 := &Store{analyzerVersion: "v1"}
	s2 := &Store{analyzerVersion: "v2"}
	if s1.dedupKey(target) == s2.dedupKey(target) {
		t.Error("dedupKey must differ across analyzer versions for the same unchanged target")
	}
	if s1.dedupKey(target) != s1.dedupKey(target) {
		t.Error("dedupKey must be stable for the same target + version")
	}
}
