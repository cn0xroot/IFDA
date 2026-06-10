package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Status is the job state machine: queued -> running -> completed|failed.
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
)

// Job is one analysis task over a binary or an extracted firmware tree.
type Job struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	Status     Status    `json:"status"`
	Progress   int        `json:"progress"` // 0..100
	Stage      string    `json:"stage"`
	Detail     string    `json:"detail"`
	Binaries   int       `json:"binaries"`
	Findings   int       `json:"findings"`
	HighCrit   int       `json:"high_crit"`
	Error      string    `json:"error,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CacheHit   bool      `json:"cache_hit"`

	reportPath string // temp file holding the full JSON report
	mdPath     string // Markdown report
	sbomPath   string // CycloneDX SBOM
}

// progressEvent mirrors the Python core's @@IFDA@@<json> lines.
type progressEvent struct {
	Stage  string `json:"stage"`
	Pct    int    `json:"pct"`
	Detail string `json:"detail"`
}

// Store is an in-memory job registry with a path-based dedup cache (NFR-PERF).
// A persistent store (Postgres/Redis) is the production drop-in behind this.
type Store struct {
	mu    sync.RWMutex
	jobs  map[string]*Job
	order []string          // insertion order, newest last
	cache map[string]string // dedup key -> completed job id
	seq   int
}

func NewStore() *Store {
	return &Store{jobs: map[string]*Job{}, cache: map[string]string{}}
}

func (s *Store) Create(target string) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := fmt.Sprintf("job-%d-%s", s.seq, randHex(4))
	j := &Job{
		ID:        id,
		Target:    target,
		Status:    StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	s.jobs[id] = j
	s.order = append(s.order, id)
	return j
}

func (s *Store) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	if !ok {
		return nil, false
	}
	cp := *j // shallow copy so callers can't race the worker
	return &cp, true
}

func (s *Store) List() []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Job, 0, len(s.order))
	for i := len(s.order) - 1; i >= 0; i-- { // newest first
		j := *s.jobs[s.order[i]]
		out = append(out, &j)
	}
	return out
}

// update mutates a job under lock via fn.
func (s *Store) update(id string, fn func(*Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		fn(j)
	}
}

// cacheLookup returns a prior completed job's id for an unchanged target.
func (s *Store) cacheLookup(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.cache[key]
	return id, ok
}

func (s *Store) cacheStore(key, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[key] = id
}

// dedupKey is target abspath + size + mtime, so a changed tree re-analyzes.
func dedupKey(target string) string {
	st, err := os.Stat(target)
	if err != nil {
		return target
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", target, st.Size(), st.ModTime().UnixNano())))
	return fmt.Sprintf("%x", h[:8])
}

// Worker pool: bounded goroutines pull job ids off a channel and run the core.
type Worker struct {
	store   *Store
	queue   chan string
	coreDir string // dir containing the ifda package (cwd for the python call)
}

func NewWorker(store *Store, coreDir string, workers, qlen int) *Worker {
	w := &Worker{store: store, queue: make(chan string, qlen), coreDir: coreDir}
	for i := 0; i < workers; i++ {
		go w.loop()
	}
	return w
}

// Submit enqueues a job, honoring the dedup cache.
func (w *Worker) Submit(j *Job) {
	key := dedupKey(j.Target)
	if prevID, ok := w.store.cacheLookup(key); ok {
		if prev, ok := w.store.Get(prevID); ok && prev.Status == StatusCompleted {
			w.store.update(j.ID, func(j *Job) {
				j.Status = StatusCompleted
				j.Progress = 100
				j.Stage = "done"
				j.CacheHit = true
				j.Binaries = prev.Binaries
				j.Findings = prev.Findings
				j.HighCrit = prev.HighCrit
				j.reportPath = prev.reportPath
				j.mdPath = prev.mdPath
				j.sbomPath = prev.sbomPath
				now := time.Now().UTC()
				j.StartedAt, j.FinishedAt = &now, &now
			})
			return
		}
	}
	w.queue <- j.ID
}

func (w *Worker) loop() {
	for id := range w.queue {
		w.run(id)
	}
}

func (w *Worker) run(id string) {
	job, ok := w.store.Get(id)
	if !ok {
		return
	}
	now := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusRunning
		j.StartedAt = &now
		j.Stage = "starting"
	})

	report, err := os.CreateTemp("", "ifda-report-*.json")
	if err != nil {
		w.fail(id, err.Error())
		return
	}
	report.Close()
	mdPath := report.Name() + ".md"
	sbomPath := report.Name() + ".sbom.json"

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-m", "ifda.cli", "analyze",
		job.Target, "--json", report.Name(), "--md", mdPath, "--sbom", sbomPath,
		"--progress")
	cmd.Dir = w.coreDir
	stderr, err := cmd.StderrPipe()
	if err != nil {
		w.fail(id, err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		w.fail(id, err.Error())
		return
	}

	// Stream progress events from stderr into the job.
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var lastErr string
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "@@IFDA@@") {
			var ev progressEvent
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "@@IFDA@@")), &ev) == nil {
				w.store.update(id, func(j *Job) {
					j.Progress, j.Stage, j.Detail = ev.Pct, ev.Stage, ev.Detail
				})
			}
		} else if strings.TrimSpace(line) != "" {
			lastErr = line // keep the final human log line for diagnostics
		}
	}

	if err := cmd.Wait(); err != nil {
		msg := lastErr
		if msg == "" {
			msg = err.Error()
		}
		w.fail(id, msg)
		return
	}

	bins, finds, hc := summarize(report.Name())
	fin := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusCompleted
		j.Progress = 100
		j.Stage = "done"
		j.Binaries, j.Findings, j.HighCrit = bins, finds, hc
		j.reportPath = report.Name()
		j.mdPath = mdPath
		j.sbomPath = sbomPath
		j.FinishedAt = &fin
	})
	w.store.cacheStore(dedupKey(job.Target), id)
}

func (w *Worker) fail(id, msg string) {
	fin := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusFailed
		j.Error = msg
		j.FinishedAt = &fin
	})
}

// summarize reads counts out of the report JSON without modeling the whole thing.
func summarize(path string) (bins, finds, highCrit int) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var r struct {
		Binaries []json.RawMessage `json:"binaries"`
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if json.Unmarshal(data, &r) != nil {
		return
	}
	bins = len(r.Binaries)
	finds = len(r.Findings)
	for _, f := range r.Findings {
		if f.Severity == "critical" || f.Severity == "high" {
			highCrit++
		}
	}
	return
}
