package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Status is the job state machine:
// queued -> running -> completed|failed|cancelled
// running <-> paused (SIGSTOP/SIGCONT; user-initiated, reversible)
// queued -> cancelled (removed before a worker picks it up)
type Status string

const (
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusPaused    Status = "paused"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

var (
	ErrJobNotFound  = errors.New("job not found")
	ErrInvalidState = errors.New("job is not in a state that allows this action")
)

// Job is one analysis task over a binary or an extracted firmware tree.
type Job struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	Decompile  bool      `json:"decompile"` // opt-in Ghidra pseudocode enrichment (FR-RE-2, slow)
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
	// Log is the full timestamped history of progress events (one per
	// @@IFDA@@ line from the core), not just the latest Stage/Detail — so
	// the web UI can show what the analyzer actually did (which binary, in
	// what order, how long each stage took), not just a single snapshot that
	// gets overwritten by the next event.
	Log []LogEntry `json:"log,omitempty"`

	reportPath string // temp file holding the full JSON report
	mdPath     string // Markdown report
	sbomPath   string // CycloneDX SBOM

	// Control handles for pause/resume/stop. Set once the analysis subprocess
	// exists; cancelFn is registered *before* the process is spawned so a Stop
	// requested in that narrow window still prevents it from ever starting
	// (context.CommandContext refuses to Start() once its context is done).
	proc     *os.Process
	cancelFn context.CancelFunc
}

// LogEntry is one timestamped progress event in a job's Log.
type LogEntry struct {
	Time   time.Time `json:"time"`
	Stage  string    `json:"stage"`
	Detail string    `json:"detail"`
	Pct    int       `json:"pct"`
}

// maxJobLog caps how many log entries a job keeps (oldest dropped first), a
// defensive bound against a pathological target with an enormous file count.
const maxJobLog = 2000

// progressEvent mirrors the Python core's @@IFDA@@<json> lines.
type progressEvent struct {
	Stage  string `json:"stage"`
	Pct    int    `json:"pct"`
	Detail string `json:"detail"`
}

// Store is a job registry with a path-based dedup cache (NFR-PERF), backed by
// one JSON file per job under dir so scan history (status, counts, and where
// its report/md/sbom live) survives a service restart. The in-memory maps are
// the hot path; disk is just replayed once at startup. A DB is the production
// drop-in behind this, same as TriageStore.
type Store struct {
	mu    sync.RWMutex
	dir   string // one <id>.json per job, plus a <id>/ dir holding its reports
	jobs  map[string]*Job
	order []string          // insertion order, oldest first
	cache map[string]string // dedup key -> completed job id
	seq   int
}

// jobRecord is the on-disk shape: Job's public fields plus the otherwise-
// unexported report paths (proc/cancelFn are process handles, never persisted;
// a reloaded "running" job has no process behind it anymore, see NewStore).
type jobRecord struct {
	ID         string     `json:"id"`
	Target     string     `json:"target"`
	Decompile  bool       `json:"decompile"`
	Status     Status     `json:"status"`
	Progress   int        `json:"progress"`
	Stage      string     `json:"stage"`
	Detail     string     `json:"detail"`
	Binaries   int        `json:"binaries"`
	Findings   int        `json:"findings"`
	HighCrit   int        `json:"high_crit"`
	Error      string     `json:"error,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	CacheHit   bool       `json:"cache_hit"`
	ReportPath string     `json:"report_path,omitempty"`
	MDPath     string     `json:"md_path,omitempty"`
	SBOMPath   string     `json:"sbom_path,omitempty"`
	Log        []LogEntry `json:"log,omitempty"`
}

func recordFromJob(j *Job) jobRecord {
	return jobRecord{
		ID: j.ID, Target: j.Target, Decompile: j.Decompile, Status: j.Status, Progress: j.Progress,
		Stage: j.Stage, Detail: j.Detail, Binaries: j.Binaries, Findings: j.Findings,
		HighCrit: j.HighCrit, Error: j.Error, CreatedAt: j.CreatedAt,
		StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, CacheHit: j.CacheHit,
		ReportPath: j.reportPath, MDPath: j.mdPath, SBOMPath: j.sbomPath, Log: j.Log,
	}
}

func (r jobRecord) toJob() *Job {
	return &Job{
		ID: r.ID, Target: r.Target, Decompile: r.Decompile, Status: r.Status, Progress: r.Progress,
		Stage: r.Stage, Detail: r.Detail, Binaries: r.Binaries, Findings: r.Findings,
		HighCrit: r.HighCrit, Error: r.Error, CreatedAt: r.CreatedAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, CacheHit: r.CacheHit,
		reportPath: r.ReportPath, mdPath: r.MDPath, sbomPath: r.SBOMPath, Log: r.Log,
	}
}

// NewStore loads any job history found under dir (created if missing), so
// past scans and their reports are still there after a restart. A job that
// was queued/running/paused when the process died has no subprocess to
// reattach to, so it's rewritten as failed ("interrupted by service
// restart") rather than left looking like it's still in progress forever.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, jobs: map[string]*Job{}, cache: map[string]string{}}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var loaded []*Job
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var rec jobRecord
		if json.Unmarshal(data, &rec) != nil || rec.ID == "" {
			continue
		}
		loaded = append(loaded, rec.toJob())
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].CreatedAt.Before(loaded[j].CreatedAt) })

	now := time.Now().UTC()
	for _, j := range loaded {
		if j.Status == StatusQueued || j.Status == StatusRunning || j.Status == StatusPaused {
			j.Status = StatusFailed
			j.Error = "interrupted by service restart"
			j.FinishedAt = &now
			j.Log = append(j.Log, LogEntry{Time: now, Stage: "interrupted", Detail: j.Error, Pct: j.Progress})
		}
		s.jobs[j.ID] = j
		s.order = append(s.order, j.ID)
		if j.Status == StatusCompleted {
			s.cache[dedupKey(j.Target)] = j.ID // later (newer) entries win
		}
		if n, _, ok := strings.Cut(strings.TrimPrefix(j.ID, "job-"), "-"); ok {
			if v, err := strconv.Atoi(n); err == nil && v > s.seq {
				s.seq = v
			}
		}
		s.persist(j) // write back any status correction made above
	}
	return s, nil
}

// persist writes one job's current state to disk. Caller holds s.mu.
func (s *Store) persist(j *Job) {
	if s.dir == "" {
		return
	}
	data, err := json.MarshalIndent(recordFromJob(j), "", "  ")
	if err != nil {
		return
	}
	path := filepath.Join(s.dir, j.ID+".json")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, path)
	}
}

func (s *Store) Create(target string, decompile bool) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := fmt.Sprintf("job-%d-%s", s.seq, randHex(4))
	j := &Job{
		ID:        id,
		Target:    target,
		Decompile: decompile,
		Status:    StatusQueued,
		CreatedAt: time.Now().UTC(),
	}
	s.jobs[id] = j
	s.order = append(s.order, id)
	s.persist(j)
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

// update mutates a job under lock via fn, then persists the new state.
func (s *Store) update(id string, fn func(*Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		fn(j)
		s.persist(j)
	}
}

// setControl attaches the running subprocess's control handles to the stored
// job (not the shallow copy Get returns), so Pause/Resume/Cancel can reach it.
func (s *Store) setControl(id string, proc *os.Process, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		if proc != nil {
			j.proc = proc
		}
		if cancel != nil {
			j.cancelFn = cancel
		}
	}
}

// Pause freezes a running job's OS process with SIGSTOP (sent to its whole
// process group, so any child processes freeze too). The Python core needs no
// checkpointing support for this: the kernel suspends it in place and CPU/wall
// time simply stops advancing until Resume.
func (s *Store) Pause(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return ErrJobNotFound
	}
	if j.Status != StatusRunning || j.proc == nil {
		return ErrInvalidState
	}
	if err := syscall.Kill(-j.proc.Pid, syscall.SIGSTOP); err != nil {
		return err
	}
	j.Status = StatusPaused
	j.Stage = "paused"
	return nil
}

// Resume un-freezes a paused job with SIGCONT.
func (s *Store) Resume(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return ErrJobNotFound
	}
	if j.Status != StatusPaused || j.proc == nil {
		return ErrInvalidState
	}
	if err := syscall.Kill(-j.proc.Pid, syscall.SIGCONT); err != nil {
		return err
	}
	j.Status = StatusRunning
	j.Stage = "resumed"
	return nil
}

// Cancel stops a job for good (queued: removed before it ever runs; running
// or paused: its process group is killed). Terminal — unlike Pause, there is
// no analyzer-side checkpoint to continue from, so a cancelled job must be
// resubmitted from scratch to re-run.
func (s *Store) Cancel(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return ErrJobNotFound
	}
	switch j.Status {
	case StatusQueued:
		now := time.Now().UTC()
		j.Status = StatusCancelled
		j.Stage = "cancelled"
		j.FinishedAt = &now
	case StatusRunning, StatusPaused:
		// Cancel the context first: if the process hasn't been Start()ed yet
		// (the narrow window right after dequeue), this stops it from ever
		// launching. If it has, SIGKILL the process group directly rather
		// than waiting on the context-watcher goroutine — SIGKILL also
		// terminates an already-SIGSTOP'd (paused) process immediately.
		if j.cancelFn != nil {
			j.cancelFn()
		}
		if j.proc != nil {
			_ = syscall.Kill(-j.proc.Pid, syscall.SIGKILL)
		}
		j.Status = StatusCancelled
		j.Stage = "cancelling"
	default:
		return ErrInvalidState
	}
	return nil
}

// Delete removes a job from history for good: its record, its report/md/sbom
// directory on disk, its dedup-cache entry, and the in-memory list. Refuses
// while the job is still queued/running/paused — stop it first, since there's
// a live (or about-to-be) subprocess and cache entry behind it.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[id]
	if !ok {
		return ErrJobNotFound
	}
	if j.Status == StatusQueued || j.Status == StatusRunning || j.Status == StatusPaused {
		return ErrInvalidState
	}
	delete(s.jobs, id)
	for i, oid := range s.order {
		if oid == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	for key, cachedID := range s.cache {
		if cachedID == id {
			delete(s.cache, key)
		}
	}
	if s.dir != "" {
		_ = os.Remove(filepath.Join(s.dir, id+".json"))
		_ = os.RemoveAll(filepath.Join(s.dir, id))
	}
	return nil
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
	if job.Status == StatusCancelled {
		return // Stop was requested while this job was still queued.
	}
	now := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusRunning
		j.StartedAt = &now
		j.Stage = "starting"
	})

	// Reports live under the store's job dir (not the OS temp dir) so they
	// survive a service restart alongside the job record itself, and so
	// there's one findable place per job instead of anonymous temp names.
	jobDir := filepath.Join(w.store.dir, id)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		w.fail(id, err.Error())
		return
	}
	reportPath := filepath.Join(jobDir, "report.json")
	mdPath := filepath.Join(jobDir, "report.md")
	sbomPath := filepath.Join(jobDir, "report.sbom.json")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	// Register cancelFn before Start(): if Cancel() races in right here, it
	// still wins (CommandContext refuses to Start() once ctx is already done).
	w.store.setControl(id, nil, cancel)
	if job, ok := w.store.Get(id); ok && job.Status == StatusCancelled {
		return
	}

	args := []string{"-m", "ifda.cli", "analyze",
		job.Target, "--json", reportPath, "--md", mdPath, "--sbom", sbomPath,
		"--progress"}
	if job.Decompile {
		// Opt-in (checked per job, not forced globally): Ghidra headless
		// enrichment is tens of seconds per binary, so it can push a job
		// past the 30-minute ctx timeout above on a large target. Degrades
		// to a no-op with a BinaryInfo.warning if Ghidra isn't installed.
		args = append(args, "--decompile")
	}
	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.Dir = w.coreDir
	// Own process group so Pause/Resume/Cancel can signal it (and any child
	// processes it spawns, e.g. an optional Ghidra headless run) as a unit.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		w.fail(id, err.Error())
		return
	}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return // killed before it ever launched
		}
		w.fail(id, err.Error())
		return
	}
	w.store.setControl(id, cmd.Process, nil)

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
					// Don't clobber "paused" with a stale in-flight progress
					// event that was already queued up before the pause.
					if j.Status != StatusPaused {
						j.Progress, j.Stage, j.Detail = ev.Pct, ev.Stage, ev.Detail
					}
					j.Log = append(j.Log, LogEntry{
						Time: time.Now().UTC(), Stage: ev.Stage, Detail: ev.Detail, Pct: ev.Pct,
					})
					if len(j.Log) > maxJobLog {
						j.Log = j.Log[len(j.Log)-maxJobLog:]
					}
				})
			}
		} else if strings.TrimSpace(line) != "" {
			lastErr = line // keep the final human log line for diagnostics
		}
	}

	waitErr := cmd.Wait()
	if cur, ok := w.store.Get(id); ok && cur.Status == StatusCancelled {
		fin := time.Now().UTC()
		w.store.update(id, func(j *Job) {
			if j.FinishedAt == nil {
				j.FinishedAt = &fin
			}
			j.Stage = "cancelled"
		})
		return
	}
	if waitErr != nil {
		msg := lastErr
		if msg == "" {
			msg = waitErr.Error()
		}
		w.fail(id, msg)
		return
	}

	bins, finds, hc := summarize(reportPath)
	fin := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusCompleted
		j.Progress = 100
		j.Stage = "done"
		j.Binaries, j.Findings, j.HighCrit = bins, finds, hc
		j.reportPath = reportPath
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
