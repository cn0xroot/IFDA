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
	ID string `json:"id"`
	// Kind distinguishes an "analyze" job (the deep RE/VUL pipeline, target
	// must already be an extracted tree or single binary) from an "extract"
	// job (identify + unpack a raw firmware image via moria, see
	// ifda/ingest -- produces Regions, not a findings report). Empty/absent
	// on any job record predating this field means "analyze", the only kind
	// that existed then.
	Kind       string     `json:"kind,omitempty"`
	Target     string     `json:"target"`
	Decompile  bool       `json:"decompile"` // opt-in Ghidra pseudocode enrichment (FR-RE-2, slow); analyze only
	Status     Status     `json:"status"`
	Progress   int        `json:"progress"` // 0..100
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
	// AnalyzerVersion is the ifda.__version__ that actually produced this
	// job's report rows (set on completion, inherited on a cache-hit copy).
	// Store.dedupKey mixes the *currently running* version into its hash, but
	// that alone doesn't stop a stale job from being re-indexed into the
	// cache after an upgrade -- NewStore's load loop also checks this field
	// against the running version before trusting a historical job as a
	// cache-hit source, so a report produced by an older ifda build is never
	// silently served again for a byte-identical target.
	AnalyzerVersion string `json:"analyzer_version,omitempty"`
	// Log is the full timestamped history of progress events (one per
	// @@IFDA@@ line from the core), not just the latest Stage/Detail — so
	// the web UI can show what the analyzer actually did (which binary, in
	// what order, how long each stage took), not just a single snapshot that
	// gets overwritten by the next event.
	Log []LogEntry `json:"log,omitempty"`
	// Regions is set only on a completed "extract" job: every region moria
	// found in the target image, whether or not it actually unpacked
	// (Usable distinguishes the two) -- see ifda/ingest's merged region
	// shape. Picking which region (if any) to submit as a new "analyze" or
	// "extract" target is a human decision made from this list, not
	// automated (real multi-partition firmware routinely has more than one
	// filesystem region, e.g. dual-bank A/B images).
	Regions []ExtractRegion `json:"regions,omitempty"`

	reportPath string // temp file holding the full JSON report
	mdPath     string // Markdown report
	sbomPath   string // CycloneDX SBOM
	chartPath  string // rootfs directory-composition pie chart PNG
	extractDir string // "extract" jobs only: where moria unpacked regions live

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
	// Arch is set only on "disassemble" stage events (ifda/pipeline.py's
	// emit(..., arch=info.arch)) -- the web UI's live progress chart tallies
	// these to show "binaries processed so far, by architecture" while a
	// scan is still running.
	Arch string `json:"arch,omitempty"`
	// Done/Total are set only on stages with a natural per-item sub-count
	// (currently "disassemble" and "decompile" -- the two stages whose own
	// item count can dominate a scan's wall time), for a dedicated
	// current-stage progress bar distinct from the overall Pct. Omitted
	// (both zero) on every other stage, which are single atomic calls with
	// no meaningful sub-progress to show.
	Done  int `json:"done,omitempty"`
	Total int `json:"total,omitempty"`
}

// ExtractRegion mirrors one entry of ifda/ingest's merged region list
// (moria's identification metadata + its extraction outcome for that
// region). Usable means it actually unpacked into Path and has content
// worth acting on -- an unusable region (moria found the byte pattern but
// couldn't decode it, e.g. vendor-obfuscated compression) still shows up
// here with Status/Warnings explaining why, not silently dropped.
type ExtractRegion struct {
	Offset      int64  `json:"offset"`
	Type        string `json:"type"`
	Category    string `json:"category"`
	Confidence  int    `json:"confidence,omitempty"`
	Description string `json:"description"`
	Status      string `json:"status"`
	Usable      bool   `json:"usable"`
	Path        string `json:"path,omitempty"`
	// RegionSize is this region's footprint in the *source* image (moria's
	// identify-pass size at this offset); Bytes is the total size of the
	// content moria actually decompressed/wrote out. These are legitimately
	// different numbers for a compressed filesystem -- kept separate rather
	// than collapsed into one "size", which made the extracted-content
	// total look like a wrong region size.
	RegionSize int64    `json:"region_size"`
	Files      int      `json:"files"`
	Dirs       int      `json:"dirs"`
	Bytes      int64    `json:"bytes"`
	Warnings   []string `json:"warnings,omitempty"`
}

// maxJobLog caps how many log entries a job keeps (oldest dropped first), a
// defensive bound against a pathological target with an enormous file count.
const maxJobLog = 2000

// progressEvent mirrors the Python core's @@IFDA@@<json> lines.
type progressEvent struct {
	Stage  string `json:"stage"`
	Pct    int    `json:"pct"`
	Detail string `json:"detail"`
	Arch   string `json:"arch,omitempty"`
	Done   int    `json:"done,omitempty"`
	Total  int    `json:"total,omitempty"`
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
	// analyzerVersion is mixed into dedupKey so a re-submitted, byte-identical
	// target doesn't silently reuse a report produced by an older ifda build.
	// Without this, shipping a new analyzer feature (e.g. the busybox_audit
	// field) never showed up for a target that was already cached, since
	// dedupKey only ever tracked target path + size + mtime -- exactly what
	// happened here: a same-day re-submit of an already-scanned firmware hit
	// the cache and CopyJob'd rows from a report that predated the new field.
	analyzerVersion string
}

// jobRecord is the on-disk shape: Job's public fields plus the otherwise-
// unexported report paths (proc/cancelFn are process handles, never persisted;
// a reloaded "running" job has no process behind it anymore, see NewStore).
type jobRecord struct {
	ID              string          `json:"id"`
	Kind            string          `json:"kind,omitempty"`
	Target          string          `json:"target"`
	Decompile       bool            `json:"decompile"`
	Status          Status          `json:"status"`
	Progress        int             `json:"progress"`
	Stage           string          `json:"stage"`
	Detail          string          `json:"detail"`
	Binaries        int             `json:"binaries"`
	Findings        int             `json:"findings"`
	HighCrit        int             `json:"high_crit"`
	Error           string          `json:"error,omitempty"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	CacheHit        bool            `json:"cache_hit"`
	AnalyzerVersion string          `json:"analyzer_version,omitempty"`
	ReportPath      string          `json:"report_path,omitempty"`
	MDPath          string          `json:"md_path,omitempty"`
	SBOMPath        string          `json:"sbom_path,omitempty"`
	ChartPath       string          `json:"chart_path,omitempty"`
	ExtractDir      string          `json:"extract_dir,omitempty"`
	Regions         []ExtractRegion `json:"regions,omitempty"`
	Log             []LogEntry      `json:"log,omitempty"`
}

func recordFromJob(j *Job) jobRecord {
	return jobRecord{
		ID: j.ID, Kind: j.Kind, Target: j.Target, Decompile: j.Decompile, Status: j.Status, Progress: j.Progress,
		Stage: j.Stage, Detail: j.Detail, Binaries: j.Binaries, Findings: j.Findings,
		HighCrit: j.HighCrit, Error: j.Error, CreatedAt: j.CreatedAt,
		StartedAt: j.StartedAt, FinishedAt: j.FinishedAt, CacheHit: j.CacheHit,
		AnalyzerVersion: j.AnalyzerVersion, Regions: j.Regions,
		ReportPath: j.reportPath, MDPath: j.mdPath, SBOMPath: j.sbomPath, ChartPath: j.chartPath,
		ExtractDir: j.extractDir, Log: j.Log,
	}
}

func (r jobRecord) toJob() *Job {
	return &Job{
		ID: r.ID, Kind: r.Kind, Target: r.Target, Decompile: r.Decompile, Status: r.Status, Progress: r.Progress,
		Stage: r.Stage, Detail: r.Detail, Binaries: r.Binaries, Findings: r.Findings,
		HighCrit: r.HighCrit, Error: r.Error, CreatedAt: r.CreatedAt,
		StartedAt: r.StartedAt, FinishedAt: r.FinishedAt, CacheHit: r.CacheHit,
		AnalyzerVersion: r.AnalyzerVersion, Regions: r.Regions,
		reportPath: r.ReportPath, mdPath: r.MDPath, sbomPath: r.SBOMPath, chartPath: r.ChartPath,
		extractDir: r.ExtractDir, Log: r.Log,
	}
}

// NewStore loads any job history found under dir (created if missing), so
// past scans and their reports are still there after a restart. A job that
// was queued/running/paused when the process died has no subprocess to
// reattach to, so it's rewritten as failed ("interrupted by service
// restart") rather than left looking like it's still in progress forever.
func NewStore(dir, analyzerVersion string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, jobs: map[string]*Job{}, cache: map[string]string{}, analyzerVersion: analyzerVersion}

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
		// Only trust a historical job as a cache-hit source if its own
		// recorded AnalyzerVersion matches what's running right now --
		// otherwise, after an ifda upgrade, a resubmit of an unchanged
		// target would still get its dedupKey computed under the new
		// version (see dedupKey) but resolve to a job whose *rows* were
		// produced by the old one, silently hiding whatever's new.
		if j.Status == StatusCompleted && j.AnalyzerVersion == s.analyzerVersion {
			s.cache[s.dedupKey(j.Target)] = j.ID // later (newer) entries win
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

// Create makes a new "analyze" job. Use CreateExtract for an "extract" job.
func (s *Store) Create(target string, decompile bool) *Job {
	return s.create("analyze", target, decompile)
}

// CreateExtract makes a new "extract" job (identify + unpack a raw firmware
// image via moria; see ifda/ingest). Never carries -decompile (analyze-only).
func (s *Store) CreateExtract(target string) *Job {
	return s.create("extract", target, false)
}

func (s *Store) create(kind, target string, decompile bool) *Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	id := fmt.Sprintf("job-%d-%s", s.seq, randHex(4))
	j := &Job{
		ID:        id,
		Kind:      kind,
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

// dedupKey is target abspath + size + mtime + analyzerVersion, so a changed
// tree re-analyzes, and so does a resubmit of an unchanged tree once the
// analyzer itself has moved on (new report fields, fixed detectors, ...) --
// otherwise Submit's cache hit below would CopyJob rows from a report an
// older ifda build produced, silently hiding whatever's new.
func (s *Store) dedupKey(target string) string {
	st, err := os.Stat(target)
	if err != nil {
		return target
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%s", target, st.Size(), st.ModTime().UnixNano(), s.analyzerVersion)))
	return fmt.Sprintf("%x", h[:8])
}

// Worker pool: bounded goroutines pull job ids off a channel and run the core.
type Worker struct {
	store          *Store
	queue          chan string
	coreDir        string // dir containing the ifda package (cwd for the python call)
	reportDB       *ReportDB
	triage         *TriageStore
	analyzeTimeout time.Duration // hard wall-clock cap per analyze subprocess
}

func NewWorker(store *Store, coreDir string, workers, qlen int, reportDB *ReportDB, triage *TriageStore,
	analyzeTimeout time.Duration) *Worker {
	w := &Worker{store: store, queue: make(chan string, qlen), coreDir: coreDir, reportDB: reportDB, triage: triage,
		analyzeTimeout: analyzeTimeout}
	for i := 0; i < workers; i++ {
		go w.loop()
	}
	return w
}

// Submit enqueues a job, honoring the dedup cache unless force is set (the
// web UI's "re-scan" button -- a plain resubmit of a byte-identical target
// would otherwise just CopyJob the previous cached report verbatim, which
// defeats the point of asking for a fresh scan, e.g. to pick up analyzer
// output fields a stale cached report predates).
func (w *Worker) Submit(j *Job, force bool) {
	// "extract" jobs don't participate in the analyze dedup cache at all --
	// that cache keys against reportDB rows (CopyJob), which an extract job
	// never produces (it has Regions, not a findings report), and moria
	// runs fast enough that a cache layer buys little anyway.
	if force || j.Kind == "extract" {
		w.queue <- j.ID
		return
	}
	key := w.store.dedupKey(j.Target)
	if prevID, ok := w.store.cacheLookup(key); ok {
		if prev, ok := w.store.Get(prevID); ok && prev.Status == StatusCompleted {
			if err := w.reportDB.CopyJob(prevID, j.ID); err != nil {
				// Fall through to a real (re)scan rather than serve a job
				// whose report rows don't actually exist.
				w.queue <- j.ID
				return
			}
			w.store.update(j.ID, func(j *Job) {
				j.Status = StatusCompleted
				j.Progress = 100
				j.Stage = "done"
				j.CacheHit = true
				j.AnalyzerVersion = prev.AnalyzerVersion
				j.Binaries = prev.Binaries
				j.Findings = prev.Findings
				j.HighCrit = prev.HighCrit
				j.mdPath = prev.mdPath
				j.sbomPath = prev.sbomPath
				j.chartPath = prev.chartPath
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
	if job.Kind == "extract" {
		w.runExtract(id, job)
		return
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
	chartPath := filepath.Join(jobDir, "report.dirchart.png")

	args := []string{"-m", "ifda.cli", "analyze",
		job.Target, "--json", reportPath, "--md", mdPath, "--sbom", sbomPath, "--chart", chartPath,
		"--progress"}
	if job.Decompile {
		// Opt-in (checked per job, not forced globally): Ghidra headless
		// enrichment is tens of seconds per binary, so it can push a job
		// past the ctx timeout above on a large target. Degrades to a no-op
		// with a BinaryInfo.warning if Ghidra isn't installed.
		args = append(args, "--decompile")
	}

	waitErr, lastErr, cancelled := w.runSubprocess(id, args)
	if cancelled {
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

	data, err := os.ReadFile(reportPath)
	if err != nil {
		w.fail(id, "report file unavailable: "+err.Error())
		return
	}
	bins, finds, hc, err := w.reportDB.Ingest(id, data, w.triage.Snapshot())
	if err != nil {
		w.fail(id, "storing report failed: "+err.Error())
		return
	}
	fin := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusCompleted
		j.Progress = 100
		j.Stage = "done"
		j.Binaries, j.Findings, j.HighCrit = bins, finds, hc
		j.reportPath = reportPath
		j.mdPath = mdPath
		j.sbomPath = sbomPath
		j.chartPath = chartPath
		j.FinishedAt = &fin
		j.AnalyzerVersion = w.store.analyzerVersion
	})
	w.store.cacheStore(w.store.dedupKey(job.Target), id)
}

// extractResult mirrors ifda/ingest's identify_and_extract() return shape.
type extractResult struct {
	Source  string          `json:"source"`
	Size    int64           `json:"size"`
	Summary string          `json:"summary"`
	Regions []ExtractRegion `json:"regions"`
	Error   string          `json:"error,omitempty"`
}

// runExtract identifies + unpacks a raw firmware image via moria (FR-ING/
// FR-EXT; see ifda/ingest). Unlike runAnalyze's flow, there's no reportDB
// involvement and no dedup cache entry -- an extract job's only durable
// output is job.Regions, a list for a human to act on (see the Job.Regions
// doc comment), not a findings report.
func (w *Worker) runExtract(id string, job *Job) {
	now := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusRunning
		j.StartedAt = &now
		j.Stage = "starting"
	})

	jobDir := filepath.Join(w.store.dir, id)
	if err := os.MkdirAll(jobDir, 0o755); err != nil {
		w.fail(id, err.Error())
		return
	}
	extractDir := filepath.Join(jobDir, "extracted")
	resultPath := filepath.Join(jobDir, "extract.json")

	args := []string{"-m", "ifda.cli", "extract", job.Target, "--out", extractDir,
		"--json", resultPath, "--progress"}

	waitErr, lastErr, cancelled := w.runSubprocess(id, args)
	if cancelled {
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

	data, err := os.ReadFile(resultPath)
	if err != nil {
		w.fail(id, "extract result unavailable: "+err.Error())
		return
	}
	var res extractResult
	if err := json.Unmarshal(data, &res); err != nil {
		w.fail(id, "extract result unreadable: "+err.Error())
		return
	}
	if res.Error != "" {
		w.fail(id, res.Error)
		return
	}
	fin := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusCompleted
		j.Progress = 100
		j.Stage = "done"
		j.Regions = res.Regions
		j.extractDir = extractDir
		j.FinishedAt = &fin
		j.AnalyzerVersion = w.store.analyzerVersion
	})
}

// runSubprocess is the shared "spawn python3 -m ifda.cli <...>, stream
// @@IFDA@@ progress into the job log, wait" machinery behind both an
// analyze and an extract run -- everything about a job kind that differs
// (which subcommand/args to run, what to do with the result on success) is
// the caller's job.
func (w *Worker) runSubprocess(id string, args []string) (waitErr error, lastErrLine string, cancelled bool) {
	ctx, cancel := context.WithTimeout(context.Background(), w.analyzeTimeout)
	defer cancel()
	// Register cancelFn before Start(): if Cancel() races in right here, it
	// still wins (CommandContext refuses to Start() once ctx is already done).
	w.store.setControl(id, nil, cancel)
	if job, ok := w.store.Get(id); ok && job.Status == StatusCancelled {
		return nil, "", true
	}

	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.Dir = w.coreDir
	// Own process group so Pause/Resume/Cancel can signal it (and any child
	// processes it spawns, e.g. an optional Ghidra headless run) as a unit.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		w.fail(id, err.Error())
		return nil, "", true
	}
	if err := cmd.Start(); err != nil {
		if ctx.Err() != nil {
			return nil, "", true // killed before it ever launched
		}
		w.fail(id, err.Error())
		return nil, "", true
	}
	w.store.setControl(id, cmd.Process, nil)

	// Stream progress events from stderr into the job.
	sc := bufio.NewScanner(stderr)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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
						Time: time.Now().UTC(), Stage: ev.Stage, Detail: ev.Detail, Pct: ev.Pct, Arch: ev.Arch,
						Done: ev.Done, Total: ev.Total,
					})
					if len(j.Log) > maxJobLog {
						j.Log = j.Log[len(j.Log)-maxJobLog:]
					}
				})
			}
		} else if strings.TrimSpace(line) != "" {
			lastErrLine = line // keep the final human log line for diagnostics
		}
	}

	waitErr = cmd.Wait()
	if cur, ok := w.store.Get(id); ok && cur.Status == StatusCancelled {
		fin := time.Now().UTC()
		w.store.update(id, func(j *Job) {
			if j.FinishedAt == nil {
				j.FinishedAt = &fin
			}
			j.Stage = "cancelled"
		})
		return nil, "", true
	}
	return waitErr, lastErrLine, false
}

func (w *Worker) fail(id, msg string) {
	fin := time.Now().UTC()
	w.store.update(id, func(j *Job) {
		j.Status = StatusFailed
		j.Error = msg
		j.FinishedAt = &fin
	})
}
