package main

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"
)

// Triage states mirror the Python core's TriageState (ifda/model.py) so a
// decision made in the UI is the same vocabulary the CLI persists.
var validTriage = map[string]bool{
	"new": true, "confirmed": true, "false_positive": true, "accepted_risk": true,
}

// TriageEvent is one audit-log entry: who set a finding to what state, when.
// Actor is free-text (the web UI asks for a name and remembers it in
// localStorage) — there's no real user/session system, just attribution
// on a best-effort basis, since without it every change looks anonymous.
type TriageEvent struct {
	Time      time.Time `json:"time"`
	FindingID string    `json:"finding_id"`
	State     string    `json:"state"`
	Actor     string    `json:"actor,omitempty"`
}

// TriageStore persists analyst triage keyed by finding id (the fingerprint),
// so a decision survives re-scans and applies across jobs (FR-VUL-8). Backed by
// a JSON file for current state; the production drop-in is a shared DB.
type TriageStore struct {
	mu      sync.RWMutex
	path    string
	logPath string
	state   map[string]string // finding id -> triage state
	log     []TriageEvent     // full history, oldest first; append-only
}

func NewTriageStore(path string) *TriageStore {
	ts := &TriageStore{path: path, state: map[string]string{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &ts.state)
	}
	if path != "" {
		ts.logPath = path + ".log.jsonl"
		if f, err := os.Open(ts.logPath); err == nil {
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" {
					continue
				}
				var ev TriageEvent
				if json.Unmarshal([]byte(line), &ev) == nil {
					ts.log = append(ts.log, ev)
				}
			}
			f.Close()
		}
	}
	return ts
}

// Set records (or clears, when state == "new") a finding's triage, and
// appends an audit-log entry regardless of state (including "new", so
// resetting a decision is itself a logged event, not a silent deletion).
func (t *TriageStore) Set(findingID, state, actor string) bool {
	if findingID == "" || !validTriage[state] {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if state == "new" {
		delete(t.state, findingID)
	} else {
		t.state[findingID] = state
	}
	t.persist()
	ev := TriageEvent{Time: time.Now().UTC(), FindingID: findingID, State: state, Actor: actor}
	t.log = append(t.log, ev)
	t.appendLog(ev)
	return true
}

// Snapshot returns a copy of the current finding-id -> state map, for
// ReportDB.Ingest to apply as an overlay so a triage decision made against an
// earlier scan of the same content (same fingerprint id) is immediately
// reflected on ingest rather than reverting to "new".
func (t *TriageStore) Snapshot() map[string]string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make(map[string]string, len(t.state))
	for k, v := range t.state {
		out[k] = v
	}
	return out
}

// History returns audit-log events, newest first. If findingID is non-empty,
// only that finding's events are returned.
func (t *TriageStore) History(findingID string) []TriageEvent {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]TriageEvent, 0, len(t.log))
	for i := len(t.log) - 1; i >= 0; i-- {
		ev := t.log[i]
		if findingID == "" || ev.FindingID == findingID {
			out = append(out, ev)
		}
	}
	return out
}

func (t *TriageStore) persist() { // caller holds the write lock
	if t.path == "" {
		return
	}
	data, err := json.MarshalIndent(t.state, "", "  ")
	if err != nil {
		return
	}
	tmp := t.path + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, t.path)
	}
}

// appendLog adds one line to the audit-log file. Append-only, so unlike
// persist() this never rewrites the whole file. Caller holds the write lock.
func (t *TriageStore) appendLog(ev TriageEvent) {
	if t.logPath == "" {
		return
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return
	}
	f, err := os.OpenFile(t.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(data)
	f.Write([]byte("\n"))
}
