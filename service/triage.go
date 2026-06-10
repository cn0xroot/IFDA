package main

import (
	"encoding/json"
	"os"
	"sync"
)

// Triage states mirror the Python core's TriageState (ifda/model.py) so a
// decision made in the UI is the same vocabulary the CLI persists.
var validTriage = map[string]bool{
	"new": true, "confirmed": true, "false_positive": true, "accepted_risk": true,
}

// TriageStore persists analyst triage keyed by finding id (the fingerprint),
// so a decision survives re-scans and applies across jobs (FR-VUL-8). Backed by
// a JSON file; the production drop-in is a shared DB.
type TriageStore struct {
	mu    sync.RWMutex
	path  string
	state map[string]string // finding id -> triage state
}

func NewTriageStore(path string) *TriageStore {
	ts := &TriageStore{path: path, state: map[string]string{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &ts.state)
	}
	return ts
}

// Set records (or clears, when state == "new") a finding's triage.
func (t *TriageStore) Set(findingID, state string) bool {
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
	return true
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

// Overlay rewrites each finding's "triage" field from the store, by id, so the
// served report reflects analyst decisions without re-running analysis.
func (t *TriageStore) Overlay(reportJSON []byte) []byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if len(t.state) == 0 {
		return reportJSON
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(reportJSON, &doc) != nil {
		return reportJSON
	}
	var findings []map[string]interface{}
	if json.Unmarshal(doc["findings"], &findings) != nil {
		return reportJSON
	}
	for _, f := range findings {
		if id, ok := f["id"].(string); ok {
			if st, ok := t.state[id]; ok {
				f["triage"] = st
			}
		}
	}
	if nf, err := json.Marshal(findings); err == nil {
		doc["findings"] = nf
	}
	if out, err := json.Marshal(doc); err == nil {
		return out
	}
	return reportJSON
}
