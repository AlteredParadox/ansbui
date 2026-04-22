package ansible

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// RunRecord summarises a single ad-hoc or playbook run.
type RunRecord struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"` // "adhoc" or "playbook"
	Server    string    `json:"server"`
	Target    string    `json:"target"`
	Module    string    `json:"module,omitempty"`
	Playbook  string    `json:"playbook,omitempty"`
	Command   string    `json:"command"`
	Status    string    `json:"status"`
	OK        int       `json:"ok"`
	Changed   int       `json:"changed"`
	Failed    int       `json:"failed"`
	Skipped   int       `json:"skipped"`
	Duration  string    `json:"duration"`
	Who       string    `json:"who"`
	StartedAt time.Time `json:"startedAt"`
	EndedAt   time.Time `json:"endedAt"`
	Log       []Event   `json:"log,omitempty"`
}

// Recorder is a thread-safe on-disk list of RunRecords.
type Recorder struct {
	path  string
	mu    sync.Mutex
	runs  []RunRecord
	limit int
}

// NewRecorder loads or creates the run log at the given path.
func NewRecorder(path string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create runs dir: %w", err)
	}
	r := &Recorder{path: path, limit: 200}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &r.runs)
	}
	return r, nil
}

// Append writes a new record and persists. The oldest records are
// dropped once the limit is exceeded.
func (r *Recorder) Append(rec RunRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.runs = append(r.runs, rec)
	sort.Slice(r.runs, func(i, j int) bool { return r.runs[i].StartedAt.After(r.runs[j].StartedAt) })
	if len(r.runs) > r.limit {
		r.runs = r.runs[:r.limit]
	}
	return r.saveLocked()
}

func (r *Recorder) saveLocked() error {
	data, err := json.MarshalIndent(r.runs, "", "  ")
	if err != nil {
		return fmt.Errorf("encode runs: %w", err)
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write runs: %w", err)
	}
	return os.Rename(tmp, r.path)
}

// List returns a copy of the current run records (already sorted newest
// first).
func (r *Recorder) List() []RunRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RunRecord, len(r.runs))
	copy(out, r.runs)
	return out
}

// Get fetches a single run record by id.
func (r *Recorder) Get(id string) (RunRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, run := range r.runs {
		if run.ID == id {
			return run, true
		}
	}
	return RunRecord{}, false
}

// NewID generates a monotonic-ish run id. Not a UUID — good enough for a
// local history file.
func NewID() string {
	return fmt.Sprintf("run-%d", time.Now().UnixMilli())
}
