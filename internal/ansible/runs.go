package ansible

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ensureSorted keeps r.runs newest-first. Called once in NewRecorder
// because on-disk order from older versions of the file might drift;
// Append maintains the invariant by prepending.
func (r *Recorder) ensureSorted() {
	sort.Slice(r.runs, func(i, j int) bool { return r.runs[i].StartedAt.After(r.runs[j].StartedAt) })
}

// RunRecord summarises a single ad-hoc or playbook run. Fields for the
// "other" kind are left at their zero value, so a UI can switch on
// Kind and read only what's relevant.
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

	// Replay fields — captured so the UI can prefill a new run from an
	// existing record. Ad-hoc records use Args/Become/Check/Forks/
	// Timeout; playbook records use Limit/Tags/ExtraVars. Playbook
	// runs also share Become/Check with ad-hoc.
	Args      map[string]string `json:"args,omitempty"`
	Become    bool              `json:"become,omitempty"`
	Check     bool              `json:"check,omitempty"`
	Forks     int               `json:"forks,omitempty"`
	Timeout   int               `json:"timeout,omitempty"`
	Limit     string            `json:"limit,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	ExtraVars map[string]any    `json:"extraVars,omitempty"`
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
	r.ensureSorted()
	return r, nil
}

// Append writes a new record and persists. Records are kept newest
// first; since wall-clock time is effectively monotonic for our use
// the record prepends cheaply, avoiding an O(n log n) sort on every
// run. The oldest records are dropped once the limit is exceeded.
func (r *Recorder) Append(rec RunRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Fast path: new record is at least as recent as the head — prepend.
	if len(r.runs) == 0 || !rec.StartedAt.Before(r.runs[0].StartedAt) {
		r.runs = append([]RunRecord{rec}, r.runs...)
	} else {
		// Out-of-order (clock skew / resumed run) — binary insert.
		idx := sort.Search(len(r.runs), func(i int) bool {
			return !r.runs[i].StartedAt.After(rec.StartedAt)
		})
		r.runs = append(r.runs, RunRecord{})
		copy(r.runs[idx+1:], r.runs[idx:])
		r.runs[idx] = rec
	}
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
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open runs temp: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("write runs temp: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("sync runs temp: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close runs temp: %w", err)
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

// LastPlay records what the most recent playbook against a single
// host looked like — populated by walking r.runs newest-first and
// stopping at the first recap mention for each host.
type LastPlay struct {
	Playbook string
	At       time.Time
	Status   string
}

// LastPlayPerHost returns, for every host that appears in some
// playbook run's PLAY RECAP, the most recent playbook that targeted
// it (path + start time + final run status). Adhoc runs are ignored
// — "last play" means the last actual playbook. The implementation
// trusts the recap entries because those are emitted for every
// targeted host regardless of whether tasks succeeded, failed, or
// were skipped, so a host that was unreachable still shows up.
func (r *Recorder) LastPlayPerHost() map[string]LastPlay {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]LastPlay)
	for _, run := range r.runs {
		if run.Kind != "playbook" {
			continue
		}
		for _, evt := range run.Log {
			if evt.Host == "" || !strings.HasPrefix(evt.Type, "recap") {
				continue
			}
			if _, seen := out[evt.Host]; seen {
				continue
			}
			out[evt.Host] = LastPlay{
				Playbook: run.Playbook,
				At:       run.StartedAt,
				Status:   run.Status,
			}
		}
	}
	return out
}
