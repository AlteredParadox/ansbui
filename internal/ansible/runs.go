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

// Recorder is a thread-safe on-disk list of RunRecords plus a small
// hostname → most-recent-playbook index that the inventory endpoint
// reads on every request. The index is maintained incrementally so a
// poll never has to walk the whole event log under the mutex.
type Recorder struct {
	path     string
	mu       sync.Mutex
	runs     []RunRecord
	limit    int
	lastPlay map[string]LastPlay
}

// NewRecorder loads or creates the run log at the given path.
func NewRecorder(path string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create runs dir: %w", err)
	}
	r := &Recorder{path: path, limit: 200, lastPlay: make(map[string]LastPlay)}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &r.runs)
	}
	r.ensureSorted()
	r.rebuildLastPlay()
	return r, nil
}

// Append writes a new record and persists. Records are kept newest
// first; since wall-clock time is effectively monotonic for our use
// the record prepends cheaply, avoiding an O(n log n) sort on every
// run. The oldest records are dropped once the limit is exceeded.
//
// The lastPlay index is updated incrementally for the new record on
// the common path. When the limit kicks in and a record is dropped,
// the index is rebuilt from scratch to clear references to the
// evicted run.
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
	evicted := false
	if len(r.runs) > r.limit {
		r.runs = r.runs[:r.limit]
		evicted = true
	}
	if evicted {
		r.rebuildLastPlay()
	} else {
		r.applyRunToLastPlay(rec)
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
// host looked like — populated by walking the recorded runs newest-
// first and stopping at the first recap mention for each host. `At`
// is the run's StartedAt, not the moment the recap line landed, so
// for very long plays the timestamp is "when this attempt began".
type LastPlay struct {
	Playbook string    `json:"playbook"`
	At       time.Time `json:"at"`
	Status   string    `json:"status"`
}

// LastPlayPerHost returns, for every host that appears in some
// playbook run's PLAY RECAP, the most recent playbook that targeted
// it. Cancelled / failed runs still count — the recap line tells us
// the runner *attempted* the host, which is what the UI's "Last
// play" column wants to show.
//
// The result is a snapshot of the incrementally-maintained
// r.lastPlay index, so the call is O(distinct hosts) under the
// mutex with no Log iteration. That keeps inventory polls from
// stalling streaming Append calls on a large run history.
func (r *Recorder) LastPlayPerHost() map[string]LastPlay {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]LastPlay, len(r.lastPlay))
	for k, v := range r.lastPlay {
		out[k] = v
	}
	return out
}

// applyRunToLastPlay folds rec's PLAY RECAP entries into the index.
// Caller must hold r.mu. A host's existing entry is preserved when
// the existing run is at least as recent as rec — the merge stays
// "newest play wins" even when rec arrived out of order.
func (r *Recorder) applyRunToLastPlay(rec RunRecord) {
	if rec.Kind != "playbook" {
		return
	}
	for _, evt := range rec.Log {
		if evt.Host == "" || !strings.HasPrefix(evt.Type, "recap") {
			continue
		}
		if existing, ok := r.lastPlay[evt.Host]; ok && !rec.StartedAt.After(existing.At) {
			continue
		}
		r.lastPlay[evt.Host] = LastPlay{
			Playbook: rec.Playbook,
			At:       rec.StartedAt,
			Status:   rec.Status,
		}
	}
}

// rebuildLastPlay reconstructs the index from r.runs. Used at
// startup (NewRecorder) and after the limit-cap eviction in Append
// drops one or more records — rebuilding lets the index forget
// about runs that no longer exist on disk. Caller must hold r.mu.
func (r *Recorder) rebuildLastPlay() {
	r.lastPlay = make(map[string]LastPlay)
	for _, run := range r.runs {
		r.applyRunToLastPlay(run)
	}
}
