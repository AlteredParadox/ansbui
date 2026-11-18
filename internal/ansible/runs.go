package ansible

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
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

	// Redaction is the generation of redaction rules this record's
	// saved command line was produced under (see redactionCurrent).
	// Set by the Recorder, not by callers. Absent on records written
	// before the field existed, which is how they are recognised and
	// repaired when the history is loaded.
	Redaction int `json:"redaction,omitempty"`
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
//
// A corrupted runs.json — truncated by a crash mid-write, hand-
// edited badly, hit by disk bit-rot — used to silently fall
// through to an empty in-memory list, and the next Append would
// happily overwrite the file with whatever was in memory: the
// operator lost their entire run history without ever seeing
// an error. We now quarantine the bad file as runs.json.bad-<ts>
// before continuing with empty state, and log the path so the
// operator can recover whatever was readable. NewRecorder still
// succeeds (callers depend on it for boot) — surfacing the file
// without aborting startup is the right balance.
func NewRecorder(path string) (*Recorder, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create runs dir: %w", err)
	}
	r := &Recorder{path: path, limit: 200, lastPlay: make(map[string]LastPlay)}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// First run — start with empty history.
	case err != nil:
		// Any other read failure (permissions, I/O error) must NOT be
		// treated like a missing file: the history may be perfectly
		// intact on disk, and continuing with an empty in-memory list
		// would let the next Append overwrite it. Fail startup so the
		// operator fixes the underlying problem instead.
		return nil, fmt.Errorf("read run history %s: %w", path, err)
	default:
		if jerr := json.Unmarshal(data, &r.runs); jerr != nil {
			r.runs = nil
			quarantined := fmt.Sprintf("%s.bad-%s", path, time.Now().UTC().Format("20060102T150405"))
			if rerr := os.Rename(path, quarantined); rerr != nil {
				log.Printf("runs: %s is corrupt (%v); failed to quarantine: %v", path, jerr, rerr)
			} else {
				log.Printf("runs: %s was corrupt (%v); moved to %s and starting with empty history", path, jerr, quarantined)
				// Belt-and-suspenders: fsync the dir so the
				// quarantine rename survives a power loss
				// during boot. If the dir sync itself fails
				// we just log — the rename already returned
				// success so the in-memory state is correct.
				if ferr := fsyncDir(filepath.Dir(path)); ferr != nil {
					log.Printf("runs: fsync dir after quarantine failed: %v", ferr)
				}
			}
		}
	}
	r.ensureSorted()
	if r.scrubLoadedRuns() {
		if err := r.saveRunsLocked(r.runs); err != nil {
			log.Printf("runs: failed to persist redacted history: %v", err)
		}
	}
	r.rebuildLastPlay()
	return r, nil
}

// scrubLoadedRuns brings every loaded record up to the current
// redaction rules and reports whether anything changed (so the caller
// rewrites the file). Two steps:
//
//   - the key and pattern rules are applied again, to every record at
//     every start, so a rule added in an upgrade reaches history that
//     was stored before it;
//   - a record whose command line was produced the old way is cut
//     where it stops being trustworthy (cutLegacyPreviews), once, and
//     stamped so it is not cut again.
func (r *Recorder) scrubLoadedRuns() bool {
	changed := false
	for i, run := range r.runs {
		redacted := RedactRunRecord(run)
		if redacted.Redaction < redactionCurrent {
			redacted = cutLegacyPreviews(redacted)
			redacted.Redaction = redactionCurrent
		}
		if !reflect.DeepEqual(redacted, run) {
			changed = true
		}
		r.runs[i] = redacted
	}
	return changed
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
	rec = RedactRunRecord(rec)
	// A record arriving here was produced by this binary, so its
	// command line is the redacted-by-value rendering.
	rec.Redaction = redactionCurrent
	// Build the prospective list in a local, attempt to persist it,
	// then commit to memory REGARDLESS of the write outcome. A run that
	// actually executed should stay visible in History for this process
	// even when the disk write fails (read-only FS, disk full) — losing
	// it entirely is worse than a memory/disk divergence, and the
	// returned error lets the caller surface the "not persisted"
	// condition. On success there is no divergence; on failure the
	// operator can still read the run's output until restart.
	newRuns := insertRun(r.runs, rec)
	evicted := false
	if len(newRuns) > r.limit {
		newRuns = newRuns[:r.limit]
		evicted = true
	}
	saveErr := r.saveRunsLocked(newRuns)
	r.runs = newRuns
	// lastPlay is an in-memory index (never persisted).
	if evicted {
		r.rebuildLastPlay()
	} else {
		r.applyRunToLastPlay(rec)
	}
	if saveErr != nil {
		return fmt.Errorf("run recorded in memory but not persisted (will be lost on restart): %w", saveErr)
	}
	return nil
}

// insertRun returns runs with rec inserted in newest-first order,
// without mutating the input slice — the caller commits it to
// r.runs only after a successful persist. The common case (rec at
// least as recent as the head) is a cheap prepend; an out-of-order
// record (clock skew / resumed run) is placed by binary search.
func insertRun(runs []RunRecord, rec RunRecord) []RunRecord {
	out := make([]RunRecord, 0, len(runs)+1)
	if len(runs) == 0 || !rec.StartedAt.Before(runs[0].StartedAt) {
		out = append(out, rec)
		return append(out, runs...)
	}
	idx := sort.Search(len(runs), func(i int) bool {
		return !runs[i].StartedAt.After(rec.StartedAt)
	})
	out = append(out, runs[:idx]...)
	out = append(out, rec)
	return append(out, runs[idx:]...)
}

// saveRunsLocked atomically persists the given record slice. It takes
// the slice as a parameter (rather than reading r.runs) so Append can
// write the prospective new state before committing it to memory,
// keeping disk and memory from diverging on a write failure.
func (r *Recorder) saveRunsLocked(runs []RunRecord) error {
	data, err := json.MarshalIndent(runs, "", "  ")
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
	if err := os.Rename(tmp, r.path); err != nil {
		return err
	}
	// fsync the parent dir so the rename's directory-entry update
	// is durable across power loss — the file's content is already
	// fsynced, but without the dir sync the rename could end up
	// reverted on crash recovery and the new run is "lost".
	return fsyncDir(filepath.Dir(r.path))
}

// fsyncDir flushes a directory's inode so a rename/unlink that
// landed in the journal becomes durable across crashes/power loss.
// Mirrors the helper in internal/config/config.go — kept local
// rather than wired into a shared util package because each
// package only has one writer and a 5-line helper isn't worth
// a new import edge.
func fsyncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir for fsync: %w", err)
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync dir: %w", err)
	}
	return nil
}

// List returns the run records, newest first, WITHOUT their logs: one
// record's log is fetched with Get.
//
// Nothing is redacted here. Every record in r.runs already is — Append
// redacts before storing and NewRecorder scrubs what it loads — and
// that is the only place it can be done once. List used to run the
// redaction pattern over every event of every retained log on each
// call, under the mutex, and then its only caller threw the logs away:
// about half a second per retained MiB during which run completion
// (Append) and every inventory poll (LastPlayPerHost) waited. The
// critical section is now O(number of runs).
func (r *Recorder) List() []RunRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RunRecord, len(r.runs))
	for i, run := range r.runs {
		run.Log = nil
		out[i] = run
	}
	return out
}

// Get fetches a single run record by id, log included. The stored
// record is already redacted (see List). The returned record shares
// its log and replay-input maps with the store: read it, encode it,
// don't modify it.
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

// NewID generates a monotonic-ish run id with a random suffix to
// disambiguate concurrent starts that land in the same millisecond.
// Without the suffix /api/runs/{id} would be ambiguous when two
// WebSocket runs started in the same tick — both records exist in
// the recorder but only one is fetchable by id. 32 bits of entropy
// is overkill for our 200-run window; we round to 8 hex chars
// because it's still a short, copy-pasteable id.
func NewID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand on linux only fails if /dev/urandom is
		// unavailable, which would mean a deeply broken environment.
		// Fall back to a time-only id rather than crash the request —
		// collisions become possible again but the run still records.
		return fmt.Sprintf("run-%d", time.Now().UnixMilli())
	}
	return fmt.Sprintf("run-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b[:]))
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
