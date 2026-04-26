// Package jobs provides an in-memory registry of long-running
// orchestrator runs whose lifecycle survives WebSocket disconnects.
//
// The legacy adhoc/playbook handlers tied run lifecycle to the WS
// connection — closing the browser tab killed the run. Provisioning
// (especially with a reinstall step) can take 30+ minutes and
// routinely outlasts a browser session, so we needed a layer where
// the run owns its own goroutine and the WS is just an attached
// observer.
//
// Manager is kind-agnostic: the orchestrator's body is supplied at
// Start time as a closure that captures whatever it needs. The
// design is intentionally cheap to slot under playbook runs later.
package jobs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"
)

// Status is a job's current lifecycle state.
type Status string

const (
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Event is one streamed message produced by the orchestrator.
// Seq is monotonic per job, starting at 1 — clients can use it
// to detect gaps if a slow consumer's buffer overflowed.
type Event struct {
	Seq  int       `json:"seq"`
	Time time.Time `json:"time"`
	Type string    `json:"type"`
	Text string    `json:"text"`
}

// Func is the orchestrator's body. It receives a context that's
// cancelled when the operator hits Cancel (or the manager shuts
// down) and an emit callback that pushes events into the event
// log + every attached subscriber.
type Func func(ctx context.Context, emit func(typ, text string)) error

// Job is a single orchestrator run.
type Job struct {
	ID        string
	Kind      string
	Summary   map[string]string // sanitized request snapshot — never includes secrets
	StartedAt time.Time

	mu      sync.Mutex
	status  Status
	endedAt time.Time
	err     string // human-readable terminal error, if any
	events  []Event
	waiters []*waiter
	cancel  context.CancelFunc
	done    chan struct{}
}

// waiter is one attached subscriber's delivery slot. ch is
// buffered; if the consumer can't keep up we set dropped and skip
// — they re-attach for a fresh backlog rather than blocking
// emit and back-pressuring the orchestrator.
type waiter struct {
	ch      chan Event
	dropped bool
}

// Snapshot is a JSON-friendly view of a Job. EventCount is useful
// for an "active runs" UI that wants to surface "12 events so far"
// without subscribing.
type Snapshot struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Status     Status            `json:"status"`
	Summary    map[string]string `json:"summary,omitempty"`
	StartedAt  time.Time         `json:"startedAt"`
	EndedAt    time.Time         `json:"endedAt,omitempty"`
	Error      string            `json:"error,omitempty"`
	EventCount int               `json:"eventCount"`
}

// Snapshot returns a stable copy of the job's metadata.
func (j *Job) Snapshot() Snapshot {
	j.mu.Lock()
	defer j.mu.Unlock()
	snap := Snapshot{
		ID:         j.ID,
		Kind:       j.Kind,
		Status:     j.status,
		Summary:    j.Summary,
		StartedAt:  j.StartedAt,
		EventCount: len(j.events),
		Error:      j.err,
	}
	if !j.endedAt.IsZero() {
		snap.EndedAt = j.endedAt
	}
	return snap
}

// Cancel signals the orchestrator's context. The orchestrator is
// expected to honour it promptly and return; finish then marks the
// job cancelled. Cancel after the job has finished is a no-op.
func (j *Job) Cancel() {
	j.cancel()
}

// Done returns a channel that closes when the job's terminal
// state is recorded. Useful for tests / shutdown wait.
func (j *Job) Done() <-chan struct{} {
	return j.done
}

// Subscribe returns a snapshot of events emitted so far plus a
// channel that delivers subsequent events. The channel is closed
// when the job ends so the consumer can range over it.
//
// unsub MUST be called when the consumer disconnects to avoid
// leaking the waiter slot. Calling it after the job ends is safe
// (no-op).
func (j *Job) Subscribe() (backlog []Event, events <-chan Event, unsub func()) {
	j.mu.Lock()
	defer j.mu.Unlock()
	backlog = append([]Event(nil), j.events...)
	w := &waiter{ch: make(chan Event, 256)}
	if j.status != StatusRunning {
		// Job already ended — close the channel immediately so the
		// consumer's range exits after draining the backlog.
		close(w.ch)
		return backlog, w.ch, func() {
			// No-op unsub: the waiter was never registered (we
			// short-circuited before append) and the channel is
			// already closed above, so there is nothing for the
			// caller's defer to undo.
		}
	}
	j.waiters = append(j.waiters, w)
	return backlog, w.ch, j.makeUnsub(w)
}

func (j *Job) makeUnsub(target *waiter) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			j.mu.Lock()
			defer j.mu.Unlock()
			for i, w := range j.waiters {
				if w == target {
					j.waiters = append(j.waiters[:i], j.waiters[i+1:]...)
					close(w.ch)
					return
				}
			}
			// Not in list — already removed by finish, which closed
			// the channel itself. Nothing to do.
		})
	}
}

// emit appends an event to the buffered log and fans it out to
// every attached subscriber. The whole operation is under the
// mutex so concurrent finish/Subscribe/emit calls serialize and
// no waiter ever sees a closed channel get sent on. Sends are
// non-blocking: a slow consumer drops events rather than
// back-pressuring the orchestrator.
func (j *Job) emit(typ, text string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status != StatusRunning {
		// Orchestrator emitted after returning. Shouldn't happen
		// (Func contract) but guard so we don't grow events past
		// the terminal state.
		return
	}
	e := Event{Seq: len(j.events) + 1, Time: time.Now().UTC(), Type: typ, Text: text}
	j.events = append(j.events, e)
	for _, w := range j.waiters {
		select {
		case w.ch <- e:
		default:
			w.dropped = true
		}
	}
}

// finish records the terminal state and closes every waiter
// channel. ctxErr is what causes the cancellation branch — when
// the orchestrator returns because ctx was cancelled, we want the
// job marked Cancelled regardless of which error the orchestrator
// chose to return.
func (j *Job) finish(err error, ctxErr error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.status != StatusRunning {
		return
	}
	switch {
	case ctxErr != nil:
		j.status = StatusCancelled
	case err != nil:
		j.status = StatusFailed
		j.err = err.Error()
	default:
		j.status = StatusSucceeded
	}
	j.endedAt = time.Now().UTC()
	for _, w := range j.waiters {
		close(w.ch)
	}
	j.waiters = nil
	close(j.done)
}

// Manager owns the in-memory job registry. The zero value is not
// usable — call New.
type Manager struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

// New returns an empty Manager.
func New() *Manager {
	return &Manager{jobs: make(map[string]*Job)}
}

// Start kicks off a goroutine running fn and returns the new Job.
// The fn closure captures whatever services it needs; the manager
// itself doesn't know what kind of orchestrator it's hosting.
//
// fn is expected to honour ctx and to emit a terminal event
// ("done"/"fail") before returning under normal flow. On cancel
// or panic-equivalent return, callers can rely on Snapshot.Status
// to disambiguate.
func (m *Manager) Start(kind string, summary map[string]string, fn Func) *Job {
	ctx, cancel := context.WithCancel(context.Background())
	job := &Job{
		ID:        newID(),
		Kind:      kind,
		Summary:   summary,
		StartedAt: time.Now().UTC(),
		status:    StatusRunning,
		cancel:    cancel,
		done:      make(chan struct{}),
	}
	m.mu.Lock()
	m.jobs[job.ID] = job
	m.mu.Unlock()
	go func() {
		defer cancel()
		err := fn(ctx, job.emit)
		job.finish(err, ctx.Err())
	}()
	return job
}

// Get returns the job for id, or false if not found.
func (m *Manager) Get(id string) (*Job, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	j, ok := m.jobs[id]
	return j, ok
}

// List returns snapshots of all jobs sorted by start time, most
// recent first.
func (m *Manager) List() []Snapshot {
	m.mu.Lock()
	jobs := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.Unlock()
	out := make([]Snapshot, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, j.Snapshot())
	}
	sort.Slice(out, func(i, k int) bool {
		return out[i].StartedAt.After(out[k].StartedAt)
	})
	return out
}

// ListActive returns snapshots of jobs that are still running.
// Helpful for the UI's "you have a run in progress" banner so it
// doesn't have to filter the full list client-side.
func (m *Manager) ListActive() []Snapshot {
	all := m.List()
	out := make([]Snapshot, 0, len(all))
	for _, s := range all {
		if s.Status == StatusRunning {
			out = append(out, s)
		}
	}
	return out
}

// Shutdown cancels every running job and waits for them to
// finish. Intended for graceful server shutdown — wires through
// the server's signal handler so an in-flight provisioning run
// gets a chance to emit its own "cancelled" event before the
// process exits.
func (m *Manager) Shutdown(ctx context.Context) {
	m.mu.Lock()
	jobs := make([]*Job, 0, len(m.jobs))
	for _, j := range m.jobs {
		jobs = append(jobs, j)
	}
	m.mu.Unlock()
	for _, j := range jobs {
		j.Cancel()
	}
	for _, j := range jobs {
		select {
		case <-j.Done():
		case <-ctx.Done():
			return
		}
	}
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable — fall back to a
		// time-based ID so we don't panic the whole binary just
		// because /dev/urandom is briefly unavailable.
		return "j" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
