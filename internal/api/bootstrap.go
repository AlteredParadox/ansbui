package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/bootstrap"
	"github.com/AlteredParadox/ansbui/internal/jobs"
	"github.com/gorilla/websocket"
)

// errUnknownJobID is returned to clients that hit /jobs/{id} for
// an ID the manager doesn't have in its registry — typically a
// stale localStorage entry from before a backend restart.
var errUnknownJobID = errors.New("unknown job id")

// httpBootstrapStart kicks off a bootstrap run as a backend
// job and returns the job ID. The orchestrator goroutine survives
// the request lifetime — the operator's tab can disconnect at any
// point without aborting the run, and the same or a different tab
// can re-attach via the stream endpoint to follow progress. Cancel
// is a separate explicit endpoint.
func (s *Server) httpBootstrapStart(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var req bootstrap.Request
	if !decodeJSONBody(w, r, &req) {
		// decodeJSONBody applies DisallowUnknownFields + the
		// trailing-data check the vault handlers use, so a
		// misspelled field gets a 400 instead of silently
		// becoming a zero-value that fails Validate later.
		return
	}
	// Validate before creating the job so a malformed/oversized
	// request gets a 400 without filling a registry slot — the
	// job's Summary would otherwise retain the request's verbatim
	// strings until the LRU evictor catches up.
	if err := bootstrap.Validate(req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Canonicalize before snapshotting so the "active runs" banner
	// matches what the orchestrator (and porkbun) actually see.
	// Without this, an operator who enters `2001:DB8::1` sees that
	// literal in the snapshot while the run uses `2001:db8::1` —
	// confusing on re-attach. The trailing ToLower also collapses
	// case-variant hostname addresses so `Host.Example.com` and
	// `host.example.com` share one mutex / snapshot row. Run does
	// the same normalization idempotently as belt-and-suspenders.
	req.IP = strings.TrimSpace(req.IP)
	if ip := net.ParseIP(req.IP); ip != nil {
		req.IP = ip.String()
	}
	req.IP = strings.ToLower(req.IP)
	req.Hostname = strings.ToLower(strings.TrimSpace(req.Hostname))
	// Trim provider/username too. Run trims req.Username later but
	// summary captured the un-trimmed copy first, leaving the
	// active-runs banner showing `"  alice  "` while the
	// orchestrator runs as `alice`.
	req.Provider = strings.TrimSpace(req.Provider)
	req.Username = strings.TrimSpace(req.Username)
	// Summary must NOT contain any of the three secrets the form
	// carries (target password, sudo password, vault password).
	// What we keep is what the operator wants to see in an
	// "active runs" list to recognize their own job.
	summary := map[string]string{
		"ip":       req.IP,
		"hostname": req.Hostname,
		"provider": req.Provider,
		"username": req.Username,
		"server":   srv.Name,
	}
	pool := s.Pool
	// Snapshot the global control-node settings at start time so the
	// orchestrator goroutine doesn't need to hold a Manager
	// reference, and a config edit mid-run can't change which
	// privkey the post-reinstall reconnect uses.
	ctrlPrivKey := s.Config.Snapshot().ControlPrivKeyPath
	hostKeys := s.BootstrapHostKeys
	job, err := s.Jobs.Start("bootstrap", summary, func(ctx context.Context, emit func(typ, text string)) error {
		return bootstrap.Run(ctx, pool, srv, req, ctrlPrivKey, hostKeys, emit)
	})
	if err != nil {
		// Running-cap hit: 503 so the operator's retry hits a
		// fresh slot once an in-flight run finishes.
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"jobId": job.ID})
}

// httpBootstrapList returns all known bootstrap jobs, most
// recent first. Used by the UI to surface a "you have an active
// run" banner on the Bootstrap view, and as a convenience for
// listing recent finished runs.
func (s *Server) httpBootstrapList(w http.ResponseWriter, _ *http.Request) {
	all := s.Jobs.List()
	out := make([]jobs.Snapshot, 0, len(all))
	for _, snap := range all {
		if snap.Kind == "bootstrap" {
			out = append(out, snap)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

// httpBootstrapGet returns a single job's snapshot.
func (s *Server) httpBootstrapGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errUnknownJobID)
		return
	}
	writeJSON(w, http.StatusOK, job.Snapshot())
}

// httpBootstrapLog returns a job's snapshot plus its full buffered
// event log — the REST twin of the WS stream's backlog replay, for
// the "recent runs" panel on the Bootstrap view. Event text is
// already redacted at emit time (bootstrap.Run wraps rawEmit), so
// serving the buffer verbatim can't leak more than the live stream
// did. The log lives only in the jobs registry's memory (up to
// maxRetained jobs), so a backend restart clears it.
func (s *Server) httpBootstrapLog(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errUnknownJobID)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"job":    job.Snapshot(),
		"events": job.Events(),
	})
}

// httpBootstrapCancel signals the orchestrator's context. The job
// is expected to honour cancellation promptly and return.
func (s *Server) httpBootstrapCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errUnknownJobID)
		return
	}
	job.Cancel()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// wsBootstrapStream attaches the WebSocket peer to a running (or
// finished) bootstrap job. The peer first receives the full
// backlog of buffered events, then live-tails new events until the
// job ends. Closing the WS does NOT cancel the job — that's the
// whole point of the detached-job model.
func (s *Server) wsBootstrapStream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errUnknownJobID)
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	// Bound inbound WS message size so a peer can't OOM the
	// server by sending a giant frame — gorilla's default is
	// unlimited. We don't read messages from the peer here
	// (only NextReader for the disconnect signal), but the
	// limit applies to that path too.
	conn.SetReadLimit(wsMaxMessageBytes)

	backlog, events, unsub := job.Subscribe()
	defer unsub()

	// We don't tie ctx to the job — we tie it to the WS lifetime
	// so this handler exits cleanly when the peer disconnects.
	// The job keeps running independently.
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = conn.SetReadDeadline(time.Now())
	}()
	go func() {
		for {
			if _, _, err := conn.NextReader(); err != nil {
				cancel()
				return
			}
		}
	}()

	// Drain backlog first so a re-attached client sees the whole
	// run from the beginning. The shape mirrors what the existing
	// Bootstrap.jsx already understands: {type, text}.
	for _, e := range backlog {
		if err := writeJobEvent(conn, e); err != nil {
			return
		}
	}

	for {
		select {
		case e, ok := <-events:
			if !ok {
				// Job ended. Synthesize a terminal event keyed
				// off the final status — bootstrap.Run already
				// emits "done"/"fail" before returning, but for
				// the cancel path (where Run dies mid-emit) the
				// client needs a stop signal. The frontend's
				// finish-latch dedupes a duplicate done/fail.
				snap := job.Snapshot()
				_ = writeTerminalEvent(conn, snap)
				return
			}
			if err := writeJobEvent(conn, e); err != nil {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

// BootstrapRunRecord converts a finished bootstrap job into the
// RunRecord shape the on-disk run history persists — the jobs
// registry is memory-only, so this is what makes a failed run's log
// survive a backend restart. Returns ok=false for non-bootstrap
// kinds and still-running jobs. Wired into jobs.Manager.OnFinish by
// main.go.
//
// Event text is already redacted (bootstrap.Run wraps emit) and the
// recorder's Append redacts the whole record again, so nothing new
// reaches disk. The sanitized Summary rides in Args — the same
// map[string]string slot ad-hoc records use for replay — so the UI
// can show provider/hostname for restored rows without new fields.
func BootstrapRunRecord(job *jobs.Job) (ansible.RunRecord, bool) {
	snap := job.Snapshot()
	if snap.Kind != "bootstrap" || snap.Status == jobs.StatusRunning {
		return ansible.RunRecord{}, false
	}
	events := job.Events()
	logEvents := make([]ansible.Event, 0, len(events)+1)
	for _, e := range events {
		logEvents = append(logEvents, ansible.Event{Type: e.Type, Text: e.Text})
	}
	// Synthesize the terminal line when the orchestrator died without
	// one (cancel, panic) — mirrors writeTerminalEvent on the WS path,
	// so the persisted log always ends with a verdict.
	if n := len(logEvents); n == 0 || (logEvents[n-1].Type != "done" && logEvents[n-1].Type != "fail") {
		switch snap.Status {
		case jobs.StatusSucceeded:
			logEvents = append(logEvents, ansible.Event{Type: "done", Text: "complete"})
		case jobs.StatusCancelled:
			logEvents = append(logEvents, ansible.Event{Type: "fail", Text: "cancelled"})
		default:
			text := snap.Error
			if text == "" {
				text = "failed"
			}
			logEvents = append(logEvents, ansible.Event{Type: "fail", Text: text})
		}
	}
	okCount, failCount := 0, 0
	for _, e := range logEvents {
		switch e.Type {
		case "ok":
			okCount++
		case "fail":
			failCount++
		}
	}
	status := "err"
	if snap.Status == jobs.StatusSucceeded {
		status = "ok"
	}
	target := snap.Summary["hostname"]
	if target == "" {
		target = snap.Summary["ip"]
	}
	return ansible.RunRecord{
		ID:        snap.ID,
		Kind:      "bootstrap",
		Server:    snap.Summary["server"],
		Target:    target,
		Status:    status,
		OK:        okCount,
		Failed:    failCount,
		Duration:  snap.EndedAt.Sub(snap.StartedAt).Round(time.Millisecond).String(),
		Who:       "ui",
		StartedAt: snap.StartedAt,
		EndedAt:   snap.EndedAt,
		Log:       logEvents,
		Args:      snap.Summary,
	}, true
}

func writeJobEvent(conn *websocket.Conn, e jobs.Event) error {
	return wsWriteJSON(conn, map[string]any{
		"type": e.Type,
		"text": e.Text,
		"seq":  e.Seq,
		"time": e.Time,
	})
}

func writeTerminalEvent(conn *websocket.Conn, snap jobs.Snapshot) error {
	switch snap.Status {
	case jobs.StatusSucceeded:
		return wsWriteJSON(conn, map[string]any{"type": "done", "text": "complete"})
	case jobs.StatusCancelled:
		return wsWriteJSON(conn, map[string]any{"type": "fail", "text": "cancelled"})
	case jobs.StatusFailed:
		text := snap.Error
		if text == "" {
			text = "failed"
		}
		return wsWriteJSON(conn, map[string]any{"type": "fail", "text": text})
	}
	return nil
}
