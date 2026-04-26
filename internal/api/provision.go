package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/AlteredParadox/ansbui/internal/jobs"
	"github.com/AlteredParadox/ansbui/internal/provision"
)

// httpProvisionStart kicks off a provisioning run as a backend
// job and returns the job ID. The orchestrator goroutine survives
// the request lifetime — the operator's tab can disconnect at any
// point without aborting the run, and the same or a different tab
// can re-attach via the stream endpoint to follow progress. Cancel
// is a separate explicit endpoint.
func (s *Server) httpProvisionStart(w http.ResponseWriter, r *http.Request) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var req provision.Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
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
	job := s.Jobs.Start("provision", summary, func(ctx context.Context, emit func(typ, text string)) error {
		return provision.Run(ctx, pool, srv, req, ctrlPrivKey, emit)
	})
	writeJSON(w, http.StatusOK, map[string]string{"jobId": job.ID})
}

// httpProvisionList returns all known provisioning jobs, most
// recent first. Used by the UI to surface a "you have an active
// run" banner on the Provision view, and as a convenience for
// listing recent finished runs.
func (s *Server) httpProvisionList(w http.ResponseWriter, _ *http.Request) {
	all := s.Jobs.List()
	out := make([]jobs.Snapshot, 0, len(all))
	for _, snap := range all {
		if snap.Kind == "provision" {
			out = append(out, snap)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": out})
}

// httpProvisionGet returns a single job's snapshot.
func (s *Server) httpProvisionGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("unknown job id"))
		return
	}
	writeJSON(w, http.StatusOK, job.Snapshot())
}

// httpProvisionCancel signals the orchestrator's context. The job
// is expected to honour cancellation promptly and return.
func (s *Server) httpProvisionCancel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("unknown job id"))
		return
	}
	job.Cancel()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// wsProvisionStream attaches the WebSocket peer to a running (or
// finished) provisioning job. The peer first receives the full
// backlog of buffered events, then live-tails new events until the
// job ends. Closing the WS does NOT cancel the job — that's the
// whole point of the detached-job model.
func (s *Server) wsProvisionStream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, ok := s.Jobs.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("unknown job id"))
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

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
	// Provisioning.jsx already understands: {type, text}.
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
				// off the final status — provision.Run already
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

func writeJobEvent(conn wsWriter, e jobs.Event) error {
	return conn.WriteJSON(map[string]any{
		"type": e.Type,
		"text": e.Text,
		"seq":  e.Seq,
		"time": e.Time,
	})
}

func writeTerminalEvent(conn wsWriter, snap jobs.Snapshot) error {
	switch snap.Status {
	case jobs.StatusSucceeded:
		return conn.WriteJSON(map[string]any{"type": "done", "text": "complete"})
	case jobs.StatusCancelled:
		return conn.WriteJSON(map[string]any{"type": "fail", "text": "cancelled"})
	case jobs.StatusFailed:
		text := snap.Error
		if text == "" {
			text = "failed"
		}
		return conn.WriteJSON(map[string]any{"type": "fail", "text": text})
	}
	return nil
}

// wsWriter is the minimal interface we use against
// *websocket.Conn — keeps writeJobEvent / writeTerminalEvent
// trivially testable.
type wsWriter interface {
	WriteJSON(v any) error
}
