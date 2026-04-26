package api

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"github.com/gorilla/websocket"
)

// wsUpgrader accepts same-origin WebSocket requests only. The client is
// served by this same binary, so there's no need to allow cross-origin.
var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin:     sameOriginCheck,
}

// wsMaxMessageBytes bounds a single inbound WebSocket message —
// gorilla/websocket's default ReadLimit is unlimited, which would
// let a malicious peer (or a non-browser client whose missing
// Origin header bypasses the same-origin check) buffer arbitrarily
// large frames into the server's memory. The provisioning request
// envelope is a few hundred bytes; even an adhoc/playbook
// JSON-decoded request maxes out at low-KB. 64 KiB matches the
// HTTP smallBody ceiling and stays comfortably above any
// legitimate request.
const wsMaxMessageBytes = 64 * 1024

// wsWriteWait bounds how long we'll block on a single WebSocket
// write. Without it, a slow / unresponsive peer (full TCP receive
// buffer, dropped network) wedges the writer indefinitely — and
// because event fan-out is on the orchestrator goroutine path,
// that's a hung run, not just a hung handler. 10 seconds is
// generous for a healthy LAN write while still bounding the worst
// case enough that ctx-cancel can clean up promptly.
const wsWriteWait = 10 * time.Second

// wsWriteJSON applies the write deadline before delegating to
// gorilla's WriteJSON. Centralised so every WS write site picks up
// the bound; gorilla's connection-level timeout knob doesn't exist.
func wsWriteJSON(conn *websocket.Conn, v any) error {
	_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	return conn.WriteJSON(v)
}

// sameOriginCheck compares the parsed Origin header host:port to the
// request's Host. url.Parse makes the match resistant to the
// HasSuffix-bypass trick ("http://evil.com//legit.host:8787"). A
// missing Origin is allowed (non-browser / curl clients).
func sameOriginCheck(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Host == r.Host
}

// runnerFunc is the shape of ansible.RunAdhoc / ansible.RunPlaybook:
// blocking, streams events into `out`, owns closing the channel.
type runnerFunc[T any] func(ctx context.Context, pool *sshpool.Pool, srv config.Server, req T, out chan<- ansible.Event) error

// buildRecordFunc maps the decoded request into the RunRecord shape
// that goes to the persistence layer. Kept separate so each handler
// only has to know how to describe itself.
type buildRecordFunc[T any] func(srv config.Server, req *T, id string) ansible.RunRecord

// runWebSocket is the shared WS handler behind /api/adhoc/stream and
// /api/playbook/stream. It owns the handshake, request decoding,
// cancellation wiring, logging, and persistence; the only per-kind
// work is the RunRecord shape and which ansible.RunX function to call.
func runWebSocket[T any](
	s *Server,
	w http.ResponseWriter, r *http.Request,
	kind string,
	buildRecord buildRecordFunc[T],
	run runnerFunc[T],
) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(wsMaxMessageBytes)

	var req T
	if err := conn.ReadJSON(&req); err != nil {
		_ = wsWriteJSON(conn, ansible.Event{Type: "error", Text: "decode request: " + err.Error()})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchPeer(ctx, conn, cancel)

	record := buildRecord(srv, &req, ansible.NewID())
	_ = wsWriteJSON(conn, map[string]string{"type": "run-id", "text": record.ID})

	events := make(chan ansible.Event, 64)
	go func() {
		if err := run(ctx, s.Pool, srv, req, events); err != nil {
			log.Printf("%s run: %v", kind, err)
		}
	}()

	consumeAndPersist(conn, events, &record, s.Runs)
}

func (s *Server) wsAdhoc(w http.ResponseWriter, r *http.Request) {
	runWebSocket(s, w, r, "adhoc", buildAdhocRecord, ansible.RunAdhoc)
}

func (s *Server) wsPlaybook(w http.ResponseWriter, r *http.Request) {
	runWebSocket(s, w, r, "playbook", buildPlaybookRecord, ansible.RunPlaybook)
}

func buildAdhocRecord(srv config.Server, req *ansible.AdhocRequest, id string) ansible.RunRecord {
	return ansible.RunRecord{
		ID:        id,
		Kind:      "adhoc",
		Server:    srv.Name,
		Target:    req.Target,
		Module:    req.Module,
		Args:      req.Args,
		Become:    req.Become,
		Check:     req.Check,
		Forks:     req.Forks,
		Timeout:   req.Timeout,
		Status:    "running",
		Who:       "ui",
		StartedAt: time.Now().UTC(),
	}
}

func buildPlaybookRecord(srv config.Server, req *ansible.PlaybookRequest, id string) ansible.RunRecord {
	return ansible.RunRecord{
		ID:        id,
		Kind:      "playbook",
		Server:    srv.Name,
		Playbook:  req.Path,
		Target:    req.Limit,
		Limit:     req.Limit,
		Tags:      req.Tags,
		ExtraVars: req.ExtraVars,
		Become:    req.Become,
		Check:     req.Check,
		Status:    "running",
		Who:       "ui",
		StartedAt: time.Now().UTC(),
	}
}

// watchPeer cancels ctx if the websocket peer disconnects or sends a
// close. A parallel goroutine nudges the read side with a deadline
// when ctx ends on its own (run finished, parent cancelled) so the
// blocking NextReader returns promptly instead of parking until the
// deferred Close fires.
func watchPeer(ctx context.Context, conn *websocket.Conn, cancel context.CancelFunc) {
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
}

func consumeAndPersist(conn *websocket.Conn, events <-chan ansible.Event, run *ansible.RunRecord, rec *ansible.Recorder) {
	logBuf := make([]ansible.Event, 0, 256)
	clientAlive := true
	for evt := range events {
		if clientAlive {
			if err := wsWriteJSON(conn, evt); err != nil {
				log.Printf("ws: write to peer failed, draining run locally: %v", err)
				clientAlive = false
			}
		}
		tallyEvent(run, evt)
		if len(logBuf) < 2000 {
			// Redact before buffering: the live peer (above) already
			// got the real value, but the copy destined for runs.json
			// must not persist passwords/passphrases to disk.
			logBuf = append(logBuf, ansible.RedactEvent(evt))
		}
	}
	run.EndedAt = time.Now().UTC()
	run.Duration = run.EndedAt.Sub(run.StartedAt).Round(time.Millisecond).String()
	run.Log = logBuf
	run.Status = finalStatus(run)
	if err := rec.Append(*run); err != nil {
		log.Printf("persist run: %v", err)
	}
	if clientAlive {
		_ = wsWriteJSON(conn, map[string]any{"type": "run-complete", "id": run.ID, "status": run.Status})
	}
}

func tallyEvent(run *ansible.RunRecord, evt ansible.Event) {
	switch evt.Type {
	case "ok":
		run.OK++
	case "changed":
		run.Changed++
	case "fail":
		run.Failed++
	}
}

func finalStatus(run *ansible.RunRecord) string {
	switch {
	case run.Failed > 0:
		return "err"
	case run.Changed > 0:
		return "warn"
	default:
		return "ok"
	}
}
