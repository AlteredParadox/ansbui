package api

import (
	"context"
	"log"
	"net/http"
	"strings"
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

func sameOriginCheck(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	host := r.Host
	return strings.HasSuffix(origin, "//"+host) || strings.HasSuffix(origin, "://"+host)
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

	var req T
	if err := conn.ReadJSON(&req); err != nil {
		_ = conn.WriteJSON(ansible.Event{Type: "error", Text: "decode request: " + err.Error()})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchPeer(conn, cancel)

	record := buildRecord(srv, &req, ansible.NewID())
	_ = conn.WriteJSON(map[string]string{"type": "run-id", "text": record.ID})

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
// close. The read loop is the canonical way to detect disconnects.
func watchPeer(conn *websocket.Conn, cancel context.CancelFunc) {
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
			if err := conn.WriteJSON(evt); err != nil {
				clientAlive = false
			}
		}
		tallyEvent(run, evt)
		if len(logBuf) < 2000 {
			logBuf = append(logBuf, evt)
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
		_ = conn.WriteJSON(map[string]any{"type": "run-complete", "id": run.ID, "status": run.Status})
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
