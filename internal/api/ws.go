package api

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/AlteredParadox/relay/internal/ansible"
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

func (s *Server) wsAdhoc(w http.ResponseWriter, r *http.Request) {
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

	var req ansible.AdhocRequest
	if err := conn.ReadJSON(&req); err != nil {
		_ = conn.WriteJSON(ansible.Event{Type: "error", Text: "decode request: " + err.Error()})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchPeer(conn, cancel)

	events := make(chan ansible.Event, 64)
	run := ansible.RunRecord{
		ID:        ansible.NewID(),
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
	_ = conn.WriteJSON(map[string]string{"type": "run-id", "text": run.ID})

	go func() {
		if err := ansible.RunAdhoc(ctx, s.Pool, srv, req, events); err != nil {
			log.Printf("adhoc run: %v", err)
		}
	}()

	consumeAndPersist(conn, events, &run, s.Runs)
}

func (s *Server) wsPlaybook(w http.ResponseWriter, r *http.Request) {
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

	var req ansible.PlaybookRequest
	if err := conn.ReadJSON(&req); err != nil {
		_ = conn.WriteJSON(ansible.Event{Type: "error", Text: "decode request: " + err.Error()})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchPeer(conn, cancel)

	events := make(chan ansible.Event, 64)
	run := ansible.RunRecord{
		ID:        ansible.NewID(),
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
	_ = conn.WriteJSON(map[string]string{"type": "run-id", "text": run.ID})

	go func() {
		if err := ansible.RunPlaybook(ctx, s.Pool, srv, req, events); err != nil {
			log.Printf("playbook run: %v", err)
		}
	}()

	consumeAndPersist(conn, events, &run, s.Runs)
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
