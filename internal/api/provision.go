package api

import (
	"context"
	"log"
	"net/http"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/provision"
)

// wsProvision is the WebSocket entry point for one provisioning run.
// The protocol mirrors the adhoc/playbook handlers: the client
// upgrades, sends a single JSON Request, then receives a stream of
// `ansible.Event` messages until the run ends. We intentionally do
// NOT persist the run to runs.json — provisioning is a one-time
// setup and the operator's history view is for play activity.
func (s *Server) wsProvision(w http.ResponseWriter, r *http.Request) {
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

	var req provision.Request
	if err := conn.ReadJSON(&req); err != nil {
		_ = conn.WriteJSON(ansible.Event{Type: "error", Text: "decode request: " + err.Error()})
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchPeer(ctx, conn, cancel)

	events := make(chan ansible.Event, 64)
	go func() {
		if err := provision.Run(ctx, s.Pool, srv, req, events); err != nil {
			log.Printf("provision: %v", err)
		}
	}()

	for evt := range events {
		if err := conn.WriteJSON(evt); err != nil {
			return
		}
	}
}
