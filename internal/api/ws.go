// ansbui — a single-binary web UI for an Ansible control node.
// Copyright (C) 2026 AlteredParadox
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License
// for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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

// wsMaxMessageBytes bounds a single inbound WebSocket message —
// gorilla/websocket's default ReadLimit is unlimited, which would
// let a malicious peer (or a non-browser client whose missing
// Origin header bypasses the same-origin check) buffer arbitrarily
// large frames into the server's memory. The bootstrap request
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

// wsHandshakeWait bounds how long a freshly-upgraded run socket may
// idle before sending its request JSON. The run slot is already held
// at that point (see runWebSocket), so a client that upgrades and
// goes quiet would otherwise pin run capacity indefinitely.
const wsHandshakeWait = 10 * time.Second

// wsWriteJSON applies the write deadline before delegating to
// gorilla's WriteJSON. Centralised so every WS write site picks up
// the bound; gorilla's connection-level timeout knob doesn't exist.
func wsWriteJSON(conn *websocket.Conn, v any) error {
	_ = conn.SetWriteDeadline(time.Now().Add(wsWriteWait))
	return conn.WriteJSON(v)
}

// sameOriginCheck is the WebSocket upgrader's CheckOrigin. It is
// checkSameOrigin reduced to a yes/no, so the upgrader and
// withOriginGuard (which wants the reason for its 403) can't drift.
func sameOriginCheck(r *http.Request) bool {
	return checkSameOrigin(r) == nil
}

// errCrossOrigin is the deliberately terse refusal for a request that
// some other origin's page produced.
var errCrossOrigin = errors.New("cross-origin request rejected")

// checkSameOrigin decides whether r can have come from the page this
// server serves. It returns nil when it can, and the reason when it
// cannot. Two independent signals, both set by the browser and both
// out of reach of page script:
//
//   - Sec-Fetch-Site. Browsers attach it to every request for an
//     https or loopback URL, including the ones that carry no Origin
//     at all (image, script and other no-cors GETs, top-level
//     navigations). Anything other than same-origin or none (the user
//     typed the URL) is another origin's page. "same-site" is refused
//     too: a sibling subdomain, or another port on this host, is not
//     this page.
//
//   - Origin, compared on scheme AND host:port. url.Parse makes the
//     host match resistant to the HasSuffix-bypass trick
//     ("http://evil.com//legit.host:8787"). The scheme matters as much
//     as the host: behind a TLS-terminating proxy that forwards the
//     public Host, https://host and http://host produce the same Host
//     header, so a host-only comparison let a plaintext page for the
//     deployment's own name — which a network attacker can serve —
//     pass as same-origin and drive the run WebSockets with whatever
//     credential the browser attaches across schemes (proxy basic
//     auth, or none on a network-restricted pass-through instance).
//
// A request with neither header is not a browser on a secure origin:
// curl, a script, or a browser on plain-HTTP non-loopback, where
// Sec-Fetch-Site is not sent. This check lets it through; the routes
// where a blind trigger matters are covered by the client-marker rule
// in withOriginGuard.
func checkSameOrigin(r *http.Request) error {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
	default: // cross-site, same-site, or a value this code doesn't know
		return errCrossOrigin
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || u.Host != r.Host {
		return errCrossOrigin
	}
	want := requestScheme(r)
	if strings.EqualFold(u.Scheme, want) {
		return nil
	}
	if want == "http" && strings.EqualFold(u.Scheme, "https") {
		// The one mismatch a legitimate deployment produces: the page
		// was loaded over HTTPS through a proxy that did not say so.
		// Name the fix, since otherwise the UI loads and every action
		// fails with an unexplained 403.
		return errors.New("cross-origin request rejected: the page was loaded over https but this request reached ansbui as plain http — a TLS-terminating reverse proxy must send X-Forwarded-Proto: https")
	}
	return errCrossOrigin
}

// runnerFunc is the shape of ansible.RunAdhoc / ansible.RunPlaybook:
// blocking, streams events into `out`, owns closing the channel.
type runnerFunc[T any] func(ctx context.Context, pool *sshpool.Pool, srv config.Server, req T, out chan<- ansible.Event) error

// buildRecordFunc maps the decoded request into the RunRecord shape
// that goes to the persistence layer. Kept separate so each handler
// only has to know how to describe itself.
type buildRecordFunc[T any] func(srv config.Server, req *T, id string) ansible.RunRecord

// prepFunc is an optional pre-run hook. It runs after the request
// has been decoded but BEFORE buildRecord captures req.* into the
// persisted RunRecord, so any mutation it makes to *req (e.g.
// auto-extending Limit with playbook-annotation hosts) is visible
// to the record. The returned event, if non-empty, is queued onto
// the events channel ahead of the runner's own first emit so the
// operator sees the prep result in the live log.
type prepFunc[T any] func(ctx context.Context, pool *sshpool.Pool, srv config.Server, req *T) ansible.Event

// maxConcurrentRuns bounds adhoc + playbook runs executing at once
// across the whole process. Each run holds an SSH session, two
// scanner goroutines, and an in-memory log buffer; without a cap a
// scripted client (or a stuck tab retrying) could start unbounded
// remote ansible processes. Bootstrap jobs have their own 4-job cap
// in the jobs manager; 8 is generous for human-driven use.
const maxConcurrentRuns = 8

// acquireRunSlot reserves one of the maxConcurrentRuns slots without
// blocking. Callers must releaseRunSlot when the run finishes.
func (s *Server) acquireRunSlot() bool {
	s.runSlotsOnce.Do(func() { s.runSlots = make(chan struct{}, maxConcurrentRuns) })
	select {
	case s.runSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releaseRunSlot() { <-s.runSlots }

// runWebSocket is the shared WS handler behind /api/adhoc/stream and
// /api/playbook/stream. It owns the handshake, request decoding,
// cancellation wiring, logging, and persistence; the only per-kind
// work is the optional prep step, the RunRecord shape, and which
// ansible.RunX function to call.
func runWebSocket[T any](
	s *Server,
	w http.ResponseWriter, r *http.Request,
	kind string,
	prep prepFunc[T],
	buildRecord buildRecordFunc[T],
	run runnerFunc[T],
) {
	srv, err := s.resolveServer(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Reserve the run slot BEFORE upgrading: acquiring after the
	// upgrade let clients open unlimited upgraded-but-idle sockets
	// (each holding a goroutine and buffers) that never submitted a
	// run and so never touched the semaphore. Slot-first means excess
	// connections cost one plain 503 and nothing else.
	if !s.acquireRunSlot() {
		writeError(w, http.StatusServiceUnavailable, fmt.Errorf("too many concurrent runs (limit %d) — wait for one to finish and retry", maxConcurrentRuns))
		return
	}
	defer s.releaseRunSlot()
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(wsMaxMessageBytes)

	// The held slot also means a peer that upgrades and then stalls
	// is now occupying run capacity, so the first read gets a short
	// deadline: send the request promptly or lose the connection.
	// Cleared after the read — the run's own lifetime is governed by
	// watchPeer + ctx from here on.
	var req T
	_ = conn.SetReadDeadline(time.Now().Add(wsHandshakeWait))
	if err := conn.ReadJSON(&req); err != nil {
		_ = wsWriteJSON(conn, ansible.Event{Type: "error", Text: "decode request: " + err.Error()})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	watchPeer(ctx, conn, cancel)

	var prepEvent ansible.Event
	if prep != nil {
		prepEvent = prep(ctx, s.Pool, srv, &req)
	}

	record := buildRecord(srv, &req, ansible.NewID())
	_ = wsWriteJSON(conn, map[string]string{"type": "run-id", "text": record.ID})

	events := make(chan ansible.Event, 64)
	if prepEvent.Type != "" {
		// Buffered chan + sync send: queues ahead of the runner's
		// first emit so consumeAndPersist sees it in source order.
		events <- prepEvent
	}
	go func() {
		if err := run(ctx, s.Pool, srv, req, events); err != nil {
			log.Printf("%s run: %v", kind, err)
		}
	}()

	consumeAndPersist(conn, events, &record, s.Runs)
}

func (s *Server) wsAdhoc(w http.ResponseWriter, r *http.Request) {
	runWebSocket[ansible.AdhocRequest](s, w, r, "adhoc", nil, buildAdhocRecord, ansible.RunAdhoc)
}

func (s *Server) wsPlaybook(w http.ResponseWriter, r *http.Request) {
	runWebSocket(s, w, r, "playbook", prepPlaybook, buildPlaybookRecord, ansible.RunPlaybook)
}

// prepPlaybook applies the playbook's `# ansbui-include:` set to
// req.Limit before the run. Run-time re-read from disk keeps the
// playbook file as the source of truth (the frontend's chip view
// is informational; this is what actually feeds --limit). Doing
// it here — not inside ansible.RunPlaybook — means the merged
// limit lands in buildPlaybookRecord and the persisted History
// entry shows the effective target set.
func prepPlaybook(ctx context.Context, pool *sshpool.Pool, srv config.Server, req *ansible.PlaybookRequest) ansible.Event {
	pb, err := ansible.LoadPlaybook(ctx, pool, srv, req.Path)
	if err != nil {
		return ansible.Event{Type: "meta", Text: "auto-include lookup skipped: " + err.Error()}
	}
	if len(pb.Include) == 0 {
		return ansible.Event{}
	}
	merged := ansible.MergeLimitHosts(req.Limit, pb.Include)
	if merged == req.Limit {
		return ansible.Event{}
	}
	req.Limit = merged
	return ansible.Event{Type: "meta", Text: "auto-including hosts from playbook annotation: " + strings.Join(pb.Include, ", ")}
}

func buildAdhocRecord(srv config.Server, req *ansible.AdhocRequest, id string) ansible.RunRecord {
	return ansible.RunRecord{
		ID:        id,
		Kind:      "adhoc",
		Server:    srv.Name,
		ServerID:  srv.ID,
		Target:    req.Target,
		Module:    req.Module,
		Args:      ansible.RedactStringMap(req.Args),
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
		ServerID:  srv.ID,
		Playbook:  req.Path,
		Target:    req.Limit,
		Limit:     req.Limit,
		Tags:      req.Tags,
		ExtraVars: ansible.RedactAnyMap(req.ExtraVars),
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

// History retention caps for a single run's persisted log. The live
// stream is never capped — these bound what runs.json retains, since
// every record is also held in memory for the recorder's 200-run
// window. Line count alone was not enough: the scanner permits lines
// up to 1 MiB, so 2000 "lines" could legally be gigabytes. Events
// past either cap are dropped with an explicit truncation marker so
// a shortened log can't be mistaken for a complete one.
const (
	maxLogEvents    = 2000
	maxLogBytes     = 1 << 20  // total string bytes per run record, ALL fields
	maxLogEventText = 64 << 10 // per-event Text ceiling
	maxLogEventHost = 1 << 10  // per-event Host ceiling (legit hostnames are ≤253)
)

// capEventStrings bounds every operator-controllable string field of
// one persisted event, marking the cut. Host matters too: classify's
// regexes capture it from raw output lines, so a hostile line can
// put ~1 MiB into Host while Text stays small — capping Text alone
// left the advertised byte budget off by orders of magnitude.
func capEventStrings(evt ansible.Event) ansible.Event {
	if len(evt.Text) > maxLogEventText {
		evt.Text = evt.Text[:maxLogEventText] + "… [event truncated for history]"
	}
	if len(evt.Host) > maxLogEventHost {
		evt.Host = evt.Host[:maxLogEventHost] + "…"
	}
	return evt
}

// eventBytes is the retained-size accounting for one event: every
// string field counts against maxLogBytes, not just Text.
func eventBytes(evt ansible.Event) int {
	return len(evt.Text) + len(evt.Host) + len(evt.Status) + len(evt.Stream) + len(evt.Type)
}

// historyLog accumulates the redacted, capped copy of a run's events
// destined for runs.json. Redaction happens here — the live peer
// already got the real value, but the persisted copy must not carry
// passwords/passphrases to disk. Once either cap trips, further
// events are dropped behind an explicit truncation marker.
type historyLog struct {
	events    []ansible.Event
	bytes     int
	truncated bool
}

func (h *historyLog) add(evt ansible.Event) {
	if h.truncated {
		return
	}
	red := capEventStrings(ansible.RedactEvent(evt))
	if len(h.events) >= maxLogEvents || h.bytes+eventBytes(red) > maxLogBytes {
		h.truncated = true
		h.events = append(h.events, ansible.Event{Type: "meta", Text: fmt.Sprintf("… history log truncated (caps: %d events / %d bytes) — the remaining output was streamed live but not retained", maxLogEvents, maxLogBytes)})
		return
	}
	h.bytes += eventBytes(red)
	h.events = append(h.events, red)
}

func consumeAndPersist(conn *websocket.Conn, events <-chan ansible.Event, run *ansible.RunRecord, rec *ansible.Recorder) {
	hist := historyLog{events: make([]ansible.Event, 0, 256)}
	clientAlive := true
	cancelled := false
	for evt := range events {
		if clientAlive {
			if err := wsWriteJSON(conn, evt); err != nil {
				log.Printf("ws: write to peer failed, draining run locally: %v", err)
				clientAlive = false
			}
		}
		if evt.Type == "cancelled" {
			cancelled = true
		}
		tallyEvent(run, evt)
		hist.add(evt)
	}
	run.EndedAt = time.Now().UTC()
	run.Duration = run.EndedAt.Sub(run.StartedAt).Round(time.Millisecond).String()
	run.Log = hist.events
	run.Status = finalStatus(run, cancelled)
	if err := rec.Append(*run); err != nil {
		log.Printf("persist run: %v", err)
		// The run is still in memory (Append commits regardless), so it
		// shows in History until restart — but the operator needs to
		// know it wasn't durably saved. Surface it in the live log
		// rather than swallowing it into the server log alone.
		if clientAlive {
			_ = wsWriteJSON(conn, map[string]any{"type": "meta", "text": "⚠ run finished but could not be saved to history (visible until restart) — check server logs / disk"})
		}
	}
	if clientAlive {
		_ = wsWriteJSON(conn, map[string]any{"type": "run-complete", "id": run.ID, "status": run.Status})
	}
}

// recapSkippedRE pulls `skipped=N` out of an ansible PLAY RECAP
// line. We don't try to track skipped per-task (classify maps
// `skipping: [host]` to type "meta" because the UI renders them
// that way) so the recap totals are the source of truth, summed
// across hosts the same way OK/Changed/Failed sum across per-task
// events.
var recapSkippedRE = regexp.MustCompile(`\bskipped=(\d+)\b`)

func tallyEvent(run *ansible.RunRecord, evt ansible.Event) {
	switch evt.Type {
	case "ok":
		run.OK++
	case "changed":
		run.Changed++
	case "fail", "error":
		// "error" is a synthetic ansbui event (vault-password
		// validation, runner panic recover) — counting it as a
		// failure keeps finalStatus from labelling a panicked run
		// "ok" just because no per-task events landed.
		run.Failed++
	}
	if strings.HasPrefix(evt.Type, "recap") {
		if m := recapSkippedRE.FindStringSubmatch(evt.Text); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				run.Skipped += n
			}
		}
	}
}

// finalStatus derives the persisted status. Hard failures win;
// otherwise a cancelled run must NOT fall through to "ok"/"warn" —
// tasks that never ran would be indistinguishable from a clean
// finish in History.
func finalStatus(run *ansible.RunRecord, cancelled bool) string {
	switch {
	case run.Failed > 0:
		return "err"
	case cancelled:
		return "cancelled"
	case run.Changed > 0:
		return "warn"
	default:
		return "ok"
	}
}
