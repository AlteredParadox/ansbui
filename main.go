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

// ansbui — web UI for an Ansible control plane.
//
// One Go binary that:
//  1. Serves the embedded React/CSS bundle at /.
//  2. Lets the user configure one or more SSH-accessible "ansible servers".
//  3. Runs ansible-inventory / ansible / ansible-playbook over SSH on the
//     selected server, streaming output to the UI via WebSocket.
//  4. Optionally enriches inventory with live Prometheus metrics for
//     CPU / mem / load / uptime / OS, matched by hostname.
package main

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/api"
	"github.com/AlteredParadox/ansbui/internal/auth"
	"github.com/AlteredParadox/ansbui/internal/bootstrap"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/jobs"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

//go:embed all:web
var webFS embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address (host:port). Default binds to loopback only. Exposing it requires an explicit override (e.g. -addr 0.0.0.0:8787); set a login password with -set-password and/or put a reverse proxy with auth in front.")
	setPassword := flag.Bool("set-password", false, "prompt for a login password, store its hash in the config dir, and exit. Enables built-in authentication; re-run to rotate.")
	allowUnauth := flag.Bool("allow-unauthenticated", false, "start even though no login password is set. Without this (or ANSBUI_ALLOW_UNAUTHENTICATED=1) ansbui refuses to start until -set-password has been run. Only for deployments where something else authenticates every request AND no other user or process on this host can reach the listen address.")
	flag.Parse()

	runsPath, err := runsPath()
	if err != nil {
		log.Fatalf("runs path: %v", err)
	}
	credPath, err := credentialPath()
	if err != nil {
		log.Fatalf("credential path: %v", err)
	}

	if *setPassword {
		if err := runSetPassword(credPath); err != nil {
			log.Fatalf("set-password: %v", err)
		}
		return
	}

	credential, err := auth.LoadCredential(credPath)
	if err != nil {
		log.Fatalf("auth credential: %v", err)
	}
	warnIfExposed(*addr, credential != nil)
	announceAuthPosture(credential != nil, *allowUnauth || envTrue(allowUnauthenticatedEnv), credPath)

	cfg, err := config.New()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	runs, err := ansible.NewRecorder(runsPath)
	if err != nil {
		log.Fatalf("runs recorder: %v", err)
	}

	pool := sshpool.New()
	defer pool.Close()

	webSub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatalf("embed web: %v", err)
	}

	jobMgr := jobs.New()
	// Persist finished bootstrap jobs into the same run history the
	// adhoc/playbook flows write, so a failed run's log survives a
	// restart (the jobs registry itself is memory-only).
	jobMgr.OnFinish = func(j *jobs.Job) { persistBootstrapRun(runs, j) }
	// Trusted reverse proxies for client-IP attribution (login
	// throttling). A typo here must be loud: silently ignoring a bad
	// entry would quietly collapse per-source throttling back into
	// one shared bucket behind the proxy.
	trustedProxies, err := api.ParseTrustedProxies(os.Getenv("ANSBUI_TRUSTED_PROXIES"))
	if err != nil {
		log.Fatalf("ANSBUI_TRUSTED_PROXIES: %v", err)
	}

	srv := &api.Server{
		Config:  cfg,
		Pool:    pool,
		Runs:    runs,
		Jobs:    jobMgr,
		WebRoot: webSub,
		Addr:    *addr,
		// The bootstrap TOFU store lives next to runs.json so it lands
		// in the deployment's writable data dir (ReadWritePaths in the
		// systemd unit covers it).
		BootstrapHostKeys: bootstrap.NewHostKeyStore(filepath.Join(filepath.Dir(runsPath), "bootstrap_known_hosts.json")),
		// Credential is nil when no password is set — the auth
		// middleware then runs in pass-through mode. Sessions is always
		// present so login can populate it if a password is set later
		// without a restart... (a restart is still needed to load a
		// newly-created credential; documented in DEPLOYMENT.md).
		Credential:     credential,
		Sessions:       auth.NewSessionStore(),
		TrustedProxies: trustedProxies,
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds the whole request read (headers + body) so
		// a client trickling a body can't hold a goroutine open —
		// bodies are already capped at 1 MiB, so 60s is generous.
		// IdleTimeout reaps keep-alive connections between requests.
		// Both stop applying to the WebSocket run streams the moment
		// gorilla hijacks the connection; those carry their own write
		// deadlines (ws.go) and peer-watch cancellation.
		//
		// WriteTimeout is deliberately absent: it starts when the
		// request is read and covers the handler's entire execution,
		// and several GET handlers legitimately block on SSH round
		// trips to the control node (inventory fan-out, vault view).
		// Response-side slow-loris protection is the reverse proxy's
		// job in the documented deployment posture.
		ReadTimeout: 60 * time.Second,
		IdleTimeout: 120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		log.Printf("ansbui listening on http://%s", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("http: %v", err)
		}
	}()

	<-ctx.Done()
	log.Printf("shutting down…")
	shutdown(httpSrv, jobMgr)
}

// persistBootstrapRun appends a finished bootstrap job to the run
// history; jobs that don't map to a run record (still running, or
// not a bootstrap) are skipped.
func persistBootstrapRun(runs *ansible.Recorder, j *jobs.Job) {
	rec, ok := api.BootstrapRunRecord(j)
	if !ok {
		return
	}
	if err := runs.Append(rec); err != nil {
		log.Printf("persist bootstrap run %s: %v", rec.ID, err)
	}
}

// allowUnauthenticatedEnv is the environment form of the
// -allow-unauthenticated flag, for service units that configure by
// Environment= lines.
const allowUnauthenticatedEnv = "ANSBUI_ALLOW_UNAUTHENTICATED"

// authPosture is what ansbui does at startup about login: refuse to
// start (fatal non-empty), or start and log notice.
type authPosture struct {
	fatal  string
	notice string
}

// decideAuthPosture is the startup rule for built-in login.
//
// Without a password, every /api route — including the WebSocket
// streams that run ansible — answers anyone who can connect. That
// used to be the default, with a warning in the log. The listener is
// a TCP port on loopback, and TCP carries no identity: every account
// and every process on the host can connect to it, with or without a
// reverse proxy in front, so "bound to loopback" or "the proxy does
// the auth" never separated the operator from other local users. The
// data directory is 0700 for exactly that separation; the API was the
// open door beside it.
//
// So the unauthenticated mode is now something the operator asks for,
// by flag or environment, and gets with a statement of what it means.
//
// ANSBUI_AUTH_REQUIRED keeps its meaning and wins over the opt-out: a
// unit that sets both never starts without a credential. It guards
// the case the opt-out reopens — the credential file going missing
// (incomplete restore, unmounted data dir, accidental delete) under a
// unit that still carries -allow-unauthenticated from before a
// password was set.
func decideAuthPosture(hasCredential, allowUnauthenticated, required bool, credPath string) authPosture {
	switch {
	case hasCredential && allowUnauthenticated:
		return authPosture{notice: "built-in authentication is enabled (login required). ⚠  -allow-unauthenticated / " + allowUnauthenticatedEnv + " is also set: it has no effect while a password exists, but if the credential file were ever lost ansbui would start WITHOUT login. Remove it."}
	case hasCredential:
		return authPosture{notice: "built-in authentication is enabled (login required)."}
	case required:
		return authPosture{fatal: fmt.Sprintf("ANSBUI_AUTH_REQUIRED is set but no credential exists at %s — refusing to start unauthenticated. Restore the file or re-run `ansbui -set-password`.", credPath)}
	case !allowUnauthenticated:
		return authPosture{fatal: fmt.Sprintf("no login password is set (no credential at %s) — refusing to start. Run `ansbui -set-password` and start again. To run without built-in login, start with -allow-unauthenticated (or %s=1): do that only when something else authenticates every request AND no other user or process on this host can reach the listen address, because a reverse proxy does not protect the port from local connections.", credPath, allowUnauthenticatedEnv)}
	default:
		return authPosture{notice: "⚠  running WITHOUT built-in login (-allow-unauthenticated). Anyone who can connect to the listen address has full control of ansible on the control node — that includes every user and process on this host, whatever a reverse proxy in front requires. Run `ansbui -set-password` to require a login."}
	}
}

// announceAuthPosture applies decideAuthPosture: exit, or log the
// posture ansbui is starting in.
func announceAuthPosture(hasCredential, allowUnauthenticated bool, credPath string) {
	p := decideAuthPosture(hasCredential, allowUnauthenticated, authRequired(), credPath)
	if p.fatal != "" {
		log.Fatal(p.fatal)
	}
	log.Print(p.notice)
}

// shutdown drains the HTTP server and the job manager in parallel.
// Sequential ordering is wrong either way:
//   - jobMgr.Shutdown first leaves the HTTP listener accepting
//     new POST /api/bootstrap/start requests during the wait
//     loop, so a job sneaks in past the snapshot.
//   - httpSrv.Shutdown first blocks until in-flight WS handlers
//     exit, but those handlers only exit when their job's
//     events chan closes, which only happens after jobMgr
//     cancels them.
//
// Run in parallel so the listener stops accepting immediately
// (closing the registry to new starts) while job cancellation
// frees the WS handlers httpSrv.Shutdown is waiting on.
func shutdown(httpSrv *http.Server, jobMgr *jobs.Manager) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpDone := make(chan struct{})
	go func() {
		_ = httpSrv.Shutdown(shutdownCtx)
		close(httpDone)
	}()
	jobMgr.Shutdown(shutdownCtx)
	<-httpDone
}

// runSetPassword prompts for a login password twice (echo off),
// confirms they match, and writes the argon2id hash to path. Runs
// as a standalone CLI action (`ansbui -set-password`) and exits; the
// server is never started on this path, so it's safe to run while a
// live instance is up — the new credential takes effect on that
// instance's next restart.
func runSetPassword(path string) error {
	fd := int(os.Stdin.Fd()) //nolint:gosec // G115: a stdin fd is a small non-negative int
	if !term.IsTerminal(fd) {
		return errors.New("-set-password requires an interactive terminal (no piped input) so the password never lands in shell history or argv")
	}
	fmt.Fprint(os.Stderr, "New ansbui login password: ")
	first, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read password: %w", err)
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	second, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return fmt.Errorf("read confirmation: %w", err)
	}
	if !bytes.Equal(first, second) {
		return errors.New("passwords did not match")
	}
	if err := auth.SetCredential(path, string(first)); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Password saved to %s. Restart ansbui for it to take effect.\n", path)
	fmt.Fprint(os.Stderr, "If the service was started with -allow-unauthenticated or "+allowUnauthenticatedEnv+"=1, remove that now: with it set, ansbui would start without login if this file ever went missing.\n")
	return nil
}

// authRequired reports whether the deployment has declared that
// built-in auth must be configured (ANSBUI_AUTH_REQUIRED=1/true).
func authRequired() bool { return envTrue("ANSBUI_AUTH_REQUIRED") }

// envTrue reports whether an on/off environment variable is on: "1"
// or "true" in any case, surrounding space ignored. Same accepted
// values as ANSBUI_INSECURE_SSH. Anything else — including "yes" —
// is off, so a typo never switches a protection off or an opt-out on.
func envTrue(name string) bool {
	v := strings.TrimSpace(os.Getenv(name))
	return v == "1" || strings.EqualFold(v, "true")
}

// warnIfExposed prints a startup warning when the listen address is
// reachable from outside the loopback interface. With no login
// password set, anyone who can reach the port can drive
// ansible-playbook as the configured SSH user; with one set, the
// remaining exposure is the login itself travelling over plain HTTP
// unless TLS terminates in front. Either way the operator needs to
// know they're running it that way.
func warnIfExposed(addr string, authEnabled bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// malformed flag; ListenAndServe will complain shortly
		return
	}
	host = strings.TrimSpace(host)
	exposed := host == "" || host == "0.0.0.0" || host == "::"
	if !exposed {
		ip := net.ParseIP(host)
		exposed = ip != nil && !ip.IsLoopback()
	}
	if !exposed {
		return
	}
	if authEnabled {
		log.Printf("ℹ  ansbui is reachable beyond loopback (%s) with built-in login enabled — for untrusted networks, terminate TLS in front so the password and session cookie don't travel in cleartext.", addr)
		return
	}
	// Only reached when the operator opted out of login (or startup is
	// about to be refused for want of a password).
	log.Printf("⚠  ansbui is set to listen beyond loopback (%s) with NO login password.", addr)
	log.Print("⚠  Set one (-set-password) before exposing it to any network you do not fully control.")
}

func runsPath() (string, error) {
	if p := os.Getenv("ANSBUI_RUNS"); p != "" {
		return p, nil
	}
	if p := os.Getenv("RELAY_RUNS"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "ansbui", "runs.json"), nil
}

// credentialPath resolves where the auth password hash lives. It
// sits next to config.json (it's config, not runtime state), so
// setting ANSBUI_CONFIG alone is enough for `-set-password` — an
// earlier version keyed off the runs dir, which meant the CLI
// silently wrote to $HOME/.config unless ANSBUI_RUNS was also set.
// ANSBUI_AUTH_CREDENTIAL overrides the location outright.
func credentialPath() (string, error) {
	if p := os.Getenv("ANSBUI_AUTH_CREDENTIAL"); p != "" {
		return p, nil
	}
	cfgPath, err := config.DefaultPath()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(cfgPath), "auth_credential"), nil
}
