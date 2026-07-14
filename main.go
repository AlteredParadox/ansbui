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
	if credential == nil {
		// A deployment that has opted into auth must never silently
		// fall back to the unauthenticated posture: an incomplete
		// restore, a missing data mount, or an accidental delete of
		// the credential file would otherwise expose the control
		// plane after the next restart. The env var lives in the
		// service unit, not the data dir, so it survives exactly the
		// failures it guards against.
		if authRequired() {
			log.Fatalf("ANSBUI_AUTH_REQUIRED is set but no credential exists at %s — refusing to start unauthenticated. Restore the file or re-run `ansbui -set-password`.", credPath)
		}
		log.Print("⚠  no login password is set — the web UI is UNAUTHENTICATED. Run `ansbui -set-password` to enable built-in auth, or keep it behind a reverse proxy / VPN.")
	} else {
		log.Print("built-in authentication is enabled (login required).")
	}

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
	jobMgr.OnFinish = func(j *jobs.Job) {
		rec, ok := api.BootstrapRunRecord(j)
		if !ok {
			return
		}
		if err := runs.Append(rec); err != nil {
			log.Printf("persist bootstrap run %s: %v", rec.ID, err)
		}
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
		Credential: credential,
		Sessions:   auth.NewSessionStore(),
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
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Run the two shutdowns in parallel. Sequential ordering is
	// wrong either way:
	//  - jobMgr.Shutdown first leaves the HTTP listener accepting
	//    new POST /api/bootstrap/start requests during the wait
	//    loop, so a job sneaks in past the snapshot.
	//  - httpSrv.Shutdown first blocks until in-flight WS handlers
	//    exit, but those handlers only exit when their job's
	//    events chan closes, which only happens after jobMgr
	//    cancels them.
	// Run in parallel so the listener stops accepting immediately
	// (closing the registry to new starts) while job cancellation
	// frees the WS handlers httpSrv.Shutdown is waiting on.
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
	fmt.Fprint(os.Stderr, "Tip: set ANSBUI_AUTH_REQUIRED=1 in the service environment so ansbui refuses to start if this file ever goes missing (instead of falling back to unauthenticated).\n")
	return nil
}

// authRequired reports whether the deployment has declared that
// built-in auth must be configured (ANSBUI_AUTH_REQUIRED=1/true).
// Same accepted values as ANSBUI_INSECURE_SSH.
func authRequired() bool {
	v := strings.TrimSpace(os.Getenv("ANSBUI_AUTH_REQUIRED"))
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
	log.Printf("⚠  ansbui is reachable beyond loopback (%s) with NO authentication.", addr)
	log.Print("⚠  Set a login password (-set-password) and/or put it behind an SSH tunnel, VPN, or reverse proxy with auth before exposing to untrusted networks.")
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
