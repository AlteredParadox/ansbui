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
	"context"
	"embed"
	"errors"
	"flag"
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

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/api"
	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/jobs"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
)

//go:embed all:web
var webFS embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address (host:port). Default binds to loopback only — ansbui has no built-in auth, so exposing it requires an explicit override (e.g. -addr 0.0.0.0:8787) and a reverse proxy with auth in front.")
	flag.Parse()

	warnIfExposed(*addr)

	cfg, err := config.New()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	runsPath, err := runsPath()
	if err != nil {
		log.Fatalf("runs path: %v", err)
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
	srv := &api.Server{
		Config:  cfg,
		Pool:    pool,
		Runs:    runs,
		Jobs:    jobMgr,
		WebRoot: webSub,
		Addr:    *addr,
	}

	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
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

// warnIfExposed prints a startup warning when the listen address is
// reachable from outside the loopback interface. ansbui has no
// built-in authentication yet — anyone who can reach the port can
// drive ansible-playbook as the configured SSH user — so the
// operator needs to know they're running it that way.
func warnIfExposed(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// malformed flag; ListenAndServe will complain shortly
		return
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		log.Print("⚠  ansbui is listening on all interfaces and has no built-in auth.")
		log.Print("⚠  Put it behind an SSH tunnel, VPN, or reverse proxy with auth before exposing to untrusted networks.")
		return
	}
	ip := net.ParseIP(host)
	if ip != nil && !ip.IsLoopback() {
		log.Printf("⚠  ansbui is bound to %s (non-loopback) without auth — restrict reachability to trusted networks.", host)
	}
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
