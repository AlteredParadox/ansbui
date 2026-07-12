package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// The connection probe must answer quickly with ok:false for a
// server it can't reach — it now runs through sshpool.Run, whose
// deadline/caps are what keep a hung probe from retaining the
// handler. This exercises the endpoint through the converted path.
func TestTestServer_UnreachableAnswersFast(t *testing.T) {
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	saved, err := cfg.UpsertServer(config.Server{
		Name: "dead",
		Host: "127.0.0.1",
		Port: 1, // nothing listens on tcp/1
		User: "nobody",
		// No KeyPath and no agent → buildAuth fails fast; even if an
		// agent leaks in from the environment, the dial to :1 refuses.
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	s := &Server{Config: cfg, Pool: sshpool.New()}
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+saved.ID+"/test", nil)
	req.SetPathValue("id", saved.ID)
	w := httptest.NewRecorder()

	start := time.Now()
	s.testServer(w, req)
	if elapsed := time.Since(start); elapsed > 15*time.Second {
		t.Fatalf("probe took %s for an unreachable server", elapsed)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	if body.OK || body.Error == "" {
		t.Fatalf("expected ok:false with an error, got %+v", body)
	}
}

// startHangingSSHServer runs a minimal SSH server that accepts any
// auth, acknowledges exec requests, and then never sends an
// exit-status — the "responsive sshd fronting a hung command" shape
// the probe must be able to abandon. Returns the listen port.
func startHangingSSHServer(t *testing.T) int {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	conf := &ssh.ServerConfig{NoClientAuth: true}
	conf.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			nConn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, conf)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					ch, chReqs, err := newChan.Accept()
					if err != nil {
						continue
					}
					// Acknowledge every request (incl. exec) but never
					// write an exit-status and never close the channel:
					// the client's Wait() blocks until IT closes.
					go func(in <-chan *ssh.Request) {
						for req := range in {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						}
					}(chReqs)
					_ = ch
				}
			}(nConn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// writeClientKey generates an ed25519 client key and writes it in
// OpenSSH PEM form for the pool's KeyPath auth.
func writeClientKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// The probe must abandon a hung `ansible --version` when the request
// context ends — this authenticates successfully and reaches
// sshpool.Run, unlike the unreachable-server case above, so it
// exercises the converted execution path itself.
func TestTestServer_HungProbeHonorsContext(t *testing.T) {
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	// Skip known_hosts verification so the test never writes TOFU
	// entries into the real user's ~/.ssh/known_hosts.
	t.Setenv("ANSBUI_INSECURE_SSH", "1")

	port := startHangingSSHServer(t)
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	saved, err := cfg.UpsertServer(config.Server{
		Name:    "hung",
		Host:    "127.0.0.1",
		Port:    port,
		User:    "test",
		KeyPath: writeClientKey(t),
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	pool := sshpool.New()
	t.Cleanup(pool.Close)
	s := &Server{Config: cfg, Pool: pool}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+saved.ID+"/test", nil).WithContext(ctx)
	req.SetPathValue("id", saved.ID)
	w := httptest.NewRecorder()

	start := time.Now()
	s.testServer(w, req)
	elapsed := time.Since(start)
	// ctx fires at 300ms; Stream then signals, waits its 2s grace,
	// and force-closes the session. Anything near the old behaviour
	// (blocking until the remote answers = forever) fails here.
	if elapsed > 10*time.Second {
		t.Fatalf("hung probe retained the handler for %s", elapsed)
	}
	var body struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	if body.OK || body.Error == "" {
		t.Fatalf("expected ok:false with an error for a cancelled probe, got %+v", body)
	}
}
