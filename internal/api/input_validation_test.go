package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// startScriptedSSHServer runs an SSH server whose exec handler is a Go
// function, and returns its port.
func startScriptedSSHServer(t *testing.T, run func(cmd string) (stdout string, status uint32)) int {
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
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveScriptedConn(c, conf, run)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func serveScriptedConn(c net.Conn, conf *ssh.ServerConfig, run func(string) (string, uint32)) {
	defer func() { _ = c.Close() }()
	sc, chans, reqs, err := ssh.NewServerConn(c, conf)
	if err != nil {
		return
	}
	defer func() { _ = sc.Close() }()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = ch.Close() }()
			for r := range creqs {
				if r.Type != "exec" {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
					continue
				}
				var payload struct{ Command string }
				_ = ssh.Unmarshal(r.Payload, &payload)
				_ = r.Reply(true, nil)
				out, status := run(payload.Command)
				_, _ = ch.Write([]byte(out))
				code := make([]byte, 4)
				binary.BigEndian.PutUint32(code, status)
				_, _ = ch.SendRequest("exit-status", false, code)
				return
			}
		}()
	}
}

// serverWithControlNode returns a Server whose one connection points
// at an SSH server answering with run.
func serverWithControlNode(t *testing.T, run func(string) (string, uint32)) (*Server, config.Server) {
	t.Helper()
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	// Never write TOFU entries into the real ~/.ssh/known_hosts.
	t.Setenv("ANSBUI_INSECURE_SSH", "1")
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	saved, err := cfg.UpsertServer(config.Server{
		Name: "ctrl", Host: "127.0.0.1", Port: startScriptedSSHServer(t, run),
		User: "ansible", KeyPath: writeClientKey(t),
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	pool := sshpool.New()
	t.Cleanup(pool.Close)
	return &Server{Config: cfg, Pool: pool}, saved
}

type testServerReply struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Version string `json:"version"`
}

func runConnectionTest(t *testing.T, s *Server, id string) testServerReply {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/servers/"+id+"/test", nil)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.testServer(w, req)
	var body testServerReply
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v (body=%s)", err, w.Body.String())
	}
	return body
}

const fakeAnsibleVersion = "ansible [core 2.99.0]"

// posixControlNode answers the version probe with a fixed line and
// runs everything else through a real local sh, the way sshd hands a
// command to a POSIX login shell.
func posixControlNode(t *testing.T) func(string) (string, uint32) {
	t.Helper()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not installed")
	}
	return func(cmd string) (string, uint32) {
		if strings.HasPrefix(cmd, "ansible --version") {
			return fakeAnsibleVersion + "\n", 0
		}
		var out bytes.Buffer
		c := exec.Command(sh, "-c", cmd) //nolint:gosec // the handler's own probe command
		c.Stdout = &out
		c.Env = []string{"HOME=/nonexistent-home", "PATH=/usr/bin:/bin"}
		if err := c.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return out.String(), uint32(ee.ExitCode()) //nolint:gosec // exit codes are 0..255
			}
			return out.String(), 127
		}
		return out.String(), 0
	}
}

// The connection test passes on a control node with a POSIX login
// shell...
func TestTestServer_PassesShellCheckUnderPOSIXShell(t *testing.T) {
	s, srv := serverWithControlNode(t, posixControlNode(t))
	got := runConnectionTest(t, s, srv.ID)
	if !got.OK || got.Error != "" || got.Version != fakeAnsibleVersion {
		t.Fatalf("connection test = %+v, want ok with the ansible version", got)
	}
}

// ...and fails, saying why and what to change, when the account's
// shell does not hand a quoted value back unchanged.
func TestTestServer_FailsWhenShellMisreadsQuoting(t *testing.T) {
	for name, probeReply := range map[string]func() (string, uint32){
		"word ends early (fish-style)": func() (string, uint32) { return `a'b`, 0 },
		"syntax error":                 func() (string, uint32) { return "", 127 },
	} {
		t.Run(name, func(t *testing.T) {
			s, srv := serverWithControlNode(t, func(cmd string) (string, uint32) {
				if strings.HasPrefix(cmd, "ansible --version") {
					return fakeAnsibleVersion + "\n", 0
				}
				return probeReply()
			})
			got := runConnectionTest(t, s, srv.ID)
			if got.OK {
				t.Fatalf("connection test passed: %+v", got)
			}
			for _, want := range []string{"does not read quoted arguments the way a POSIX shell does", "chsh -s /bin/bash ansible", "fish"} {
				if !strings.Contains(got.Error, want) {
					t.Errorf("error does not mention %q: %s", want, got.Error)
				}
			}
			// ansible itself answered; the reply still says which.
			if got.Version != fakeAnsibleVersion {
				t.Errorf("version = %q, want it reported alongside the shell error", got.Version)
			}
		})
	}
}

// /api/facts takes one plain host name. Anything else is refused with
// a 400 before a command is built — the control node here would fail
// the test if it were sent one.
func TestGetFactsRejectsNonHostNames(t *testing.T) {
	s, srv := serverWithControlNode(t, func(cmd string) (string, uint32) {
		t.Errorf("a command reached the control node: %s", cmd)
		return "", 1
	})
	for name, host := range map[string]string{
		"fish escape":    `x\'"; echo INJECTED #`,
		"ansible option": "-e@/etc/passwd",
		"pattern":        "web*",
		"host list":      "web1,web2",
		"exclusion":      "all:!web1",
		"newline":        "web1\nweb2",
		"spaces inside":  "web1 web2",
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/facts", nil)
			q := req.URL.Query()
			q.Set("server", srv.ID)
			q.Set("host", host)
			req.URL.RawQuery = q.Encode()
			w := httptest.NewRecorder()
			s.getFacts(w, req)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "single host name") {
				t.Fatalf("body does not explain the rule: %s", w.Body.String())
			}
		})
	}
}

// A plain host name still reaches ansible, as one quoted argument.
func TestGetFactsSendsPlainHostName(t *testing.T) {
	var sent []string
	s, srv := serverWithControlNode(t, func(cmd string) (string, uint32) {
		sent = append(sent, cmd)
		return `web-1.example.com | SUCCESS => {"ansible_facts": {"ansible_distribution": "Debian"}}` + "\n", 0
	})
	req := httptest.NewRequest(http.MethodGet, "/api/facts?server="+srv.ID+"&host=web-1.example.com", nil)
	w := httptest.NewRecorder()
	s.getFacts(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body=%s)", w.Code, w.Body.String())
	}
	if len(sent) != 1 || !strings.Contains(sent[0], "ansible 'web-1.example.com' -m ansible.builtin.setup") {
		t.Fatalf("commands sent: %q", sent)
	}
}

// Text from the configured Prometheus endpoint cannot start a new line
// in the server log, or fill it.
func TestTryMetricsLogsOneBoundedLinePerProbe(t *testing.T) {
	t.Setenv("ANSBUI_CONFIG", filepath.Join(t.TempDir(), "config.json"))
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	forged := "boom\n2026/11/18 09:00:00 \"POST\" \"/api/login\" 200 1.234ms  FORGED\r\n" + strings.Repeat("A", 1<<20)
	body, err := json.Marshal(map[string]string{"status": "error", "error": forged})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer prom.Close()

	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if err := cfg.SetSettings(config.SettingsUpdate{PrometheusURL: prom.URL, PrometheusLabel: "instance"}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	s := &Server{Config: cfg}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	result, ok := s.tryMetrics(context.Background())
	log.SetOutput(prev)
	if !ok {
		t.Fatal("tryMetrics reported no result")
	}

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != len(result.Probes) {
		t.Fatalf("%d log lines for %d probes:\n%.600s", len(lines), len(result.Probes), buf.String())
	}
	for _, line := range lines {
		if !strings.Contains(line, "prom: probe ") || !strings.Contains(line, "failed: prometheus error:") {
			t.Fatalf("a log line is not one of ansbui's probe lines: %.200q", line)
		}
		if len(line) > 1024 {
			t.Fatalf("log line is %d bytes", len(line))
		}
		if strings.ContainsRune(line, '\r') {
			t.Fatalf("log line carries a carriage return: %.200q", line)
		}
	}
	if buf.Len() > 16<<10 {
		t.Fatalf("one metrics call wrote %d bytes of log", buf.Len())
	}
}

// A Prometheus URL stored before the base-address rule (here with a
// query string, and a line break for good measure) is refused at fetch
// time, and the refusal is one log line.
func TestTryMetricsRefusesStoredURLWithQuery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	stored, err := json.Marshal(map[string]any{
		"prometheusUrl":       "http://127.0.0.1:9/internal/admin?action=reset&x=",
		"prometheusHostLabel": "instance\nforged line",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, stored, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("ANSBUI_CONFIG", path)
	t.Setenv("ANSBUI_PROM_ALLOWED_HOSTS", "")
	cfg, err := config.New()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if url, _ := cfg.Prometheus(); !strings.Contains(url, "?") {
		t.Skipf("the stored URL was not loaded as written (%q); nothing to refuse", url)
	}
	s := &Server{Config: cfg}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	_, ok := s.tryMetrics(context.Background())
	log.SetOutput(prev)
	if ok {
		t.Fatal("tryMetrics used a Prometheus URL that carries a query string")
	}
	out := strings.TrimRight(buf.String(), "\n")
	if strings.Count(out, "\n") != 0 || !strings.Contains(out, "prom: bad client config:") || !strings.Contains(out, "query string") {
		t.Fatalf("want one 'bad client config' line naming the query string, got:\n%s", out)
	}
}

func TestLogSafe(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"plain text: ok", "plain text: ok"},
		{"a\nb", `a\u000ab`},
		{"a\r\nb", `a\u000d\u000ab`},
		{"tab\there", `tab\u0009here`},
		{"esc\x1b[31m", `esc\u001b[31m`},
		{"sep\u2028x\u2029y\u0085z", `sep\u2028x\u2029y\u0085z`},
		{"ünïcödé 🚀 stays", "ünïcödé 🚀 stays"},
		{"", ""},
	} {
		if got := logSafe(tc.in); got != tc.want {
			t.Errorf("logSafe(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := logSafe(strings.Repeat("é", 4000))
	if len(long) > maxLoggedRemoteText+8 || !strings.HasSuffix(long, "…") {
		t.Fatalf("long text not cut: %d bytes, ends %q", len(long), long[len(long)-6:])
	}
}
