package ansible

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"golang.org/x/crypto/ssh"
)

func TestValidHostName(t *testing.T) {
	for _, h := range []string{"web1", "web-1.example.com", "db_01", "192.0.2.7", "2001:db8::1", "::1", "localhost", strings.Repeat("a", 253)} {
		if !ValidHostName(h) {
			t.Errorf("ValidHostName(%q) = false", h)
		}
	}
	for name, h := range map[string]string{
		"empty":             "",
		"option":            "-e",
		"long option":       "--inventory=/etc/passwd",
		"space":             "web1 web2",
		"fish escape":       `x\'"; echo INJECTED #`,
		"quote":             "web'1",
		"semicolon":         "web1;id",
		"pattern":           "web*",
		"exclusion":         "all:!web1",
		"comma list":        "web1,web2",
		"newline":           "web1\nweb2",
		"carriage return":   "web1\r",
		"line separator":    "web1\u2028x",
		"yaml mapping":      "a: b",
		"delegation":        "web1 -> localhost",
		"bracket":           "web[1:3]",
		"too long":          strings.Repeat("a", 254),
		"non-ASCII":         "wéb1",
		"trailing new line": "web1\n",
	} {
		if ValidHostName(h) {
			t.Errorf("%s: ValidHostName(%q) = true", name, h)
		}
	}
}

// classify keeps the type of a line and drops a host it cannot vouch
// for. The names here are what a managed host can put in its own
// command output.
func TestClassifyHostIsAPlainName(t *testing.T) {
	for _, tc := range []struct {
		line     string
		wantType string
		wantHost string
	}{
		{"ok: [web1]", "ok", "web1"},
		{"changed: [web-1.example.com]", "changed", "web-1.example.com"},
		{"fatal: [2001:db8::1]: FAILED! => {}", "fail", "2001:db8::1"},
		{"unreachable: [db_01]: UNREACHABLE!", "fail", "db_01"},
		{"skipping: [web1]", "meta", "web1"},
		// A delegated task names the inventory host before the arrow.
		{"fatal: [web1 -> localhost]: FAILED! => {}", "fail", "web1"},
		{"ok: [web1 -> 192.0.2.9]", "ok", "web1"},
		// Still a failure line, but no usable host.
		{"fatal: [web1\u2028  pre_tasks:\u2028    - ansible.builtin.debug: msg=INJECTED]: FAILED! => {}", "fail", ""},
		{"fatal: [web2\r  become: true]: FAILED! => {}", "fail", ""},
		{"fatal: [a: b]: FAILED!", "fail", ""},
		{"fatal: [web1,web2]: FAILED!", "fail", ""},
		{"fatal: [all:!web1]: FAILED!", "fail", ""},
		{"fatal: [-e @/etc/shadow]: FAILED!", "fail", ""},
		{"unreachable: [" + strings.Repeat("h", 300) + "]: UNREACHABLE!", "fail", ""},
		// Recap rows: the host is the first non-space run.
		{"web1                       : ok=2    changed=1    unreachable=0    failed=0", "recap-warn", "web1"},
		{"web1                       : ok=2    changed=0    unreachable=0    failed=1", "recap-fail", "web1"},
		{"web*,db1                   : ok=2    changed=0    unreachable=0    failed=1", "recap-fail", ""},
		{"{x}                        : ok=2    changed=0    unreachable=1    failed=0", "recap-fail", ""},
	} {
		got := classify(tc.line, "stdout")
		if got.Type != tc.wantType || got.Host != tc.wantHost {
			t.Errorf("classify(%.60q) = type %q host %q, want type %q host %q", tc.line, got.Type, got.Host, tc.wantType, tc.wantHost)
		}
		if got.Text != tc.line {
			t.Errorf("classify(%.60q) changed the text", tc.line)
		}
	}
}

// The facts lookup refuses a host that is not a plain name before it
// touches the control node (the pool here is unusable on purpose).
func TestGatherFactsRefusesNonHostNames(t *testing.T) {
	for _, host := range []string{`x\'"; echo INJECTED #`, "-e@/etc/passwd", "web1,web2", "web*", "web1\n"} {
		_, err := GatherFacts(context.Background(), nil, config.Server{}, host)
		if !errors.Is(err, ErrFactsHost) {
			t.Errorf("GatherFacts(%q) error = %v, want ErrFactsHost", host, err)
		}
	}
}

// execServer is an in-process SSH server whose exec handler is a Go
// function, so a test decides what the "login shell" does with the
// command string it is sent.
func startExecServer(t *testing.T, run func(cmd string) (stdout string, status uint32)) *ssh.Client {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveExecConn(conn, cfg, run)
		}
	}()
	cli, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // loopback test server
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial exec server: %v", err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

func serveExecConn(conn net.Conn, cfg *ssh.ServerConfig, run func(string) (string, uint32)) {
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
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

// localShell runs cmd the way sshd would hand it to a POSIX login
// shell.
func localShell(t *testing.T, shell string) func(string) (string, uint32) {
	t.Helper()
	path, err := exec.LookPath(shell)
	if err != nil {
		t.Skipf("%s not installed", shell)
	}
	return func(cmd string) (string, uint32) {
		var out bytes.Buffer
		c := exec.Command(path, "-c", cmd) //nolint:gosec // the test's own probe command
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

// The probe passes under real POSIX shells: the quoted value comes
// back byte for byte, with nothing expanded or split.
func TestCheckShellQuotingPassesUnderPOSIXShells(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "dash", "zsh", "ksh"} {
		t.Run(shell, func(t *testing.T) {
			cli := startExecServer(t, localShell(t, shell))
			if err := CheckShellQuoting(context.Background(), cli); err != nil {
				t.Fatalf("CheckShellQuoting under %s: %v", shell, err)
			}
		})
	}
}

// fishSingleQuoted is how fish reads the probe's quoted word, per its
// documented rule that inside single quotes a backslash escapes a
// following quote or backslash: the word ends early at what POSIX
// treats as an ordinary character.
func fishSingleQuoted(cmd string) (string, uint32) {
	const prefix = "printf '%s' '"
	if !strings.HasPrefix(cmd, prefix) {
		return "", 127
	}
	var word strings.Builder
	rest := cmd[len(prefix):]
	for i := 0; i < len(rest); i++ {
		switch {
		case rest[i] == '\\' && i+1 < len(rest) && (rest[i+1] == '\'' || rest[i+1] == '\\'):
			word.WriteByte(rest[i+1])
			i++
		case rest[i] == '\'':
			return word.String(), 0 // word ended; fish would go on to parse the tail as syntax
		default:
			word.WriteByte(rest[i])
		}
	}
	return "", 127 // unterminated quote
}

func TestCheckShellQuotingDetectsOtherShells(t *testing.T) {
	for name, run := range map[string]func(string) (string, uint32){
		"fish-style single quotes": fishSingleQuoted,
		"syntax error":             func(string) (string, uint32) { return "", 127 },
		"value expanded":           func(string) (string, uint32) { return strings.ReplaceAll(shellQuoteProbe, "$HOME", "/root"), 0 },
		"empty output":             func(string) (string, uint32) { return "", 0 },
		"trailing newline added":   func(string) (string, uint32) { return shellQuoteProbe + "\n", 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cli := startExecServer(t, run)
			err := CheckShellQuoting(context.Background(), cli)
			if !errors.Is(err, ErrShellQuoting) {
				t.Fatalf("CheckShellQuoting = %v, want ErrShellQuoting", err)
			}
		})
	}
}

// A cancelled check reports the cancellation, not a shell problem.
func TestCheckShellQuotingHonoursContext(t *testing.T) {
	cli := startExecServer(t, func(string) (string, uint32) { return shellQuoteProbe, 0 })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := CheckShellQuoting(ctx, cli)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrShellQuoting) {
		t.Fatalf("CheckShellQuoting with a cancelled context = %v", err)
	}
}

// The probe is only a fair test if it exercises the escape that
// differs between shells, and survives its own quoting.
func TestShellQuoteProbeShape(t *testing.T) {
	if !strings.Contains(shellQuoteProbe, `\'`) {
		t.Fatal("probe lacks the backslash-quote pair that fish treats as an escape")
	}
	quoted := shellQuote(shellQuoteProbe)
	if !strings.HasPrefix(quoted, "'") || !strings.HasSuffix(quoted, "'") || strings.Count(quoted, `'"'"'`) != 1 {
		t.Fatalf("unexpected quoting of the probe: %s", quoted)
	}
}
