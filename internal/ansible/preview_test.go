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

package ansible

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"github.com/AlteredParadox/ansbui/internal/sshpool"
	"golang.org/x/crypto/ssh"
)

// The "$ ..." line at the top of every run is saved to history and
// served back by the API. These tests cover what it may contain.
//
// It used to be the executed command with RedactText applied. That
// command is JSON inside single-quote shell quoting, and the pattern
// could not find where a secret ended in it: a single quote in the
// value becomes '"'"' and the pattern stopped there, and a list or an
// object has no closing quote where it looked for one. The structured
// copy of the same inputs (RunRecord.ExtraVars) showed <REDACTED>
// while the command line beside it kept the value.

// Markers no test output may contain. Each secret is built so that a
// redaction which stops early leaves a recognisable tail.
const (
	secretHead = "HEAD-1111"
	secretTail = "DUMMY-TAIL-2222"
	secretList = "LIST-TOKEN-3333"
	secretObj  = "NESTED-KEY-4444"
)

func assertNoSecret(t *testing.T, what, text string) {
	t.Helper()
	for _, marker := range []string{secretHead, secretTail, secretList, secretObj} {
		if strings.Contains(text, marker) {
			t.Errorf("%s contains %q:\n%s", what, marker, text)
		}
	}
}

func secretExtraVars() map[string]any {
	return map[string]any{
		// A single quote: shellQuote turns it into '"'"'.
		"db_password": secretHead + "'" + secretTail,
		// A double quote and a backslash: JSON escapes both.
		"api_token": secretHead + `"\` + secretTail,
		// List and object values under a secret-looking key.
		"deploy_tokens": []any{secretList + "-a", secretList + "-b"},
		"registry_credential": map[string]any{
			"user": "ci",
			"key":  secretObj,
		},
		// A secret-looking key nested under an ordinary one.
		"app": map[string]any{"client_secret": secretObj, "region": "eu-west-1"},
		// Ansible's own names for connection secrets.
		"ansible_become_pass": secretHead + secretTail,
		"ansible_ssh_pass":    secretHead + secretTail,
		// Ordinary values stay readable.
		"version": "1.2.3",
	}
}

func TestPlaybookPreviewCarriesNoSecretValues(t *testing.T) {
	srv := config.Server{WorkDir: "/srv/ansible", Inventory: "hosts.yml"}
	req := PlaybookRequest{Path: "staging/deploy.yml", Limit: "web", Tags: []string{"release"}, ExtraVars: secretExtraVars(), Become: true}

	cmd, preview, err := buildPlaybookCmd(srv, req)
	if err != nil {
		t.Fatal(err)
	}
	// The executed command must still carry the real values — the
	// preview is a rendering, not a change to what runs.
	for _, marker := range []string{secretTail, secretList, secretObj} {
		if !strings.Contains(cmd, marker) {
			t.Errorf("executed command lost %q — the run would not get its variables:\n%s", marker, cmd)
		}
	}
	assertNoSecret(t, "preview", preview)
	shown := RedactText(preview) // what runStreaming emits
	assertNoSecret(t, "emitted preview", shown)

	// And it is still the command, recognisably.
	for _, want := range []string{
		"cd '/srv/ansible' && ", "ansible-playbook 'staging/deploy.yml'", "-i 'hosts.yml'",
		"--limit 'web'", "--tags 'release'", "--extra-vars ", "--become",
		"1.2.3", "eu-west-1", redactedValue,
	} {
		if !strings.Contains(shown, want) {
			t.Errorf("emitted preview is missing %q:\n%s", want, shown)
		}
	}
	// Every secret-named key is still named, so the reader can tell a
	// value was supplied.
	for _, key := range []string{"db_password", "api_token", "deploy_tokens", "registry_credential", "client_secret", "ansible_become_pass", "ansible_ssh_pass"} {
		if !strings.Contains(shown, key) {
			t.Errorf("emitted preview no longer names %q:\n%s", key, shown)
		}
	}
}

func TestPlaybookPreviewMatchesCommandWithoutSecrets(t *testing.T) {
	srv := config.Server{WorkDir: "/srv/ansible", Inventory: "hosts.yml"}
	req := PlaybookRequest{
		Path: "site.yml", Limit: "db", Check: true,
		// Entries that are dropped from the command are dropped from
		// the preview too, secret-named or not.
		ExtraVars: map[string]any{"version": "2", "debug": true, "empty": "", "none": nil, "db_password": ""},
	}
	cmd, preview, err := buildPlaybookCmd(srv, req)
	if err != nil {
		t.Fatal(err)
	}
	if cmd != preview {
		t.Errorf("with nothing to redact the preview must be the command\n    cmd: %s\npreview: %s", cmd, preview)
	}
	if strings.Contains(preview, "db_password") || strings.Contains(preview, "empty") {
		t.Errorf("preview shows a variable the command does not send:\n%s", preview)
	}
}

func TestPlaybookPreviewWithVaultPassword(t *testing.T) {
	srv := config.Server{WorkDir: "/srv/ansible"}
	req := PlaybookRequest{Path: "site.yml", VaultPassword: secretHead + secretTail, ExtraVars: map[string]any{"db_password": secretHead + "'" + secretTail}}
	cmd, preview, err := buildPlaybookCmd(srv, req)
	if err != nil {
		t.Fatal(err)
	}
	// Executed: the bash wrapper that reads the password from stdin.
	if !strings.HasPrefix(cmd, "/usr/bin/env bash -c ") || !strings.Contains(cmd, "PASS=$(cat)") {
		t.Errorf("executed command lost the vault wrapper:\n%s", cmd)
	}
	// The vault password is never in either string: it travels on stdin.
	if strings.Contains(cmd, secretHead+secretTail) {
		t.Errorf("vault password is in the executed command:\n%s", cmd)
	}
	shown := RedactText(preview)
	assertNoSecret(t, "emitted preview", shown)
	// Shown: the ansible-playbook line, flag included, wrapper omitted.
	if strings.Contains(shown, "PASS=") || strings.Contains(shown, "bash -c") {
		t.Errorf("preview shows the vault plumbing:\n%s", shown)
	}
	if !strings.Contains(shown, "ansible-playbook 'site.yml'") || !strings.Contains(shown, "--vault-password-file=/dev/fd/3") {
		t.Errorf("preview does not show the command that runs:\n%s", shown)
	}
}

func TestAdhocPreviewCarriesNoSecretValues(t *testing.T) {
	srv := config.Server{WorkDir: "/srv/ansible", Inventory: "hosts.yml"}
	req := AdhocRequest{
		Target: "db", Module: "community.mysql.mysql_user", Become: true,
		Args: map[string]string{
			"name":           "app",
			"password":       secretHead + "'" + secretTail,
			"login_password": secretHead + `"` + secretTail,
			"api_token":      secretHead + ` with spaces \ ` + secretTail,
			"priv":           "app.*:ALL",
			"state":          "present",
			"update_passwd":  "", // empty: not sent, so not shown
		},
	}
	cmd, preview, err := buildAdhocCmd(srv, req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cmd, secretTail) {
		t.Errorf("executed command lost the argument value:\n%s", cmd)
	}
	shown := RedactText(preview)
	assertNoSecret(t, "preview", preview)
	assertNoSecret(t, "emitted preview", shown)
	for _, want := range []string{"ansible 'db'", "-m 'community.mysql.mysql_user'", `name="app"`, `priv="app.*:ALL"`, `state="present"`, "--become", redactedValue} {
		if !strings.Contains(shown, want) {
			t.Errorf("emitted preview is missing %q:\n%s", want, shown)
		}
	}
	if strings.Contains(shown, "update_passwd") {
		t.Errorf("preview shows an argument the command does not send:\n%s", shown)
	}

	// Same arguments, same order, in both: only the values differ.
	plain := AdhocRequest{Target: "web", Module: "ansible.builtin.copy", Args: map[string]string{"src": "a", "dest": "/b", "mode": "0644", "owner": "root", "group": "root"}}
	for i := 0; i < 20; i++ { // map order would differ between calls
		c, p, err := buildAdhocCmd(srv, plain)
		if err != nil {
			t.Fatal(err)
		}
		if c != p {
			t.Fatalf("with nothing to redact the preview must be the command\n    cmd: %s\npreview: %s", c, p)
		}
	}
}

// End to end: what a client of RunPlaybook / RunAdhoc receives, which
// is what the API streams to the browser and writes to runs.json.
func TestRunEventsCarryNoSecretValues(t *testing.T) {
	t.Setenv("ANSBUI_INSECURE_SSH", "1")
	seen := &execLog{}
	addr := startExitingSSHServer(t, seen)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	srv := config.Server{ID: "preview-test", Host: host, Port: port, User: "test", KeyPath: writeTestClientKey(t), WorkDir: "/srv/ansible"}
	pool := sshpool.New()
	t.Cleanup(pool.Close)

	collect := func(run func(out chan<- Event) error) []Event {
		out := make(chan Event, 64)
		var events []Event
		done := make(chan struct{})
		go func() {
			for ev := range out {
				events = append(events, ev)
			}
			close(done)
		}()
		if err := run(out); err != nil {
			t.Fatalf("run failed: %v", err)
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("event channel was not closed")
		}
		return events
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	check := func(name string, events []Event) {
		t.Helper()
		preview := ""
		for _, ev := range events {
			assertNoSecret(t, name+" event", ev.Text)
			// The API applies RedactEvent again before storing; that
			// must not be what the result depends on, but must not
			// undo it either.
			assertNoSecret(t, name+" stored event", RedactEvent(ev).Text)
			if ev.Type == "meta" && strings.HasPrefix(ev.Text, "$ ") {
				preview = ev.Text
			}
		}
		if preview == "" || !strings.Contains(preview, redactedValue) {
			t.Errorf("%s: no command preview with a redaction marker among %d events: %q", name, len(events), preview)
		}
	}

	check("playbook", collect(func(out chan<- Event) error {
		return RunPlaybook(ctx, pool, srv, PlaybookRequest{Path: "site.yml", ExtraVars: secretExtraVars()}, out)
	}))
	check("ad-hoc", collect(func(out chan<- Event) error {
		return RunAdhoc(ctx, pool, srv, AdhocRequest{Target: "all", Module: "ansible.builtin.shell", Args: map[string]string{"cmd": "true", "password": secretHead + "'" + secretTail}}, out)
	}))

	// The control node did receive the real values.
	got := seen.all()
	if len(got) != 2 || !strings.Contains(got[0], secretList) || !strings.Contains(got[1], secretTail) {
		t.Errorf("the executed commands did not carry the variables: %q", got)
	}
}

type execLog struct {
	mu   sync.Mutex
	cmds []string
}

func (l *execLog) add(cmd string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cmds = append(l.cmds, cmd)
}

func (l *execLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cmds...)
}

// startExitingSSHServer is a fake control node: it accepts any auth,
// records each exec command, prints one line and exits 0.
func startExitingSSHServer(t *testing.T, seen *execLog) string {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(hostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				defer func() { _ = sconn.Close() }()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					if nc.ChannelType() != "session" {
						_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, chReqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						defer func() { _ = ch.Close() }()
						for req := range chReqs {
							if req.Type != "exec" {
								if req.WantReply {
									_ = req.Reply(false, nil)
								}
								continue
							}
							// Payload: uint32 length + command.
							if len(req.Payload) >= 4 {
								seen.add(string(req.Payload[4:]))
							}
							_ = req.Reply(true, nil)
							_, _ = ch.Write([]byte("ok: [fakehost]\n"))
							status := make([]byte, 4)
							binary.BigEndian.PutUint32(status, 0)
							_, _ = ch.SendRequest("exit-status", false, status)
							return
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// Requests that cannot be turned into a command are refused before
// anything is sent, and the run still leaves an error event behind:
// the persisted status is derived from the event stream alone.
func TestRunsRefuseUnbuildableRequests(t *testing.T) {
	srv := config.Server{WorkDir: "/srv/ansible"}
	cases := []struct {
		name string
		run  func(out chan<- Event) error
		want string
	}{
		{"ad-hoc without a target", func(out chan<- Event) error {
			return RunAdhoc(context.Background(), nil, srv, AdhocRequest{Module: "ansible.builtin.ping"}, out)
		}, "target is required"},
		{"ad-hoc without a module", func(out chan<- Event) error {
			return RunAdhoc(context.Background(), nil, srv, AdhocRequest{Target: "all"}, out)
		}, "module is required"},
		{"playbook path that leaves the tree", func(out chan<- Event) error {
			return RunPlaybook(context.Background(), nil, srv, PlaybookRequest{Path: "../site.yml"}, out)
		}, ""},
		{"extra-var with an unsafe name", func(out chan<- Event) error {
			return RunPlaybook(context.Background(), nil, srv, PlaybookRequest{Path: "site.yml", ExtraVars: map[string]any{"a b; rm -rf /": "x"}}, out)
		}, "invalid extra-var name"},
		{"extra-var that cannot be encoded", func(out chan<- Event) error {
			return RunPlaybook(context.Background(), nil, srv, PlaybookRequest{Path: "site.yml", ExtraVars: map[string]any{"fn": func() {}}}, out)
		}, "encode extra-vars"},
		{"vault password with a newline", func(out chan<- Event) error {
			return RunPlaybook(context.Background(), nil, srv, PlaybookRequest{Path: "site.yml", VaultPassword: "a\nb"}, out)
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := make(chan Event, 8)
			err := c.run(out) // nil pool: reaching SSH would panic, and be reported as an internal error
			if err == nil {
				t.Fatal("request accepted")
			}
			if c.want != "" && !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q does not mention %q", err, c.want)
			}
			var events []Event
			for ev := range out {
				events = append(events, ev)
			}
			if len(events) != 1 || events[0].Type != "error" || events[0].Text != err.Error() {
				t.Errorf("want exactly one error event carrying %q, got %+v", err, events)
			}
		})
	}
}

// Every optional flag of the two command lines appears in both the
// command and its preview.
func TestCommandLinesCarryEveryOption(t *testing.T) {
	srv := config.Server{WorkDir: "/srv/ansible", Inventory: "hosts.yml"}
	cmd, preview, err := buildAdhocCmd(srv, AdhocRequest{
		Target: "web", Module: "ansible.builtin.command", Become: true, Check: true, Forks: 7, Timeout: 42,
		// An argument whose name is not a safe identifier is dropped.
		Args: map[string]string{"cmd": "uptime", "bad key": "x"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{cmd, preview} {
		for _, want := range []string{"ansible 'web'", "-i 'hosts.yml'", `-a 'cmd="uptime"'`, "--become", "--check", "--forks 7", "--timeout 42"} {
			if !strings.Contains(line, want) {
				t.Errorf("missing %q in: %s", want, line)
			}
		}
		if strings.Contains(line, "bad key") {
			t.Errorf("an unsafe argument name reached the command line: %s", line)
		}
	}
	// No workDir, no inventory, no arguments: the bare command.
	cmd, preview, err = buildAdhocCmd(config.Server{}, AdhocRequest{Target: "all", Module: "ansible.builtin.ping"})
	if err != nil || cmd != preview || cmd != "ANSIBLE_FORCE_COLOR=0 ansible 'all' -m 'ansible.builtin.ping' 2>&1" {
		t.Errorf("bare ad-hoc command: %q / %q / %v", cmd, preview, err)
	}
	cmd, preview, err = buildPlaybookCmd(config.Server{}, PlaybookRequest{Path: "site.yml"})
	if err != nil || cmd != preview || cmd != "ANSIBLE_FORCE_COLOR=0 ansible-playbook 'site.yml' 2>&1" {
		t.Errorf("bare playbook command: %q / %q / %v", cmd, preview, err)
	}
}
