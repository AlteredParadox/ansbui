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

package sshpool

import (
	"bytes"
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
	"golang.org/x/crypto/ssh/knownhosts"
)

// A host name that reaches the known_hosts writer with pattern syntax
// in it used to be written as it was. With a newline in an IPv6 zone
// the second line was any entry the caller chose — a bare "*" pattern
// with their own key, which every later host-key check then accepted
// for hosts that already had a different key pinned.

const hostileZoneHost = "::1%a\n* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK #"

func TestAppendKnownHostRefusesPatternSyntax(t *testing.T) {
	key := mustEd25519Key(t)
	remote := &net.TCPAddr{IP: net.ParseIP("::1"), Port: 22}
	for name, hostname := range map[string]string{
		"newline in zone, port 22":  net.JoinHostPort(hostileZoneHost, "22"),
		"newline in zone, port set": net.JoinHostPort(hostileZoneHost, "38031"),
		"comma and wildcard":        net.JoinHostPort("::1%x,*", "22"),
		"bare wildcard":             "*:22",
		"negation":                  "!ctrl.example.com:22",
		"comment":                   "ctrl#x:22",
		"marker":                    "@cert-authority:22",
		"hashed prefix":             "|1|salt|hash:22",
		"space":                     "ctrl example:22",
		"question mark":             "ctrl?:2222",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			cb, err := knownHostsCallback(path)
			if err != nil {
				t.Fatalf("init callback: %v", err)
			}
			err = cb(hostname, remote, key)
			if err == nil || !strings.Contains(err.Error(), "refusing to record a host key") {
				t.Fatalf("callback error = %v, want the refusal", err)
			}
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("read known_hosts: %v", rerr)
			}
			if len(data) != 0 {
				t.Fatalf("known_hosts was written:\n%s", data)
			}
		})
	}
}

// What the writer still accepts, and that a recorded entry cannot be
// used for a different, pinned host.
func TestAppendKnownHostWritesOrdinaryNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	keyA, keyB := mustEd25519Key(t), mustEd25519Key(t)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 22}
	cb, err := knownHostsCallback(path)
	if err != nil {
		t.Fatalf("init callback: %v", err)
	}
	for _, hostname := range []string{
		"ctrl.example.com:22",
		"ctrl_01.internal:2222",
		"192.0.2.10:22",
		"[2001:db8::1]:22",
		"[2001:db8::1]:2222",
		"[fe80::1%eth0]:22",
	} {
		if err := cb(hostname, remote, keyA); err != nil {
			t.Fatalf("first contact with %q: %v", hostname, err)
		}
	}
	// Each name is its own entry: key B is new to all of them and is a
	// mismatch for every one, including one not literally listed.
	fresh, err := knownHostsCallback(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if err := fresh("ctrl.example.com:22", remote, keyB); err == nil {
		t.Fatal("a different key was accepted for a recorded host")
	}
	data, _ := os.ReadFile(path)
	if n := strings.Count(string(data), "\n"); n != 6 {
		t.Fatalf("known_hosts has %d lines, want 6:\n%s", n, data)
	}
	if got := knownHostsWildcardLines(path); len(got) != 0 {
		t.Fatalf("ordinary entries reported as wildcard lines: %v", got)
	}
}

func TestSafeKnownHostsName(t *testing.T) {
	for _, name := range []string{"ctrl", "ctrl.example.com", "192.0.2.10", "2001:db8::1", "fe80::1%eth0", "[ctrl.example.com]:2222", "[2001:db8::1]:2222"} {
		if !safeKnownHostsName(name) {
			t.Errorf("safeKnownHostsName(%q) = false", name)
		}
	}
	for _, name := range []string{"", "*", "a,b", "a b", "a\nb", "!a", "a#b", "@a", "|1|x", "a?", "[a]:", "[a]:port", "[a b]:22", "[a]:22 x"} {
		if safeKnownHostsName(name) {
			t.Errorf("safeKnownHostsName(%q) = true", name)
		}
	}
	// Normalize is what feeds it; a hostile dial address stays unsafe
	// after normalisation.
	if safeKnownHostsName(knownhosts.Normalize(net.JoinHostPort(hostileZoneHost, "22"))) {
		t.Error("normalised hostile address passed")
	}
}

// dial refuses such a record before it opens a connection, so a host
// stored by an older release cannot reach the writer either.
func TestDialRefusesInvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dial(ctx, config.Server{ID: "x", Host: hostileZoneHost, Port: 22, User: "ansible", KeyPath: "/nonexistent"})
	if err == nil || !strings.Contains(err.Error(), "host cannot be used") {
		t.Fatalf("dial error = %v, want the host refusal", err)
	}
}

// Existing wildcard entries are reported by line number, once.
func TestKnownHostsWildcardWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	content := strings.Join([]string{
		"# comment with * in it",
		"ctrl.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA",
		"* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB",
		"",
		"|1|c2FsdA==|aGFzaA== ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC",
		"::1%x,* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID",
		"@cert-authority *.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE",
		"@revoked ctrl.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF",
		"web?.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG",
		"@cert-authority",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got, want := strings.Join(knownHostsWildcardLines(path), ","), "3,6,7,9"; got != want {
		t.Fatalf("wildcard lines = %s, want %s", got, want)
	}
	if got := knownHostsWildcardLines(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatalf("missing file reported lines %v", got)
	}

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	warnKnownHostsWildcardsOnce(path)
	warnKnownHostsWildcardsOnce(path)
	out := buf.String()
	if strings.Count(out, "wildcard host patterns") != 1 {
		t.Fatalf("want exactly one warning, got:\n%s", out)
	}
	if !strings.Contains(out, "line(s) 3, 6, 7, 9") {
		t.Fatalf("warning does not list the lines:\n%s", out)
	}
	if strings.Contains(out, "AAAAC3") {
		t.Fatalf("warning repeats key material:\n%s", out)
	}

	// A clean file logs nothing.
	buf.Reset()
	clean := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(clean, []byte("ctrl.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	warnKnownHostsWildcardsOnce(clean)
	if buf.Len() != 0 {
		t.Fatalf("clean file produced a warning:\n%s", buf.String())
	}
}

// The two layers agree: every host the server record accepts produces
// a known_hosts name the writer accepts, on the default port and on
// another one. If they drifted apart, a valid connection would dial
// and then fail to record its key.
func TestAcceptedServerHostsAreWritable(t *testing.T) {
	for _, host := range []string{
		"ctrl", "ctrl.example.com", "ctrl-01.internal", "ctrl_01", "host.example.com.",
		"192.0.2.10", "2001:db8::1", "::1", "fe80::1%eth0", "fe80::1%br-lan.10", "fe80::1%2",
	} {
		if err := config.ValidateServerHost(host); err != nil {
			t.Fatalf("ValidateServerHost(%q) = %v; the list here should hold accepted hosts", host, err)
		}
		for _, port := range []string{"22", "2222"} {
			name := knownhosts.Normalize(net.JoinHostPort(host, port))
			if !safeKnownHostsName(name) {
				t.Errorf("host %q on port %s normalises to %q, which the known_hosts writer refuses", host, port, name)
			}
		}
	}
}
