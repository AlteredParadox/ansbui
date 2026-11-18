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

package bootstrap

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestSshdPortScriptSyntax checks the generated script is valid sh —
// the no-op guard is now a shell function plus a compound if joined
// into the "; "-separated one-liner, which is easy to break.
func TestSshdPortScriptSyntax(t *testing.T) {
	script := sshdPortScript(4242)
	cmd := exec.Command("sh", "-n", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generated script is not valid sh: %v\n%s\nscript:\n%s", err, out, script)
	}
}

// TestSshdPortScriptNoOpGatedOnListener runs just the ground-truth
// guard (the lines up to the config edit) against a fake `ss`, proving
// the early exit follows the actual listener — a box whose config
// already says TARGET but whose listener is still on 22 must NOT
// early-exit (that half-flipped state is exactly what the socket
// remediation exists to fix).
func TestSshdPortScriptNoOpGatedOnListener(t *testing.T) {
	// The guard prelude: the listening() helper, HAVE_SS, and the
	// no-op decision — taken verbatim from the generated script so we
	// exercise the real logic, then a marker if it falls through.
	full := sshdPortScript(4242)
	guard := guardPrelude(t, full) + `; echo PROCEEDED`

	const sshdOwner = `users:(("sshd",pid=812,fd=3))`
	cases := []struct {
		name string
		// what fake `ss -tlnp` prints
		ssLine string
		// active socket unit and the address it listens on, if any
		socketUnit, socketListen string
		wantExitCode             int
		wantOutput               string
		wantProceeded            bool
	}{
		{name: "sshd already on target", ssLine: "LISTEN 0 128 0.0.0.0:4242 0.0.0.0:* " + sshdOwner,
			wantOutput: "already listening"},
		{name: "config flipped but listener still on 22", ssLine: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* " + sshdOwner,
			wantOutput: "PROCEEDED", wantProceeded: true},
		// The operator picks the port now. One taken by another
		// service used to be reported as "sshd already listening":
		// the run went on to write that port into the inventory.
		{name: "another service holds the target port", ssLine: `LISTEN 0 511 0.0.0.0:4242 0.0.0.0:* users:(("nginx",pid=700,fd=6))`,
			wantExitCode: 1, wantOutput: "already in use on the target by something other than sshd"},
		{name: "listener with no owner shown is not assumed to be sshd", ssLine: "LISTEN 0 128 0.0.0.0:4242 0.0.0.0:*",
			wantExitCode: 1, wantOutput: "other than sshd"},
		{name: "ssh socket activation on the target port counts as ssh", ssLine: `LISTEN 0 4096 *:4242 *:* users:(("systemd",pid=1,fd=40))`,
			socketUnit: "ssh.socket", socketListen: "[::]:4242 (Stream)", wantOutput: "already listening"},
		{name: "systemd listening for something else does not", ssLine: `LISTEN 0 4096 *:4242 *:* users:(("systemd",pid=1,fd=40))`,
			socketUnit: "ssh.socket", socketListen: "[::]:22 (Stream)", wantExitCode: 1, wantOutput: "other than sshd"},
		{name: "a port that merely ends in the target is not it", ssLine: "LISTEN 0 128 0.0.0.0:14242 0.0.0.0:* " + sshdOwner,
			wantOutput: "PROCEEDED", wantProceeded: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeStub(t, dir, "ss", "echo '"+c.ssLine+"'")
			// Fake systemctl: one unit may be active, and `show … -p
			// Listen` prints its address.
			writeStub(t, dir, "systemctl", `
case "$1" in
is-active) [ -n "`+c.socketUnit+`" ] && [ "$3" = "`+c.socketUnit+`" ] ;;
show) [ "$2" = "`+c.socketUnit+`" ] && echo 'Listen=`+c.socketListen+`' ;;
*) exit 1 ;;
esac`)
			cmd := exec.Command("sh", "-c", guard)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			got := string(out)
			code := 0
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				code = exitErr.ExitCode()
			} else if err != nil {
				t.Fatalf("run guard: %v", err)
			}
			if code != c.wantExitCode {
				t.Errorf("exit code = %d, want %d (output %q)", code, c.wantExitCode, got)
			}
			if !strings.Contains(got, c.wantOutput) {
				t.Errorf("output %q does not contain %q", got, c.wantOutput)
			}
			if proceeded := strings.Contains(got, "PROCEEDED"); proceeded != c.wantProceeded {
				t.Errorf("proceeded to the config edit = %v, want %v: %q", proceeded, c.wantProceeded, got)
			}
		})
	}
}

// writeStub puts an executable sh script named name into dir.
func writeStub(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// guardPrelude extracts the "; "-joined statements of the generated
// script up to (but not including) the config-edit line, so a test can
// run the listener-based no-op decision in isolation without the edit
// touching /etc/ssh.
func guardPrelude(t *testing.T, script string) string {
	t.Helper()
	parts := strings.Split(script, "; ")
	for i, p := range parts {
		// The config-edit `if` head — the first statement after the
		// no-op guard. `grep -qE` (not the no-ss branch's `grep -hE`)
		// makes it unambiguous.
		if strings.Contains(p, "if grep -qE") && strings.Contains(p, "/etc/ssh/sshd_config") {
			return strings.Join(parts[:i], "; ")
		}
	}
	t.Fatalf("could not find config-edit boundary in script:\n%s", script)
	return ""
}
