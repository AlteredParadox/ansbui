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
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Tests for an installer whose sshd answers on port 22 although it was
// given another port. Seen on a real target: the installer wrote
// "Port 4242" into its sshd config after sshd was already running, so
// the box sat at hold 2 on :22 while the run polled :4242 until its
// 45-minute budget ran out.

// keyTarget is an in-process SSH server that accepts any public key
// and answers every exec with a fixed stdout, the way the installer
// answers installerProbeScript.
func startKeyTarget(t *testing.T, stdout string) (host string, port int) {
	t.Helper()
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil },
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns sync.Map
	t.Cleanup(func() {
		_ = ln.Close()
		conns.Range(func(k, _ any) bool {
			_ = k.(net.Conn).Close()
			return true
		})
	})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conns.Store(conn, struct{}{})
			go serveScriptedTarget(conn, cfg, targetAnswersWith, stdout)
		}
	}()
	return "127.0.0.1", ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a local port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func testClientKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

// installerOutput builds what installerProbeScript prints.
func installerOutput(osID string, holdCount, errCount int, logLine string) string {
	return strings.Join([]string{
		"ID=" + osID + "\n",
		"\n" + strconv.Itoa(holdCount) + "\n",
		"\n" + strconv.Itoa(errCount) + "\n",
		"\n" + logLine + "\n",
	}, reinstallProbeMarker)
}

func usePortAsInstallerDefault(t *testing.T, port int) {
	t.Helper()
	old := installerDefaultPort
	installerDefaultPort = port
	t.Cleanup(func() { installerDefaultPort = old })
}

// The reported case: nothing on the requested port, the finished
// installer on the default one. The run must find it there and get an
// open session to continue with.
func TestInstallerFoundOnDefaultPortWhenRequestedPortIsSilent(t *testing.T) {
	host, port := startKeyTarget(t, installerOutput("alpine", 1, 0, "***** HOLD 2 *****"))
	usePortAsInstallerDefault(t, port)
	requested := closedPort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := tryInstallerDone(ctx, host, requested, testClientKey(t), "debian")
	if p.target != nil {
		defer func() { _ = p.target.Close() }()
	}
	if p.verdict != installerHoldDone {
		t.Fatalf("verdict = %d (%q), want hold-done", p.verdict, p.detail)
	}
	if p.port != port || p.target == nil {
		t.Fatalf("probe = port %d, session %v; want the default port %d with an open session", p.port, p.target != nil, port)
	}
	// The session is usable: the hold stage runs its checks over it.
	if _, _, err := p.target.runRoot(ctx, "true", ""); err != nil {
		t.Fatalf("command over the fallback session: %v", err)
	}
	if note := installerPortNote(p.port, requested); !strings.Contains(note, "not on :"+strconv.Itoa(requested)) {
		t.Errorf("job-log note does not name the requested port: %q", note)
	}
}

// When the installer answers where it should, the default port is not
// consulted at all — a listener there must not change the outcome.
func TestInstallerOnRequestedPortIgnoresDefaultPort(t *testing.T) {
	host, requested := startKeyTarget(t, installerOutput("alpine", 0, 0, "Download qcow2 image"))
	_, other := startKeyTarget(t, installerOutput("alpine", 1, 0, "***** HOLD 2 *****"))
	usePortAsInstallerDefault(t, other)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := tryInstallerDone(ctx, host, requested, testClientKey(t), "debian")
	if p.verdict != installerInstalling || p.port != requested || !p.reached {
		t.Fatalf("probe = verdict %d on :%d (reached %v), want still-installing on the requested port %d", p.verdict, p.port, p.reached, requested)
	}
	if installerPortNote(p.port, requested) != "" {
		t.Error("a note was produced although the installer answered on the requested port")
	}
}

// Neither port answers: the result is the requested port's failure,
// so the job log keeps naming the port the run is waiting for.
func TestInstallerOnNeitherPort(t *testing.T) {
	usePortAsInstallerDefault(t, closedPort(t))
	requested := closedPort(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	p := tryInstallerDone(ctx, "127.0.0.1", requested, testClientKey(t), "debian")
	if p.reached || p.verdict != installerInstalling || p.port != requested {
		t.Fatalf("probe = verdict %d on :%d (reached %v), want an unreached still-waiting on :%d", p.verdict, p.port, p.reached, requested)
	}
	if !strings.HasPrefix(p.detail, "dial: ") {
		t.Errorf("detail = %q, want the dial error", p.detail)
	}
}

func TestChooseInstallerProbe(t *testing.T) {
	primary := installerProbe{verdict: installerInstalling, detail: "dial: refused", port: 4242}
	t.Run("an unreached fallback changes nothing", func(t *testing.T) {
		got := chooseInstallerProbe(primary, installerProbe{verdict: installerInstalling, detail: "dial: timeout", port: 22})
		if got != primary {
			t.Fatalf("got %+v, want the primary probe", got)
		}
	})
	t.Run("an installer still working on the fallback port reports its progress", func(t *testing.T) {
		got := chooseInstallerProbe(primary, installerProbe{verdict: installerInstalling, detail: "in installer env (alpine) — Download qcow2 image", port: 22, reached: true})
		if got.verdict != installerInstalling || !strings.Contains(got.detail, "answering on :22, not :4242") || !strings.Contains(got.detail, "Download qcow2 image") {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("an installer error on the fallback port is reported", func(t *testing.T) {
		got := chooseInstallerProbe(primary, installerProbe{verdict: installerErrored, detail: "Line 12 return 1", port: 22, reached: true})
		if got.verdict != installerErrored || got.port != 22 {
			t.Fatalf("got %+v", got)
		}
	})
	// Before the reboot, port 22 may have been the OLD system's. An
	// old system of the same distribution that takes the bootstrap key
	// would answer "this is the target OS"; believing that would skip
	// the installer-stage checks for a machine that was never
	// reinstalled.
	t.Run("a final-OS answer on the fallback port is not believed", func(t *testing.T) {
		got := chooseInstallerProbe(primary, installerProbe{verdict: installerFinalOS, port: 22, reached: true})
		if got.verdict != installerInstalling {
			t.Fatalf("verdict = %d, want still-waiting", got.verdict)
		}
		if !strings.Contains(got.detail, "still waiting for :4242") {
			t.Fatalf("detail = %q", got.detail)
		}
	})
}

// fastInstallerPoll makes the installer-stage loop run without real
// waits.
func fastInstallerPoll(t *testing.T) {
	t.Helper()
	old := installerPoll
	installerPoll.initialWait = time.Millisecond
	installerPoll.retryInterval = 5 * time.Millisecond
	installerPoll.heartbeatPeriod = time.Millisecond
	t.Cleanup(func() { installerPoll = old })
}

// The whole wait, as the run performs it: the requested port is
// silent, the parked installer is on the default port. The wait must
// end with a session on that port and say so in the job log.
func TestWaitForInstallerDoneFindsItOnDefaultPort(t *testing.T) {
	fastInstallerPoll(t)
	host, port := startKeyTarget(t, installerOutput("alpine", 1, 0, "***** HOLD 2 *****"))
	usePortAsInstallerDefault(t, port)
	requested := closedPort(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var log emitLog
	p, err := waitForInstallerDone(ctx, host, requested, testClientKey(t), "debian", log.emit)
	if err != nil {
		t.Fatalf("waitForInstallerDone: %v", err)
	}
	defer func() { _ = p.target.Close() }()
	if p.verdict != installerHoldDone || p.port != port {
		t.Fatalf("got verdict %d on :%d, want hold-done on :%d", p.verdict, p.port, port)
	}
	want := "listening on :" + strconv.Itoa(port) + ", not on :" + strconv.Itoa(requested)
	if !strings.Contains(log.text(), want) {
		t.Errorf("job log does not say where the installer was found (%q):\n%s", want, log.text())
	}
}

// While the installer on the default port is still working, the job
// log carries its progress, and the wait ends only when the caller's
// context does.
func TestWaitForInstallerDoneReportsProgressFromDefaultPort(t *testing.T) {
	fastInstallerPoll(t)
	host, port := startKeyTarget(t, installerOutput("alpine", 0, 0, "Download qcow2 image"))
	usePortAsInstallerDefault(t, port)

	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	var log emitLog
	_, err := waitForInstallerDone(ctx, host, closedPort(t), testClientKey(t), "debian", log.emit)
	if err == nil {
		t.Fatal("the wait ended although the installer never finished")
	}
	if !strings.Contains(log.text(), "answering on :"+strconv.Itoa(port)) || !strings.Contains(log.text(), "Download qcow2 image") {
		t.Errorf("job log does not carry the installer's progress:\n%s", log.text())
	}
}

// An installer that failed on the default port ends the run with the
// port it is really reachable on in the recovery instructions.
func TestWaitForInstallerDoneErrorNamesTheRealPort(t *testing.T) {
	fastInstallerPoll(t)
	host, port := startKeyTarget(t, installerOutput("alpine", 0, 1, "Line 12 return 1"))
	usePortAsInstallerDefault(t, port)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var log emitLog
	_, err := waitForInstallerDone(ctx, host, closedPort(t), testClientKey(t), "debian", log.emit)
	if err == nil || !strings.Contains(err.Error(), "-p "+strconv.Itoa(port)+" ") {
		t.Fatalf("error = %v, want recovery instructions for port %d", err, port)
	}
}

// A machine that already answers as the target OS on the REQUESTED
// port ends the wait with no session; the boot probe decides the rest.
func TestWaitForInstallerDoneFinalOSOnRequestedPort(t *testing.T) {
	fastInstallerPoll(t)
	host, port := startKeyTarget(t, installerOutput("debian", 0, 0, ""))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var log emitLog
	p, err := waitForInstallerDone(ctx, host, port, testClientKey(t), "debian", log.emit)
	if err != nil || p.verdict != installerFinalOS || p.target != nil {
		t.Fatalf("got verdict %d, session %v, err %v; want final-OS with no session", p.verdict, p.target != nil, err)
	}
}

// When the rendered network config looks wrong the run stops and
// leaves the box parked. The instructions must send the operator to
// the port the installer answers on — on a fallback run that is not
// the requested one, which is known to be silent.
func TestVerifyInstalledSystemNamesTheInstallersRealPort(t *testing.T) {
	host, port := startKeyTarget(t, "NOT_FOUND\n")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	target, err := dialKeyTarget(ctx, host, port, testClientKey(t), hostKeyExpectation{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()

	netInfo := parseReinstallNetInfo("IPv4 Address: 192.0.2.5/24\nIPv4 Gateway: 192.0.2.1\n")
	var log emitLog
	err = verifyInstalledSystem(ctx, target, heldInstaller{host: "192.0.2.5", port: 22}, netInfo, log.emit)
	if err == nil {
		t.Fatal("a NOT_FOUND verdict did not stop the run")
	}
	if !strings.Contains(err.Error(), "ssh root@192.0.2.5 -p 22 ") {
		t.Errorf("recovery instructions do not name the installer's port:\n%v", err)
	}
	if strings.Contains(err.Error(), "-p "+strconv.Itoa(defaultNewSSHPort)) {
		t.Errorf("recovery instructions name the requested port, which does not answer:\n%v", err)
	}
}

// text is the whole job log, one event per line.
func (e *emitLog) text() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.Join(e.lines, "\n")
}

// The hold stage end to end on a fallback run: the installer is found
// on the default port, verified over that session, and told to reboot.
func TestRunInstallerHoldStageOverDefaultPort(t *testing.T) {
	fastInstallerPoll(t)
	host, port := startKeyTarget(t, installerOutput("alpine", 1, 0, "***** HOLD 2 *****"))
	usePortAsInstallerDefault(t, port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	netInfo := parseReinstallNetInfo("IPv4 Address: 192.0.2.5/24\nIPv4 Gateway: 192.0.2.1\n")
	var log emitLog
	verified, err := runInstallerHoldStage(ctx, heldInstaller{host: host, port: closedPort(t)}, testClientKey(t), netInfo, "debian", log.emit)
	if err != nil || !verified {
		t.Fatalf("runInstallerHoldStage = %v, %v; want the install verified\n%s", verified, err, log.text())
	}
	for _, want := range []string{
		"listening on :" + strconv.Itoa(port),
		"installer finished writing the new system",
		"triggering reboot into the freshly-installed system",
	} {
		if log.count(want) == 0 {
			t.Errorf("job log is missing %q:\n%s", want, log.text())
		}
	}
}
