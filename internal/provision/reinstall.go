package provision

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ReinstallOpts is the optional reinstall step. When Enabled, the
// orchestrator drives bin456789/reinstall against the target
// before running the ansible-user-setup steps:
//
//   1. download reinstall.sh
//   2. run reinstall.sh <os> <version> --ssh-port 4242 --ssh-key <pub>
//   3. trigger reboot in a detached process so our SSH session can
//      close cleanly
//   4. poll-dial :4242 with key auth until the freshly-installed
//      system answers
//
// On success, provision.Run swaps the original password-auth target
// for the new key-auth target and continues the rest of the
// workflow (ansible user, sshd-port no-op-if-already-4242, inventory).
type ReinstallOpts struct {
	Enabled bool   `json:"enabled"`
	OS      string `json:"os"`
	Version string `json:"version"`
}

// reinstallOSMatrix is the curated OS/version allowlist exposed to
// operators. It's intentionally narrower than reinstall.sh's full
// catalogue — the rest of provision.go only knows how to bootstrap
// a Debian-family box (apt install sudo + python3), so allowing
// alma / fedora / alpine / etc. via reinstall would just produce a
// successful reinstall followed by an apt-install failure on the
// next step. When the bootstrap is generalised this list grows.
//
// Versions match what reinstall.sh's README advertises (Debian
// 9-13, Ubuntu LTS 18.04-26.04). Listed newest-first because the
// UI tends to default to the first entry.
var reinstallOSMatrix = map[string][]string{
	"debian": {"13", "12", "11", "10", "9"},
	"ubuntu": {"26.04", "24.04", "22.04", "20.04", "18.04"},
}

// reinstallScriptURL is the canonical raw URL for bin456789's
// reinstall.sh. Pinned to main on purpose — the project ships
// distro support and bug fixes rolling, and we want operators to
// pick up fixes without a binary rebuild. If supply-chain trust
// becomes a concern we'd checksum-verify or vendor the script.
const reinstallScriptURL = "https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh"

// reinstallSSHPort is the port reinstall.sh is told to bake into
// the new system's sshd_config. Matches the port targetSSHPort
// uses for the rest of the provisioning workflow so the rest of
// the steps see "already on 4242" and no-op the flip script.
const reinstallSSHPort = targetSSHPort

// validateReinstall checks that opts is consistent with the
// curated matrix. We allowlist rather than passing the values
// through to the shell because they get spliced into a remote
// bash command — even though shellQuote handles quoting, defending
// at the boundary keeps the surface area small.
func validateReinstall(opts ReinstallOpts) error {
	if !opts.Enabled {
		return nil
	}
	versions, ok := reinstallOSMatrix[opts.OS]
	if !ok {
		return fmt.Errorf("unsupported reinstall OS %q — allowed: %s", opts.OS, strings.Join(reinstallOSList(), ", "))
	}
	for _, v := range versions {
		if v == opts.Version {
			return nil
		}
	}
	return fmt.Errorf("unsupported %s version %q — allowed: %s", opts.OS, opts.Version, strings.Join(versions, ", "))
}

func reinstallOSList() []string {
	out := make([]string, 0, len(reinstallOSMatrix))
	for k := range reinstallOSMatrix {
		out = append(out, k)
	}
	return out
}

// runReinstall downloads + runs reinstall.sh, kicks off a detached
// reboot, then waits for SSH to come back on the new port with key
// auth. Returns the new key-auth target session — caller takes
// ownership, original password-auth target should be closed by the
// caller before this is invoked.
//
// emit receives progress messages on the same channel as the rest
// of provisioning. The "wait for SSH" phase periodically emits a
// heartbeat so the operator can tell the run is still alive — a
// silent 20-minute install otherwise looks indistinguishable from
// a hung process.
func runReinstall(ctx context.Context, target *targetSession, opts ReinstallOpts, pubKey string, privKey []byte, host string, emit func(typ, text string)) (*targetSession, error) {
	if err := validateReinstall(opts); err != nil {
		return nil, err
	}
	emit("meta", fmt.Sprintf("Running reinstall.sh %s %s on target (this prepares the new install — actual reinstall happens after reboot)...", opts.OS, opts.Version))

	heartbeat := startHeartbeat(ctx, "reinstall.sh still running", emit)
	defer heartbeat() // belt-and-suspenders against future early returns
	stdout, stderr, err := target.runRoot(ctx, reinstallPrepScript(opts, pubKey), "")
	heartbeat()
	if err != nil {
		return nil, fmt.Errorf("reinstall.sh: %s: %w", strings.TrimSpace(stderr), err)
	}
	if tail := tailLines(stdout, 6); tail != "" {
		emit("meta", "reinstall.sh tail:\n"+tail)
	}
	emit("ok", "reinstall.sh prepared the new install")

	emit("meta", "Triggering reboot (detached) — SSH session will drop in ~1s...")
	// Fire-and-forget: the inner `&` should background the reboot
	// inside the remote shell so the wrapper exits cleanly. But a
	// fast reboot or half-closed SSH channel can still surface
	// EOF / *ExitMissingError from runRoot — the side-effect has
	// already been scheduled, so treat any error as a warning and
	// proceed to the reconnect wait. Mis-classifying a real
	// failure as "rebooting" is OK because waitForReinstallTarget
	// will time out on its 30-minute budget if the box never
	// actually reboots.
	if _, _, err := target.runRoot(ctx, "(sleep 1; reboot) >/dev/null 2>&1 &", ""); err != nil {
		emit("meta", fmt.Sprintf("reboot scheduling returned %v — proceeding (the reboot itself is detached)", err))
	} else {
		emit("ok", "reboot scheduled")
	}

	emit("meta", fmt.Sprintf("Waiting for OS install + reboot, then SSH on :%d (key auth as root). Timeout: 30 minutes.", reinstallSSHPort))
	emit("meta", fmt.Sprintf("(reinstall.sh exposes SSH on :%d from its installer env so you can screen -r the install — we'll keep checking /etc/os-release until it reports the target distro.)", reinstallSSHPort))
	newTarget, err := waitForReinstallTarget(ctx, host, reinstallSSHPort, privKey, opts.OS, emit)
	if err != nil {
		return nil, err
	}
	emit("ok", fmt.Sprintf("connected to freshly-installed %s %s on :%d", opts.OS, opts.Version, reinstallSSHPort))
	return newTarget, nil
}

// reinstallPrepScript builds the bash one-liner that downloads and
// runs reinstall.sh. The pubkey content goes through shellQuote,
// which uses '"'"' escapes — safe even with the SSH option-prefix
// shapes (`command="..." ssh-ed25519 ...`) authorized_keys allows.
//
// Output is teed to /tmp/reinstall.log so the operator has a copy
// to inspect post-reboot via the new target session if anything
// looked suspicious during the prep phase.
func reinstallPrepScript(opts ReinstallOpts, pubKey string) string {
	return strings.Join([]string{
		`set -e`,
		`cd /tmp`,
		`rm -f reinstall.sh`,
		`if command -v curl >/dev/null 2>&1; then curl -fsSLO ` + shellQuote(reinstallScriptURL) +
			`; elif command -v wget >/dev/null 2>&1; then wget -q ` + shellQuote(reinstallScriptURL) +
			`; else echo "neither curl nor wget available" >&2; exit 1; fi`,
		`chmod +x reinstall.sh`,
		`bash reinstall.sh ` + shellQuote(opts.OS) + ` ` + shellQuote(opts.Version) +
			` --ssh-port ` + fmt.Sprintf("%d", reinstallSSHPort) +
			` --ssh-key ` + shellQuote(pubKey) +
			` 2>&1 | tee /tmp/reinstall.log`,
	}, "; ")
}

// waitForReinstallTarget polls the target on (host:port) until SSH
// answers with key auth AND /etc/os-release reports the requested
// target OS, or until ctx is cancelled / the 30-minute budget
// elapses. The os-release check is what distinguishes the
// reinstaller's live environment (where reinstall.sh exposes SSH
// on :4242 with the same key for `screen -r` monitoring) from the
// freshly-installed target OS that comes up after the second
// reboot. Without it we'd attach to the live env mid-install and
// run `apt install` against an alpine initramfs.
//
// The first 60 seconds are an unconditional sleep — the original
// box is going down, dialing during that window just produces
// noise. Subsequent retries are 15s apart; with dialKeyTarget's
// 15s dial timeout the worst-case loop iteration is 30s. A
// heartbeat fires every 60s so the operator sees progress.
func waitForReinstallTarget(ctx context.Context, host string, port int, privKey []byte, expectedOS string, emit func(typ, text string)) (*targetSession, error) {
	const (
		initialWait     = 60 * time.Second
		retryInterval   = 15 * time.Second
		heartbeatPeriod = 60 * time.Second
		totalBudget     = 30 * time.Minute
	)
	deadline := time.Now().Add(totalBudget)
	select {
	case <-time.After(initialWait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	startedAt := time.Now()
	lastBeat := time.Now()
	var lastStatus string
	for {
		if time.Now().After(deadline) {
			if lastStatus == "" {
				return nil, errors.New("timeout waiting for SSH after 30 minutes")
			}
			return nil, fmt.Errorf("timeout waiting for target OS after 30 minutes: last status: %s", lastStatus)
		}
		target, status := tryReinstallReady(ctx, host, port, privKey, expectedOS)
		if target != nil {
			return target, nil
		}
		lastStatus = status
		if time.Since(lastBeat) >= heartbeatPeriod {
			emit("meta", fmt.Sprintf("waiting for %s on :%d (%s elapsed) — %s", expectedOS, port, friendly(time.Since(startedAt)), status))
			lastBeat = time.Now()
		}
		select {
		case <-time.After(retryInterval):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// tryReinstallReady performs one dial + os-release probe. Returns
// (target, "") when the target OS matches expectedOS — the caller
// owns the session. Returns (nil, status) when we should keep
// waiting, where status describes the current state for the
// heartbeat ("connection refused", "still in installer (alpine)",
// etc.). The session is closed on the not-ready paths so we don't
// leak SSH connections during the wait loop.
func tryReinstallReady(ctx context.Context, host string, port int, privKey []byte, expectedOS string) (*targetSession, string) {
	target, err := dialKeyTarget(ctx, host, port, privKey)
	if err != nil {
		return nil, "dial: " + err.Error()
	}
	osRelease, _, err := target.runRoot(ctx, "cat /etc/os-release", "")
	if err != nil {
		_ = target.Close()
		return nil, "cat /etc/os-release: " + err.Error()
	}
	if osMatches(osRelease, expectedOS) {
		return target, ""
	}
	_ = target.Close()
	return nil, fmt.Sprintf("still in installer env (detected: %s)", detectDistro(osRelease))
}

// osMatches checks whether /etc/os-release identifies expectedOS.
// We accept either a direct ID match or expectedOS appearing in
// ID_LIKE — reinstall.sh's image of "debian" might land on a
// derivative whose ID is "raspbian" / "devuan" / similar with
// ID_LIKE=debian. Without ID_LIKE acceptance the wait loop would
// burn the full 30-minute budget on a successful install.
func osMatches(osRelease, expected string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	if expected == "" {
		return false
	}
	var id, idLike string
	for _, line := range strings.Split(osRelease, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID="), `"`))
		case strings.HasPrefix(line, "ID_LIKE="):
			idLike = strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`))
		}
	}
	if id == expected {
		return true
	}
	for _, like := range strings.Fields(idLike) {
		if like == expected {
			return true
		}
	}
	return false
}

// startHeartbeat fires a "still running" emit every 30s until the
// returned cancel func is called. Used during reinstall.sh's prep
// phase, which can take 1-3 minutes of silence.
//
// The returned function is safe to call concurrently and more
// than once — sync.Once ensures `close(stop)` fires exactly once
// even when callers pair the explicit call with a `defer` for
// safety.
func startHeartbeat(ctx context.Context, msg string, emit func(typ, text string)) func() {
	stop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		started := time.Now()
		for {
			select {
			case <-ticker.C:
				emit("meta", fmt.Sprintf("%s (%s elapsed)", msg, friendly(time.Since(started))))
			case <-stop:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() { close(stop) })
	}
}

// tailLines returns the last n lines of s. Cheap helper for the
// "show me the end of reinstall.sh's output" emit so we don't
// flood the operator's terminal with the full prep transcript.
func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[len(lines)-n:], "\n")
}

// friendly formats d as e.g. "2m 15s" — matches the cadence of
// provisioning emits, which are minute-scale during the reinstall
// wait phase.
func friendly(d time.Duration) string {
	d = d.Round(time.Second)
	mins := int(d / time.Minute)
	secs := int((d % time.Minute) / time.Second)
	if mins == 0 {
		return fmt.Sprintf("%ds", secs)
	}
	return fmt.Sprintf("%dm %ds", mins, secs)
}
