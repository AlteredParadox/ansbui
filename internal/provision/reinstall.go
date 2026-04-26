package provision

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
// Versions are listed newest-first because the UI tends to default
// to the first entry.
var reinstallOSMatrix = map[string][]string{
	"debian": {"12", "11"},
	"ubuntu": {"24.04", "22.04"},
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
	// Fire-and-forget: schedule reboot and let our session close
	// cleanly. Doing `reboot` inline races with our SSH ack and
	// usually surfaces as an "EOF" error from runRoot which we'd
	// then have to special-case as not-an-error.
	if _, _, err := target.runRoot(ctx, "(sleep 1; reboot) >/dev/null 2>&1 &", ""); err != nil {
		return nil, fmt.Errorf("schedule reboot: %w", err)
	}
	emit("ok", "reboot scheduled")

	emit("meta", fmt.Sprintf("Waiting for OS install + reboot, then SSH on :%d (key auth as root). Timeout: 30 minutes.", reinstallSSHPort))
	newTarget, err := waitForKeyTarget(ctx, host, reinstallSSHPort, privKey, emit)
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

// waitForKeyTarget polls the target on (host:port) until SSH
// answers with key auth, or until ctx is cancelled / the 30-minute
// budget elapses. The first 60 seconds are an unconditional sleep
// — the box is going down, dialing during that window just
// produces noise.
//
// Subsequent retries are 15s apart; with dialKeyTarget's 15s dial
// timeout the worst-case loop iteration is 30s. A heartbeat fires
// every 60s so the operator sees progress.
func waitForKeyTarget(ctx context.Context, host string, port int, privKey []byte, emit func(typ, text string)) (*targetSession, error) {
	const (
		initialWait      = 60 * time.Second
		retryInterval    = 15 * time.Second
		heartbeatPeriod  = 60 * time.Second
		totalBudget      = 30 * time.Minute
	)
	deadline := time.Now().Add(totalBudget)
	select {
	case <-time.After(initialWait):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	startedAt := time.Now()
	lastBeat := time.Now()
	var lastErr error
	for {
		if time.Now().After(deadline) {
			if lastErr == nil {
				return nil, errors.New("timeout waiting for SSH after 30 minutes")
			}
			return nil, fmt.Errorf("timeout waiting for SSH after 30 minutes: last error: %w", lastErr)
		}
		target, err := dialKeyTarget(ctx, host, port, privKey)
		if err == nil {
			return target, nil
		}
		lastErr = err
		if time.Since(lastBeat) >= heartbeatPeriod {
			emit("meta", fmt.Sprintf("still waiting for SSH on :%d (%s elapsed) — last error: %v", port, friendly(time.Since(startedAt)), err))
			lastBeat = time.Now()
		}
		select {
		case <-time.After(retryInterval):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// startHeartbeat fires a "still running" emit every 30s until the
// returned cancel func is called. Used during reinstall.sh's prep
// phase, which can take 1-3 minutes of silence.
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
	var stopped bool
	return func() {
		if stopped {
			return
		}
		stopped = true
		close(stop)
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
