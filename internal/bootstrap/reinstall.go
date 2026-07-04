package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ReinstallOpts is the optional reinstall step. When Enabled, the
// orchestrator drives bin456789/reinstall against the target
// before running the ansible-user-setup steps:
//
//  1. download reinstall.sh (sha256-verified against the pinned
//     commit) and repoint its helper downloads at the same commit
//  2. run reinstall.sh <os> <version> --ssh-port 4242 --ssh-key <pub>
//  3. capture the old system's /etc/machine-id, trigger a reboot in
//     a detached session, and confirm the old system actually drops
//     off its SSH port
//  4. poll-dial :4242 with key auth until the freshly-installed
//     system answers with the right os-release, a changed
//     machine-id, and a settled systemd
//
// On success, bootstrap.Run swaps the original password-auth target
// for the new key-auth target and continues the rest of the
// workflow (ansible user, sshd-port no-op-if-already-4242, inventory).
type ReinstallOpts struct {
	Enabled bool   `json:"enabled"`
	OS      string `json:"os"`
	Version string `json:"version"`
}

// reinstallOSMatrix is the curated OS/version allowlist exposed to
// operators. It's intentionally narrower than reinstall.sh's full
// catalogue — the rest of bootstrap.go only knows how to bootstrap
// a Debian-family box (apt install sudo + python3), so allowing
// alma / fedora / alpine / etc. via reinstall would just produce a
// successful reinstall followed by an apt-install failure on the
// next step. When the bootstrap is generalised this list grows.
//
// Versions are limited to releases whose cloud images are still
// published upstream (verified 2026-07: debian 11-13 nocloud qcow2
// at cloud.debian.org, ubuntu 20.04-26.04 server cloudimg) — the
// prep script passes --ci, so a matrix entry without a cloud image
// would fail every run. Debian 9/10 and Ubuntu 18.04 were dropped:
// no cloud image (debian) or fully EOL (18.04), which made them
// dropdown entries that could never succeed. Listed newest-first
// because the UI tends to default to the first entry.
//
// web/views/Bootstrap.jsx's REINSTALL_MATRIX must mirror this map.
var reinstallOSMatrix = map[string][]string{
	"debian": {"13", "12", "11"},
	"ubuntu": {"26.04", "24.04", "22.04", "20.04"},
}

// reinstallScriptCommit pins bin456789/reinstall to a specific
// commit. The script runs as root on the target — pulling from
// `main` would mean any upstream compromise (or surprise change)
// becomes root code execution on every freshly-bootstrapped host.
// Updating both this SHA and reinstallScriptSHA256 below is a
// deliberate, reviewable bump.
//
// The script ships with `confhome` hardcoded to the upstream
// `main` branch — at install time it downloads its helper scripts
// (trans.sh, debian.cfg, fix-eth-name.sh, initrd-network.sh, ...)
// from there, and its own commit-pinning path is dead code
// (`if false && ...`). Left alone, that makes every run depend on
// whatever is on `main` that day: silent behaviour drift in the
// helpers that configure the new system's disk and networking, and
// hard failures whenever upstream bumps SCRIPT_VERSION past the
// pinned orchestrator. reinstallPrepScript therefore rewrites the
// confhome assignments to this commit after the sha256 check, so
// the orchestrator and every helper come from the same pinned
// commit and a run is reproducible end-to-end.
//
// To roll: pick the new commit upstream, run
//
//	curl -fsSL https://raw.githubusercontent.com/bin456789/reinstall/<sha>/reinstall.sh | sha256sum
//
// and update both constants in the same commit.
const reinstallScriptCommit = "52c5a29fba0cef139b1193eee1efe09879205f52"

// reinstallScriptSHA256 is the expected sha256 of reinstall.sh at
// reinstallScriptCommit. Verified on the target after download
// before we hand it to bash. A mismatch aborts the run with a
// clear error so the operator notices a tampered mirror or a
// stale pin rather than silently running unverified code.
const reinstallScriptSHA256 = "c7931dfa847adc41c58b60eceb3237ef7b2eb676e38e00efeb9b7e29274b70bc"

// reinstallConfhomeURL is the commit-pinned base URL for upstream
// files. reinstallScriptURL fetches reinstall.sh from it, and
// reinstallPrepScript rewrites the script's own `confhome` /
// `confhome_cn` assignments to it so helper downloads at install
// time come from the same commit (see reinstallScriptCommit doc).
// raw.githubusercontent.com serves the exact file at the requested
// commit; combined with the local sha256 check below, an MITM or
// upstream compromise would have to produce a sha256 collision to
// slip past.
var (
	reinstallConfhomeURL = fmt.Sprintf("https://raw.githubusercontent.com/bin456789/reinstall/%s", reinstallScriptCommit)
	reinstallScriptURL   = reinstallConfhomeURL + "/reinstall.sh"
)

// reinstallSSHPort is the port reinstall.sh is told to bake into
// the new system's sshd_config. Matches the port targetSSHPort
// uses for the rest of the bootstrap workflow so the rest of
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
// reboot, confirms the old system went down, then waits for SSH to
// come back on the new port with key auth. Returns the new key-auth
// target session — caller takes ownership, original password-auth
// target should be closed by the caller before this is invoked.
//
// req supplies the reinstall opts plus the target's address and
// ORIGINAL SSH port — the latter is what the down-detection probes,
// since the old system is the one listening there.
//
// emit receives progress messages on the same channel as the rest
// of bootstrap. The "wait for SSH" phase periodically emits a
// heartbeat so the operator can tell the run is still alive — a
// silent 20-minute install otherwise looks indistinguishable from
// a hung process.
func runReinstall(ctx context.Context, target *targetSession, req Request, pubKey string, privKey []byte, emit func(typ, text string)) (*targetSession, error) {
	opts := req.Reinstall
	if err := validateReinstall(opts); err != nil {
		return nil, err
	}

	emit("meta", "Ensuring curl is available on target (needed by reinstall.sh)...")
	if _, stderr, err := target.runRoot(ctx, ensureCurlScript(), ""); err != nil {
		return nil, fmt.Errorf("prepare reinstall curl dependency: %s: %w", strings.TrimSpace(stderr), err)
	}
	emit("ok", "curl available")

	emit("meta", fmt.Sprintf("Running reinstall.sh %s %s on target (this prepares the new install — actual reinstall happens after reboot)...", opts.OS, opts.Version))

	heartbeat := startHeartbeat(ctx, "reinstall.sh still running", emit)
	defer heartbeat() // belt-and-suspenders against future early returns
	// The prep phase gets its own deadline: it normally takes 1-3
	// minutes, and the only ways past 15 are a stalled mirror or a
	// dead-but-undetected connection. Without the bound (jobs carry
	// no global timeout) a stall here idles the run indefinitely.
	prepCtx, cancelPrep := context.WithTimeout(ctx, reinstallPrepBudget)
	stdout, stderr, err := target.runRoot(prepCtx, reinstallPrepScript(opts, pubKey), "")
	cancelPrep()
	heartbeat()
	if err != nil {
		if errors.Is(prepCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, fmt.Errorf("reinstall.sh prep did not finish within %s — a download from the pinned repo or the OS image mirror likely stalled; re-run bootstrap to retry", friendly(reinstallPrepBudget))
		}
		return nil, fmt.Errorf("reinstall.sh: %s: %w", strings.TrimSpace(stderr), err)
	}
	if tail := tailLines(stdout, 6); tail != "" {
		emit("meta", "reinstall.sh tail:\n"+tail)
	}
	emit("ok", "reinstall.sh prepared the new install")

	// Capture the old system's machine-id before rebooting. The
	// wait loop uses "machine-id changed" as proof the box really
	// was reinstalled — without it, a box that boots back into its
	// OLD system (failed grub entry) while already having key auth
	// on :4242 from a previous bootstrap would pass the os-release
	// check and be reported as freshly installed. Read failures
	// degrade to "" (the proof is skipped), never abort the run.
	oldMachineID := ""
	if out, _, err := target.runRoot(ctx, "cat /etc/machine-id 2>/dev/null || true", ""); err == nil {
		oldMachineID = strings.TrimSpace(out)
	}

	emit("meta", "Triggering reboot (detached) — SSH session will drop in ~2s...")
	// Fire-and-forget, hardened against session teardown: setsid
	// detaches the subshell from the SSH session so neither sshd's
	// process-group cleanup nor systemd-logind (KillUserProcesses)
	// can reap it before the sleep elapses — with a bare `&` the
	// reboot was occasionally lost that way. `reboot -f` is the
	// fallback for non-systemd targets. A fast reboot or half-closed
	// SSH channel can still surface an error from runRoot — the
	// side-effect has already been scheduled, so treat any error as
	// a warning; waitForTargetDown below catches the case where the
	// reboot genuinely never fires.
	rebootCmd := `nohup setsid bash -c 'sleep 2; systemctl reboot || reboot -f' >/dev/null 2>&1 &`
	if _, _, err := target.runRoot(ctx, rebootCmd, ""); err != nil {
		emit("meta", fmt.Sprintf("reboot scheduling returned %v — proceeding (the reboot itself is detached)", err))
	} else {
		emit("ok", "reboot scheduled")
	}

	emit("meta", fmt.Sprintf("Confirming the old system drops off :%d (up to %s)...", req.Port, friendly(targetDownBudget)))
	if err := waitForTargetDown(ctx, req.IP, req.Port); err != nil {
		return nil, err
	}
	emit("ok", "old system went down — reboot confirmed")

	emit("meta", fmt.Sprintf("Waiting for OS install + reboot, then SSH on :%d (key auth as root). Timeout: %s.", reinstallSSHPort, friendly(reinstallWaitBudget)))
	emit("meta", fmt.Sprintf("(reinstall.sh exposes SSH on :%d from its installer env so you can screen -r the install — we'll keep probing until os-release, machine-id, and systemd state all say the new system is up.)", reinstallSSHPort))
	probe := reinstallReadyProbe{
		expectedOS:      opts.OS,
		expectedVersion: opts.Version,
		oldMachineID:    oldMachineID,
	}
	newTarget, err := waitForReinstallTarget(ctx, req.IP, reinstallSSHPort, privKey, probe, emit)
	if err != nil {
		return nil, err
	}
	emit("ok", fmt.Sprintf("connected to freshly-installed %s %s on :%d", opts.OS, opts.Version, reinstallSSHPort))
	return newTarget, nil
}

// Phase budgets for the reinstall workflow.
//
//   - reinstallPrepBudget bounds reinstall.sh's prep run (download
//     script + OS image, write boot entry). Normally 1-3 minutes;
//     15 tolerates a slow image mirror without letting a stall idle
//     the run forever.
//   - targetDownBudget bounds the wait for the old system to stop
//     answering after the detached reboot fires. A healthy reboot
//     drops the port within seconds; five minutes is generous slack
//     for a loaded box flushing to disk.
//   - reinstallWaitBudget bounds the install + reboot + come-back
//     wait. Cloud-image installs typically finish in 5-15 minutes,
//     but a slow provider disk or throttled mirror can stretch
//     that; 45 keeps a legitimately slow install from being
//     misreported as a network failure.
const (
	reinstallPrepBudget = 15 * time.Minute
	targetDownBudget    = 5 * time.Minute
	reinstallWaitBudget = 45 * time.Minute
)

// waitForTargetDown polls host:port with plain TCP dials until the
// port stops accepting connections, confirming the detached reboot
// actually fired. Failing fast here converts the nastiest reinstall
// failure mode — reboot silently lost, run burning the full
// 30-minute install budget before a misleading timeout — into an
// immediate, self-diagnosing error.
//
// Two consecutive failed dials are required before declaring the
// box down so a single transient network blip can't end the wait
// early. (A false "down" is harmless anyway — the ready probe's
// machine-id check keeps the old system from passing as new.)
func waitForTargetDown(ctx context.Context, host string, port int) error {
	const (
		probeInterval = 5 * time.Second
		dialTimeout   = 5 * time.Second
		needFailures  = 2
	)
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(targetDownBudget)
	failures := 0
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("old system on %s is still accepting connections %s after the reboot was triggered — the detached reboot appears not to have fired; reboot the box manually (the install starts on next boot) or re-run bootstrap", addr, friendly(targetDownBudget))
		}
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", addr)
		switch {
		case err == nil:
			_ = conn.Close()
			failures = 0
		case ctx.Err() != nil:
			return ctx.Err()
		default:
			failures++
			if failures >= needFailures {
				return nil
			}
		}
		select {
		case <-time.After(probeInterval):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// ensureCurlScript installs curl via apt-get if it isn't already on
// the target. reinstallPrepScript can use wget to fetch the pinned
// script, but reinstall.sh itself calls curl internally, so wget alone
// is not enough. Fail before running reinstall.sh if curl cannot be
// installed.
func ensureCurlScript() string {
	return strings.Join([]string{
		`set -e`,
		`if command -v curl >/dev/null 2>&1; then exit 0; fi`,
		`if ! command -v apt-get >/dev/null 2>&1; then echo "curl not found and apt-get not found to install it" >&2; exit 1; fi`,
		// A failed update is tolerated: this is the OLD system,
		// often an EOL release whose mirrors have moved — its stale
		// package lists usually still resolve curl, and the box is
		// about to be wiped anyway. The install line is the real
		// gate.
		`DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 update -qq || echo "apt-get update failed — trying curl install with existing package lists" >&2`,
		`DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 install -y -qq curl`,
		`command -v curl >/dev/null 2>&1`,
	}, "; ")
}

// reinstallPrepScript builds the bash one-liner that downloads,
// verifies, pins, and runs reinstall.sh. The pubkey content goes
// through shellQuote, which uses '"'"' escapes — safe even with the
// SSH option-prefix shapes (`command="..." ssh-ed25519 ...`)
// authorized_keys allows.
//
// Verification: after download, sha256sum is compared to
// reinstallScriptSHA256 before bash ever sees the file. A
// mismatch aborts the run; the operator gets a "checksum
// mismatch" message so a tampered mirror or stale pin is
// distinguishable from a genuine reinstall failure.
//
// Pinning: after the checksum passes, the script's hardcoded
// `confhome=.../main` (and its China-mirror twin) are rewritten to
// reinstallConfhomeURL so every helper it downloads at install time
// (trans.sh, debian.cfg, fix-eth-name.sh, ...) comes from the same
// pinned commit. This is a deliberate self-authored edit of
// verified content — without it, runs silently depend on upstream's
// `main` branch of the day (see reinstallScriptCommit doc).
//
// Output is teed to /tmp/reinstall.log so the prep transcript is
// inspectable if the run fails before the reboot. It does NOT
// survive the reinstall — the install erases the disk — so anything
// worth keeping must come out through the emit stream.
func reinstallPrepScript(opts ReinstallOpts, pubKey string) string {
	// --ci forces cloud-image mode for both matrix distros. Upstream
	// already forces it for ubuntu, but debian otherwise defaults to
	// the full debian-installer netboot: slower (can outlive even
	// the 45m wait budget), unobservable while it runs (d-i exposes
	// no SSH and writes no /reinstall.log for the wait loop to
	// tail), and dependent on netboot mirror paths that disappear
	// once a release goes EOL. Cloud images for every matrix entry
	// were verified present upstream; passing the flag explicitly
	// also keeps an upstream default change from silently flipping
	// the install mode between runs.
	runCmd := `bash reinstall.sh ` + shellQuote(opts.OS) + ` ` + shellQuote(opts.Version) +
		` --ci` +
		` --ssh-port ` + fmt.Sprintf("%d", reinstallSSHPort) +
		` --ssh-key ` + shellQuote(pubKey) +
		` 2>&1 | tee /tmp/reinstall.log`
	return strings.Join([]string{
		`set -e`,
		`cd /tmp`,
		`rm -f reinstall.sh`,
		`if command -v curl >/dev/null 2>&1; then curl -fsSLO ` + shellQuote(reinstallScriptURL) +
			`; elif command -v wget >/dev/null 2>&1; then wget -q ` + shellQuote(reinstallScriptURL) +
			`; else echo "neither curl nor wget available" >&2; exit 1; fi`,
		`echo ` + shellQuote(reinstallScriptSHA256+"  reinstall.sh") + ` | sha256sum -c - ` +
			`|| { echo "reinstall.sh sha256 mismatch — refusing to run (expected ` + reinstallScriptSHA256 + `)" >&2; exit 1; }`,
		`sed -i -e 's|^confhome=.*|confhome=` + reinstallConfhomeURL + `|'` +
			` -e 's|^confhome_cn=.*|confhome_cn=` + reinstallConfhomeURL + `|' reinstall.sh`,
		`chmod +x reinstall.sh`,
		`bash -o pipefail -c ` + shellQuote(runCmd),
	}, "; ")
}

// reinstallReadyProbe carries the evidence thresholds a dialed
// session must clear before the wait loop hands it back as "the
// freshly-installed system":
//
//   - expectedOS: /etc/os-release ID (or ID_LIKE) must match —
//     distinguishes the target OS from the installer's live env.
//   - expectedVersion: VERSION_ID must match when present — a box
//     that boots back into an old same-family install answers
//     honestly here.
//   - oldMachineID: when non-empty, /etc/machine-id must DIFFER —
//     positive proof a reinstall happened, catching the
//     boots-back-into-the-old-system case even when the versions
//     coincide.
type reinstallReadyProbe struct {
	expectedOS      string
	expectedVersion string
	oldMachineID    string
}

// reinstallProbeMarker separates the sections of
// reinstallProbeScript's output. Unusual enough that it can't
// appear inside a legitimate /etc/os-release.
const reinstallProbeMarker = "__ANSBUI_PROBE__"

// reinstallProbeScript gathers everything evalReinstallProbe needs
// in ONE round trip: os-release, systemd's settle state, the
// machine-id, and the tail of the installer's log. Each fragment
// tolerates its command or file missing (the alpine installer env
// has no systemctl; the final OS has no /reinstall.log) —
// classification happens on the Go side where it can be tested.
// The trailing `true` keeps a missing fragment from failing the
// whole probe.
//
// The log tail turns the wait loop's "still in installer env"
// heartbeat into live install progress ("Downloading cloud image
// 43%" vs "error: no space left") — the difference between a
// diagnosable timeout and a mystery. The password/token filter
// mirrors what upstream's own log viewer strips before display;
// belt-and-suspenders on top of the emit-side redaction.
var reinstallProbeScript = strings.Join([]string{
	`cat /etc/os-release 2>/dev/null`,
	`echo ` + reinstallProbeMarker,
	`systemctl is-system-running 2>/dev/null | head -n1`,
	`echo ` + reinstallProbeMarker,
	`cat /etc/machine-id 2>/dev/null`,
	`echo ` + reinstallProbeMarker,
	`tail -n 20 /reinstall.log 2>/dev/null | grep -Fiav -e password -e token | tail -n 1`,
	`true`,
}, "; ")

// waitForReinstallTarget polls the target on (host:port) until SSH
// answers with key auth AND evalReinstallProbe's checks all pass,
// or until ctx is cancelled / the 30-minute budget elapses. The
// probe is what distinguishes the reinstaller's live environment
// (where reinstall.sh exposes SSH on :4242 with the same key for
// `screen -r` monitoring) — and a box that wrongly booted back
// into its old system — from the freshly-installed target OS.
// Without it we'd attach to the live env mid-install and run
// `apt install` against an alpine initramfs.
//
// The first 15 seconds are an unconditional sleep — the caller has
// already confirmed the old system went down, so this only skips
// the shutdown/BIOS window where dialing is pure noise. Subsequent
// retries are 15s apart; with dialKeyTarget's 15s dial timeout the
// worst-case loop iteration is 30s. A heartbeat fires every 60s so
// the operator sees progress.
func waitForReinstallTarget(ctx context.Context, host string, port int, privKey []byte, probe reinstallReadyProbe, emit func(typ, text string)) (*targetSession, error) {
	const (
		initialWait     = 15 * time.Second
		retryInterval   = 15 * time.Second
		heartbeatPeriod = 60 * time.Second
	)
	deadline := time.Now().Add(reinstallWaitBudget)
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
			// The reinstall very likely succeeded — reinstall.sh's
			// prep phase passed and the box rebooted — but the
			// freshly-installed system never came back on the
			// expected port. By far the most common cause is
			// networking failing to come up in the new install
			// (wrong NIC name after debian-installer's predictable
			// renaming, or the auto-detected static config not
			// matching the new interface), which is invisible over
			// SSH. Point the operator at the provider console, the
			// only place that failure is observable.
			hint := fmt.Sprintf("check the provider's serial/VNC console: the reinstall likely completed but %s isn't reachable on :%d, usually because networking (NIC name / static config) didn't come up in the new install", probe.expectedOS, port)
			if lastStatus == "" {
				return nil, fmt.Errorf("timeout after %s waiting for SSH on :%d — %s", friendly(reinstallWaitBudget), port, hint)
			}
			return nil, fmt.Errorf("timeout after %s waiting for %s to come up (last status: %s) — %s", friendly(reinstallWaitBudget), probe.expectedOS, lastStatus, hint)
		}
		target, status := tryReinstallReady(ctx, host, port, privKey, probe)
		if target != nil {
			return target, nil
		}
		lastStatus = status
		if time.Since(lastBeat) >= heartbeatPeriod {
			emit("meta", fmt.Sprintf("waiting for %s on :%d (%s elapsed) — %s", probe.expectedOS, port, friendly(time.Since(startedAt)), status))
			lastBeat = time.Now()
		}
		select {
		case <-time.After(retryInterval):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// tryReinstallReady performs one dial + readiness probe. Returns
// (target, "") when every probe check passes — the caller owns the
// session. Returns (nil, status) when we should keep waiting, where
// status describes the current state for the heartbeat ("dial:
// connection refused", "still in installer (alpine)", etc.). The
// session is closed on the not-ready paths so we don't leak SSH
// connections during the wait loop.
func tryReinstallReady(ctx context.Context, host string, port int, privKey []byte, probe reinstallReadyProbe) (*targetSession, string) {
	target, err := dialKeyTarget(ctx, host, port, privKey)
	if err != nil {
		return nil, "dial: " + err.Error()
	}
	out, _, err := target.runRoot(ctx, reinstallProbeScript, "")
	if err != nil {
		_ = target.Close()
		return nil, "readiness probe: " + err.Error()
	}
	ready, status := evalReinstallProbe(out, probe)
	if ready {
		return target, ""
	}
	_ = target.Close()
	return nil, status
}

// evalReinstallProbe classifies one reinstallProbeScript output.
// Returns (true, "") when the session belongs to the settled,
// freshly-installed target OS; otherwise (false, status) with a
// heartbeat-friendly description of why we're still waiting. Pure
// function so the classification rules are unit-testable.
//
// Check order matters for status quality: OS identity first (the
// common "still in installer" case), then version, then the
// machine-id reinstall proof, then systemd settle state. The
// settle gate is what protects the next step's apt-get from
// first-boot lock contention with cloud-init/unattended-upgrades.
// Unknown or missing states fail open — debian/ubuntu always run
// systemd, so only the documented early/late states block.
func evalReinstallProbe(out string, probe reinstallReadyProbe) (bool, string) {
	parts := strings.Split(out, reinstallProbeMarker)
	if len(parts) != 4 {
		return false, "unexpected readiness-probe output shape"
	}
	osRelease := parts[0]
	sysState := strings.TrimSpace(parts[1])
	machineID := strings.TrimSpace(parts[2])
	logLine := sanitizeLogLine(parts[3])

	if !osMatches(osRelease, probe.expectedOS) {
		status := fmt.Sprintf("still in installer env (detected: %s)", detectDistro(osRelease))
		if logLine != "" {
			status += " — installer log: " + logLine
		}
		return false, status
	}
	if got := osReleaseField(osRelease, "VERSION_ID"); got != "" && got != strings.TrimSpace(probe.expectedVersion) {
		return false, fmt.Sprintf("%s answered but reports version %s (want %s) — wrong system, still waiting", probe.expectedOS, got, probe.expectedVersion)
	}
	if probe.oldMachineID != "" && machineID != "" && machineID == probe.oldMachineID {
		return false, "reachable, but /etc/machine-id is unchanged — this is still the pre-reinstall system (did it boot back into the old install?)"
	}
	switch sysState {
	case "initializing", "starting":
		return false, fmt.Sprintf("%s is up, waiting for systemd to settle (state: %s)", probe.expectedOS, sysState)
	case "stopping", "maintenance":
		return false, fmt.Sprintf("system reports systemd state %q — still waiting", sysState)
	}
	return true, ""
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
	if osReleaseField(osRelease, "ID") == expected {
		return true
	}
	for _, like := range strings.Fields(osReleaseField(osRelease, "ID_LIKE")) {
		if like == expected {
			return true
		}
	}
	return false
}

// osReleaseField extracts one KEY=value field from os-release
// content, lowercased with surrounding quotes stripped. Returns ""
// when the key is absent — callers treat missing fields as
// fail-open (e.g. debian testing/sid ships no VERSION_ID).
func osReleaseField(osRelease, key string) string {
	prefix := key + "="
	for _, line := range strings.Split(osRelease, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.ToLower(strings.Trim(strings.TrimPrefix(line, prefix), `"`))
		}
	}
	return ""
}

// sanitizeLogLine makes one tail'd installer-log line safe for the
// heartbeat emit: ANSI escape sequences are dropped (trans.sh
// colours its output), remaining control characters are removed
// (carriage-return progress spam), and the result is capped at 160
// runes so a pathological line can't flood the event stream.
func sanitizeLogLine(s string) string {
	out := strings.TrimSpace(stripANSI(s))
	const maxRunes = 160
	if runes := []rune(out); len(runes) > maxRunes {
		out = string(runes[:maxRunes]) + "…"
	}
	return out
}

// States for stripANSI's escape-sequence scanner.
const (
	ansiText = iota
	ansiEsc  // just consumed ESC
	ansiCSI  // inside an ESC[ ... sequence
)

// stripANSI drops ANSI escape sequences and non-printing control
// characters, keeping tabs and everything from space upward.
func stripANSI(s string) string {
	var b strings.Builder
	state := ansiText
	for _, r := range s {
		var keep bool
		state, keep = ansiStep(state, r)
		if keep {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// ansiStep advances the scanner by one rune, returning the next
// state and whether the rune is printable text to keep.
func ansiStep(state int, r rune) (int, bool) {
	switch state {
	case ansiEsc:
		if r == '[' {
			return ansiCSI, false // CSI: consume until final byte
		}
		return ansiText, false // two-char escape: drop and move on
	case ansiCSI:
		// CSI sequences end on a final byte in @-~ (0x40-0x7e);
		// parameter/intermediate bytes (0x20-0x3f) continue them.
		if r >= '@' && r <= '~' {
			return ansiText, false
		}
		return ansiCSI, false
	default:
		if r == 0x1b {
			return ansiEsc, false
		}
		return ansiText, r >= 32 || r == '\t'
	}
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
// bootstrap emits, which are minute-scale during the reinstall
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
