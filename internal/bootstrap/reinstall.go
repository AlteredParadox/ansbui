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
//  2. run reinstall.sh <os> <version> --ssh-port 4242 --ssh-key
//     <pub> --hold 2 (hold = don't auto-reboot out of the installer)
//  3. cross-check the network config reinstall.sh detected against
//     the bootstrap target address — abort BEFORE the reboot if the
//     new system would come up on the wrong address
//  4. capture the old system's /etc/machine-id, trigger a reboot in
//     a detached session, and confirm the old system actually drops
//     off its SSH port
//  5. wait for the installer env to finish writing the new OS
//     (--hold 2 parks it instead of rebooting), then verify the
//     rendered network config under /os mentions the detected
//     address, persist the install log into the new system, and
//     trigger the final reboot ourselves
//  6. poll-dial :4242 with key auth until the freshly-installed
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
	// AcknowledgeUnverifiableHostKey lets a run proceed under strict
	// host-key mode (ANSBUI_BOOTSTRAP_REQUIRE_HOSTKEY) even though a
	// reinstall's replacement host key cannot be authenticated in
	// band. It is a deliberate per-run exception, not a stored
	// setting: strict mode keeps meaning "no *silent* trust on first
	// use", and the operator's acknowledgement is recorded in the job
	// log. Ignored entirely when strict mode is off, where TOFU is
	// already the documented default.
	AcknowledgeUnverifiableHostKey bool `json:"acknowledgeUnverifiableHostKey,omitempty"`
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

// checkReinstallHostKeyPolicy refuses a reinstall when strict
// host-key mode is on.
//
// A reinstall wipes the box and the new system generates fresh SSH
// host keys, so no fingerprint the operator could pin beforehand can
// cover the reconnect, and nothing in band can authenticate the
// replacement: the installer-stage and first-boot sessions are
// themselves reached over the very connection we would be trying to
// verify, so an on-path attacker controls that evidence too. The
// only trustworthy source is out of band (the provider's console).
//
// requireHostKeyEnv means "never trust an unauthenticated host key",
// and the reinstall path cannot honour that, so it is refused rather
// than quietly exempted — which is what it was doing before, since
// hostKeyRequired() was consulted only on the first-contact dial.
// The check runs from Validate so the refusal lands as a 400 before
// a job slot is taken and, critically, long before the target is
// wiped.
//
// AcknowledgeUnverifiableHostKey is the escape hatch, and it is
// per-run on purpose. Strict mode's real guarantee is that no
// unauthenticated key is trusted *silently*; an explicit,
// per-invocation acknowledgement preserves that, whereas a second
// env var would switch the exemption on permanently and record
// nothing about who decided or when. runReinstall logs the
// acknowledgement into the job so it survives in run history.
func checkReinstallHostKeyPolicy(opts ReinstallOpts) error {
	if !opts.Enabled || !hostKeyRequired() {
		return nil
	}
	if opts.AcknowledgeUnverifiableHostKey {
		return nil
	}
	return fmt.Errorf("%s is set, but a reinstall regenerates the target's SSH host keys — the replacement key cannot be authenticated in band. Tick the reinstall host-key acknowledgement in the form to accept that for this run (it is recorded in the job log), bootstrap without the reinstall option, or verify the fingerprint ansbui reports against the provider console afterwards", requireHostKeyEnv)
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
func runReinstall(ctx context.Context, target *targetSession, req Request, pubKey string, privKey []byte, hostKeys *HostKeyStore, emit func(typ, text string)) (*targetSession, error) {
	opts := req.Reinstall
	if err := validateReinstall(opts); err != nil {
		return nil, err
	}
	// Re-checked here as well as in Validate: Run is exported, and
	// this is the last point before the target is destroyed.
	if err := checkReinstallHostKeyPolicy(opts); err != nil {
		return nil, err
	}
	// Record the exception where it outlives the request. Strict mode
	// is on, the operator waived host-key verification for this run,
	// and run history should say so.
	if opts.AcknowledgeUnverifiableHostKey && hostKeyRequired() {
		emit("meta", "⚠ operator acknowledged that this reinstall's replacement host key cannot be verified — proceeding despite "+requireHostKeyEnv)
	}

	stdout, err := runReinstallPrep(ctx, target, opts, pubKey, emit)
	if err != nil {
		return nil, err
	}

	// Pre-reboot network cross-check. reinstall.sh bakes the network
	// config it auto-detected on the OLD system into the installer
	// (default-route NIC, FIRST global address on it as primary —
	// and only the primary makes it into the new install for IPv4).
	// The pre-reboot environment is trusted — it's provider-set and
	// we're SSH'd in over it — so the address this bootstrap dialed
	// is ground truth. If detection picked something else (multi-IP
	// box, unusual routing), the new system would come up on the
	// wrong address: a guaranteed 45-minute timeout and possibly a
	// console-rescue job. Abort now instead, while the old system
	// is still alive and untouched.
	netInfo := resolvePrepNetInfo(ctx, target, stdout, emit)
	if err := verifyReinstallNetconf(ctx, netInfo, req.IP, emit); err != nil {
		return nil, err
	}

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
	scheduleDetachedReboot(ctx, target, emit)

	emit("meta", fmt.Sprintf("Confirming the old system drops off :%d (up to %s)...", req.Port, friendly(targetDownBudget)))
	if err := waitForTargetDown(ctx, req.IP, req.Port); err != nil {
		return nil, err
	}
	emit("ok", "old system went down — reboot confirmed")

	emit("meta", fmt.Sprintf("Waiting for the installer on :%d to finish writing %s %s to disk (--hold 2 parks it there for verification; timeout %s)...", reinstallSSHPort, opts.OS, opts.Version, friendly(reinstallWaitBudget)))
	verifiedInstall, err := runInstallerHoldStage(ctx, req.IP, privKey, netInfo, opts.OS, emit)
	if err != nil {
		return nil, err
	}

	emit("meta", fmt.Sprintf("Waiting for the first boot of %s %s on :%d (timeout %s)...", opts.OS, opts.Version, reinstallSSHPort, friendly(reinstallBootBudget)))
	probe := reinstallReadyProbe{
		expectedOS:             opts.OS,
		expectedVersion:        opts.Version,
		oldMachineID:           oldMachineID,
		requireMachineIDChange: !verifiedInstall,
	}
	newTarget, err := waitForReinstallTarget(ctx, req.IP, reinstallSSHPort, privKey, probe, reinstallBootBudget, emit)
	if err != nil {
		return nil, err
	}
	emit("ok", fmt.Sprintf("connected to freshly-installed %s %s on :%d", opts.OS, opts.Version, reinstallSSHPort))
	// The reinstall regenerated the box's host keys, so no pre-run pin
	// can cover this connection — surface what we accepted, and record
	// it under the NEW port so future bootstraps/reconnects of this
	// target verify against it. (The pre-reinstall entry for the old
	// port is left alone; it describes a system that no longer exists,
	// and a fresh box reusing that port gets the mismatch-remediation
	// message.)
	emit("meta", "⚠ new system's host key accepted on first use (NOT verifiable — keys were regenerated by the reinstall): "+newTarget.fingerprint())
	newHostport := net.JoinHostPort(req.IP, fmt.Sprintf("%d", reinstallSSHPort))
	if perr := hostKeys.Put(newHostport, newTarget.fingerprint()); perr != nil {
		emit("meta", "could not record the new host key fingerprint ("+perr.Error()+") — the next bootstrap of "+newHostport+" will be treated as a first contact")
	} else if hostKeys != nil {
		emit("ok", "new host key recorded for "+newHostport)
	}
	return newTarget, nil
}

// runReinstallPrep ensures curl on the target, then downloads,
// verifies, pins, and runs reinstall.sh under the prep budget (see
// reinstallPrepBudget — the jobs carry no global timeout, so a
// stalled mirror would otherwise idle the run indefinitely). Returns
// the prep stdout (a tail — see resolvePrepNetInfo) for the network
// cross-check. Extracted from runReinstall to keep the orchestrator
// under the cognitive-complexity ceiling (S3776).
func runReinstallPrep(ctx context.Context, target *targetSession, opts ReinstallOpts, pubKey string, emit func(typ, text string)) (string, error) {
	emit("meta", "Ensuring curl is available on target (needed by reinstall.sh)...")
	if _, stderr, err := target.runRoot(ctx, ensureCurlScript(), ""); err != nil {
		return "", fmt.Errorf("prepare reinstall curl dependency: %s: %w", strings.TrimSpace(stderr), err)
	}
	emit("ok", "curl available")

	emit("meta", fmt.Sprintf("Running reinstall.sh %s %s on target (this prepares the new install — actual reinstall happens after reboot)...", opts.OS, opts.Version))

	heartbeat := startHeartbeat(ctx, "reinstall.sh still running", emit)
	defer heartbeat()
	prepCtx, cancelPrep := context.WithTimeout(ctx, reinstallPrepBudget)
	stdout, stderr, err := target.runRoot(prepCtx, reinstallPrepScript(opts, pubKey), "")
	cancelPrep()
	heartbeat()
	if err != nil {
		if errors.Is(prepCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return "", fmt.Errorf("reinstall.sh prep did not finish within %s — a download from the pinned repo or the OS image mirror likely stalled; re-run bootstrap to retry", friendly(reinstallPrepBudget))
		}
		detail := reinstallFailureDetail(stdout, stderr)
		if detail == "" {
			return "", fmt.Errorf("reinstall.sh failed: %w", err)
		}
		return "", fmt.Errorf("reinstall.sh failed: %w\n%s", err, detail)
	}
	if tail := tailLines(stdout, 6); tail != "" {
		emit("meta", "reinstall.sh tail:\n"+tail)
	}
	emit("ok", "reinstall.sh prepared the new install")
	return stdout, nil
}

// resolvePrepNetInfo parses the detected network config out of the
// prep stdout, recovering from the tee'd prep log when needed.
//
// stdout is a TAIL buffer (targetStdoutMax) and the script prints
// its Network Info block early in prep — enough later output
// (verbose mirrors, progress spam) could push some or all of the
// block out of the tail and weaken the pre-reboot check via its
// fail-open paths. The tee'd prep log still holds the complete
// transcript and the box is alive pre-reboot, so whenever the tail
// was truncated — not just when it parsed to nothing, since a
// partial tail can retain one address family or a stale occurrence —
// the complete log is re-read and preferred over whatever the tail
// happened to keep.
func resolvePrepNetInfo(ctx context.Context, target *targetSession, stdout string, emit func(typ, text string)) reinstallNetInfo {
	netInfo := parseReinstallNetInfo(stdout)
	if !outputWasTruncated(stdout) && len(netInfo.ips()) > 0 {
		return netInfo
	}
	out, _, err := target.runRoot(ctx, netInfoFromLogScript, "")
	if err != nil {
		return netInfo
	}
	if recovered := parseReinstallNetInfo(out); len(recovered.ips()) > 0 {
		emit("meta", "prep output tail was incomplete — using the network detection re-read from "+reinstallPrepLog)
		return recovered
	}
	return netInfo
}

// detachedRebootCmd triggers a reboot that survives its SSH session
// ending: setsid detaches the subshell so neither sshd's
// process-group cleanup nor systemd-logind (KillUserProcesses) can
// reap it before the sleep elapses — with a bare `&` the reboot was
// occasionally lost that way. The fallback chain covers every box
// this runs on: systemctl (debian-family old system / new system),
// plain reboot (openrc in the alpine installer env), reboot -f
// (last resort; the callers sync beforehand where it matters).
const detachedRebootCmd = `nohup setsid sh -c 'sleep 2; systemctl reboot || reboot || reboot -f' >/dev/null 2>&1 &`

// scheduleDetachedReboot fires detachedRebootCmd and treats any
// error as a warning: a fast reboot or half-closed SSH channel can
// surface an error from runRoot even though the side-effect is
// already scheduled. The caller's follow-up wait (waitForTargetDown
// or the installer/boot probes) catches the case where the reboot
// genuinely never fires.
func scheduleDetachedReboot(ctx context.Context, target *targetSession, emit func(typ, text string)) {
	if _, _, err := target.runRoot(ctx, detachedRebootCmd, ""); err != nil {
		emit("meta", fmt.Sprintf("reboot scheduling returned %v — proceeding (the reboot itself is detached)", err))
	} else {
		emit("ok", "reboot scheduled")
	}
}

// reinstallPrepDir is the working directory for the prep phase on
// the OLD (multi-user) system. It must NOT live in /tmp: the prep
// runs as root and /tmp is world-writable, so predictable names
// there let any unprivileged local user pre-create reinstall.log as
// a symlink (root's tee then clobbers an arbitrary file) or plant an
// attacker-owned file whose contents the netinfo recovery would
// read. /run is root-owned tmpfs on every supported distro; the dir
// is recreated 0700 at the top of each prep run and umask 077 keeps
// every file inside it 0600.
const (
	reinstallPrepDir = "/run/ansbui-reinstall"
	reinstallPrepLog = reinstallPrepDir + "/reinstall.log"
)

// netInfoFromLogScript re-extracts the Network Info field lines from
// the tee'd prep log for parseReinstallNetInfo. \r progress spam is
// flattened first; the grep is case-insensitive and unanchored (the
// parser skips anything that doesn't prefix-match after trimming),
// and tail bounds the reply. The trailing `true` keeps a no-match
// grep (exit 1) from surfacing as a step failure — recovery is
// best-effort on top of verifyReinstallNetconf's fail-open paths.
const netInfoFromLogScript = `tr -d '\r' < ` + reinstallPrepLog + ` 2>/dev/null | grep -aiE '(IPv4|IPv6) (Address|Gateway):' | tail -n 20; true`

// reinstallNetInfo is the network config reinstall.sh reports
// detecting during prep, parsed from the plain-text "Network Info"
// block collect_netconf echoes (`IPv4 Address: 1.2.3.4/24` etc.).
// Addresses keep their /cidr suffix for display; ips() strips it.
type reinstallNetInfo struct {
	ipv4Addr, ipv4Gateway string
	ipv6Addr, ipv6Gateway string
}

// parseReinstallNetInfo extracts the detected addresses/gateways
// from reinstall.sh's prep output. Field labels are fixed English
// literals in the pinned script, so prefix matching is stable
// across runs; when a label appears more than once (collect_netconf
// can run twice during prep) the last occurrence wins, matching
// what actually gets baked into the installer. Missing fields stay
// "" — callers fail open on absent data.
func parseReinstallNetInfo(out string) reinstallNetInfo {
	var nc reinstallNetInfo
	fields := map[string]*string{
		"ipv4 address:": &nc.ipv4Addr,
		"ipv4 gateway:": &nc.ipv4Gateway,
		"ipv6 address:": &nc.ipv6Addr,
		"ipv6 gateway:": &nc.ipv6Gateway,
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		for prefix, dst := range fields {
			if strings.HasPrefix(lower, prefix) {
				*dst = strings.TrimSpace(line[len(prefix):])
			}
		}
	}
	return nc
}

// ips returns the detected primary addresses as parsed IPs, /cidr
// suffixes stripped. Unparseable or empty fields are skipped.
func (nc reinstallNetInfo) ips() []net.IP {
	var out []net.IP
	for _, raw := range []string{nc.ipv4Addr, nc.ipv6Addr} {
		host := raw
		if i := strings.IndexByte(raw, '/'); i >= 0 {
			host = raw[:i]
		}
		if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
			out = append(out, ip)
		}
	}
	return out
}

// summary renders the detection for the emit stream, e.g.
// "IPv4 1.2.3.4/24 via 1.2.3.1; IPv6 (none)".
func (nc reinstallNetInfo) summary() string {
	part := func(label, addr, gw string) string {
		if addr == "" {
			return label + " (none)"
		}
		if gw == "" {
			gw = "?"
		}
		return fmt.Sprintf("%s %s via %s", label, addr, gw)
	}
	return part("IPv4", nc.ipv4Addr, nc.ipv4Gateway) + "; " + part("IPv6", nc.ipv6Addr, nc.ipv6Gateway)
}

// Verdicts for classifyDetectedNetconf.
const (
	netconfMatch     = iota // a detected address equals a target address
	netconfNoData           // nothing usable detected/parsed — fail open
	netconfNATLikely        // no match, but a detected address is private (1:1 NAT provider)
	netconfMismatch         // all detected addresses public, none match — abort-worthy
)

// classifyDetectedNetconf compares reinstall.sh's detected primary
// addresses against the bootstrap target's address(es). The NAT
// exemption keeps the gate from false-aborting on providers that
// give instances private on-box addresses behind 1:1 NAT (the
// target public IP never appears on the box there, and reinstall.sh
// handles that layout fine).
func classifyDetectedNetconf(detected, targets []net.IP) int {
	if len(detected) == 0 {
		return netconfNoData
	}
	anyPrivate := false
	for _, d := range detected {
		for _, t := range targets {
			if d.Equal(t) {
				return netconfMatch
			}
		}
		if isNATCandidate(d) {
			anyPrivate = true
		}
	}
	if anyPrivate {
		return netconfNATLikely
	}
	return netconfMismatch
}

// isNATCandidate reports whether ip is the kind of address a
// 1:1-NAT provider puts on the instance itself: RFC1918 / ULA
// (IsPrivate), CGNAT 100.64.0.0/10, loopback, or link-local.
func isNATCandidate(ip net.IP) bool {
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return true
	}
	return false
}

// resolveTargetIPs turns the bootstrap target address into IPs to
// compare against: literal IPs pass through, hostnames resolve via
// DNS (both families).
func resolveTargetIPs(ctx context.Context, addr string) ([]net.IP, error) {
	if ip := net.ParseIP(addr); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, addr)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

// verifyReinstallNetconf is the pre-reboot gate: it surfaces what
// reinstall.sh detected and aborts (before anything destructive
// happens) when the reinstalled system would come up on an address
// this bootstrap isn't targeting. Every uncertain path — parse
// failure, DNS failure, NAT-shaped addressing — fails open with a
// note rather than blocking a legitimate run.
func verifyReinstallNetconf(ctx context.Context, nc reinstallNetInfo, targetAddr string, emit func(typ, text string)) error {
	emit("meta", "reinstall.sh network detection: "+nc.summary())
	detected := nc.ips()
	if len(detected) == 0 {
		emit("meta", "couldn't parse reinstall.sh's network detection from the prep output — skipping the pre-reboot address cross-check")
		return nil
	}
	targets, err := resolveTargetIPs(ctx, targetAddr)
	if err != nil {
		emit("meta", fmt.Sprintf("could not resolve %s for the pre-reboot address cross-check (%v) — skipping", targetAddr, err))
		return nil
	}
	switch classifyDetectedNetconf(detected, targets) {
	case netconfMatch:
		emit("ok", "detected address matches the bootstrap target — new system will come up reachable")
	case netconfNATLikely:
		emit("meta", "detected addresses are private (box likely behind 1:1 NAT) — address cross-check not applicable, proceeding")
	case netconfMismatch:
		return fmt.Errorf(
			"aborting before reboot: reinstall.sh will configure the new system with %s, but this bootstrap targets %s — the reinstalled box would come up on the wrong address and never be reachable. The current OS is untouched. If the box has multiple IPs, reinstall.sh only carries the default-route NIC's primary address into the new install; re-run targeting that address, or fix the box's routing so the target address is primary",
			nc.summary(), targetAddr)
	}
	return nil
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
//   - reinstallWaitBudget bounds the installer stage: reboot into
//     the live env plus writing the new OS to disk (--hold 2 parks
//     it there when done). Cloud-image installs typically finish in
//     5-15 minutes, but a slow provider disk or throttled mirror
//     can stretch that; 45 keeps a legitimately slow install from
//     being misreported as a network failure.
//   - reinstallBootBudget bounds the final stage: rebooting out of
//     the installer env into the new OS's first boot (fs resize,
//     cloud-init, sshd up). The big variable — install time — has
//     already elapsed by then, so this is deliberately tighter.
const (
	reinstallPrepBudget = 15 * time.Minute
	targetDownBudget    = 5 * time.Minute
	reinstallWaitBudget = 45 * time.Minute
	reinstallBootBudget = 15 * time.Minute
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
// TLS re-enable: the pinned script's own curl() wrapper passes
// --insecure on every invocation (upstream tolerates broken 32-bit
// cygwin cert stores), which would let an on-path attacker replace
// trans.sh and every other helper the commit pin was supposed to
// fix — the pin only pins the URL, and --insecure surrenders the
// TLS layer that makes the URL trustworthy. We strip the flag from
// the verified content, then grep-verify both rewrites actually
// landed (a silently unapplied sed would otherwise reintroduce the
// hole on the next upstream refactor) before bash runs the script.
//
// Output is teed to reinstallPrepLog so the prep transcript is
// inspectable if the run fails before the reboot, and so the
// netinfo recovery path can re-read it. It does NOT survive the
// reinstall — the install erases the disk — so anything worth
// keeping must come out through the emit stream.
//
// Everything happens inside reinstallPrepDir (root-owned, 0700,
// recreated per run, umask 077) — see that constant for why /tmp
// is off limits for root-written predictable filenames.
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
	// --hold 2 stops trans.sh from rebooting out of the installer
	// env once the new OS is written to disk: the env stays up
	// (SSH on the same port/key) so runReinstall can verify the
	// rendered system and persist the install log before triggering
	// the final reboot itself. See waitForInstallerDone.
	runCmd := `bash reinstall.sh ` + shellQuote(opts.OS) + ` ` + shellQuote(opts.Version) +
		` --ci` +
		` --hold 2` +
		// Upstream prompts for a username even when --ssh-key is set.
		// Our SSH exec is deliberately noninteractive, so the prompt's
		// read sees EOF and set -e exits immediately unless this is
		// explicit. The reconnect contract below is root key auth.
		` --user root` +
		` --ssh-port ` + fmt.Sprintf("%d", reinstallSSHPort) +
		` --ssh-key ` + shellQuote(pubKey) +
		` 2>&1 | tee ` + reinstallPrepLog
	return strings.Join([]string{
		`set -e`,
		`umask 077`,
		`rm -rf ` + reinstallPrepDir,
		`mkdir -m 0700 ` + reinstallPrepDir,
		`cd ` + reinstallPrepDir,
		`if command -v curl >/dev/null 2>&1; then curl -fsSLO ` + shellQuote(reinstallScriptURL) +
			`; elif command -v wget >/dev/null 2>&1; then wget -q ` + shellQuote(reinstallScriptURL) +
			`; else echo "neither curl nor wget available" >&2; exit 1; fi`,
		`echo ` + shellQuote(reinstallScriptSHA256+"  reinstall.sh") + ` | sha256sum -c - ` +
			`|| { echo "reinstall.sh sha256 mismatch — refusing to run (expected ` + reinstallScriptSHA256 + `)" >&2; exit 1; }`,
		`sed -i -e 's|^confhome=.*|confhome=` + reinstallConfhomeURL + `|'` +
			` -e 's|^confhome_cn=.*|confhome_cn=` + reinstallConfhomeURL + `|'` +
			` -e 's|command curl --insecure |command curl |g' reinstall.sh`,
		`if grep -q 'command curl --insecure' reinstall.sh; then echo "reinstall.sh still passes --insecure to curl after patching — refusing to run" >&2; exit 1; fi`,
		`grep -qxF 'confhome=` + reinstallConfhomeURL + `' reinstall.sh || { echo "confhome commit-pin rewrite did not apply — refusing to run" >&2; exit 1; }`,
		`chmod +x reinstall.sh`,
		`bash -o pipefail -c ` + shellQuote(runCmd),
	}, "; ")
}

// Markers trans.sh writes into /reinstall.log inside the installer
// env. Both are contiguous literals in the pinned trans.sh (ANSI
// colour codes wrap them but don't interrupt them), so grep -F
// finds them reliably. HOLD 2 appears exactly once, when the
// install has finished and --hold 2 stopped the auto-reboot; ERROR
// comes from trans.sh's error()/ERR-trap paths.
const (
	installerHoldDoneMarker = "***** HOLD 2 *****"
	installerErrorMarker    = "***** ERROR *****"
)

// Verdicts for evalInstallerProbe.
const (
	installerInstalling = iota // keep waiting (detail = status/log line)
	installerHoldDone          // install finished, env held for verification
	installerErrored           // trans.sh reported an error — fail fast
	installerFinalOS           // box already answers as the target OS
)

// installerProbeScript gathers the installer stage's state in one
// round trip: os-release (is this even still the live env?), the
// hold-done and error marker counts, and the last useful log line.
// Every fragment tolerates its file/command missing; the counts
// come back empty when /reinstall.log doesn't exist and are treated
// as zero on the Go side.
var installerProbeScript = strings.Join([]string{
	`cat /etc/os-release 2>/dev/null`,
	`echo ` + reinstallProbeMarker,
	`grep -aFc ` + shellQuote(installerHoldDoneMarker) + ` /reinstall.log 2>/dev/null`,
	`echo ` + reinstallProbeMarker,
	`grep -aFc ` + shellQuote(installerErrorMarker) + ` /reinstall.log 2>/dev/null`,
	`echo ` + reinstallProbeMarker,
	`tail -n 40 /reinstall.log 2>/dev/null | tr '\r' '\n' | grep -Fiav -e password -e token | tail -n 1`,
	`true`,
}, "; ")

// evalInstallerProbe classifies one installerProbeScript output.
// The final-OS check runs first so a box that was already rebooted
// (manually, or by an upstream behaviour change) short-circuits to
// the boot probe instead of waiting for a hold marker that will
// never appear; the stricter machine-id/version checks there still
// decide whether it really is the new system. Pure function so the
// classification is unit-testable.
func evalInstallerProbe(out, expectedOS string) (int, string) {
	parts := strings.Split(out, reinstallProbeMarker)
	if len(parts) != 4 {
		return installerInstalling, "unexpected installer-probe output shape"
	}
	osRelease := parts[0]
	holdCount := strings.TrimSpace(parts[1])
	errCount := strings.TrimSpace(parts[2])
	logLine := sanitizeLogLine(parts[3])

	if osMatches(osRelease, expectedOS) {
		return installerFinalOS, ""
	}
	if holdCount != "" && holdCount != "0" {
		return installerHoldDone, logLine
	}
	if errCount != "" && errCount != "0" {
		if logLine == "" {
			logLine = "(no log line captured)"
		}
		return installerErrored, logLine
	}
	status := fmt.Sprintf("in installer env (%s)", detectDistro(osRelease))
	if logLine != "" {
		status += " — " + logLine
	}
	return installerInstalling, status
}

// runInstallerHoldStage drives the --hold 2 window: wait for the
// installer to finish writing the new OS, then — with the box
// parked in the live env and the new system mounted at /os —
// persist the install log, verify the rendered network config, and
// trigger the reboot into the new system. Failing here leaves the
// box HELD and reachable for inspection instead of rebooting it
// into a possibly-unreachable first boot.
func runInstallerHoldStage(ctx context.Context, host string, privKey []byte, netInfo reinstallNetInfo, expectedOS string, emit func(typ, text string)) (bool, error) {
	holdTarget, alreadyFinal, err := waitForInstallerDone(ctx, host, reinstallSSHPort, privKey, expectedOS, emit)
	if err != nil {
		return false, err
	}
	if alreadyFinal {
		emit("meta", "target already answers as the final OS — skipping installer-env verification (rebooted out-of-band?)")
		return false, nil
	}
	defer func() { _ = holdTarget.Close() }()
	emit("ok", "installer finished writing the new system — verifying before first boot...")
	if err := verifyInstalledSystem(ctx, holdTarget, host, netInfo, emit); err != nil {
		return false, err
	}
	emit("meta", "triggering reboot into the freshly-installed system...")
	scheduleDetachedReboot(ctx, holdTarget, emit)
	return true, nil
}

// waitForInstallerDone polls the installer env on (host:port) until
// trans.sh reports the install finished (hold marker), errored, or
// the box already answers as the final OS. Returns the OPEN session
// on hold-done — the caller runs the verification over it — and
// (nil, true, nil) when the final OS answered. Timeout means the
// installer env never finished or never came up at all; its own
// network setup is the usual culprit for the latter, observable
// only on the provider console.
func waitForInstallerDone(ctx context.Context, host string, port int, privKey []byte, expectedOS string, emit func(typ, text string)) (*targetSession, bool, error) {
	const (
		initialWait     = 15 * time.Second
		retryInterval   = 15 * time.Second
		heartbeatPeriod = 60 * time.Second
	)
	deadline := time.Now().Add(reinstallWaitBudget)
	if err := sleepCtx(ctx, initialWait); err != nil {
		return nil, false, err
	}
	startedAt := time.Now()
	lastBeat := time.Now()
	lastStatus := ""
	for {
		if time.Now().After(deadline) {
			hint := "check the provider's serial/VNC console — if the installer env never came up, its network setup is the usual culprit"
			if lastStatus != "" {
				hint = fmt.Sprintf("last status: %s — %s", lastStatus, hint)
			}
			return nil, false, fmt.Errorf("timeout after %s waiting for the installer to finish writing %s: %s", friendly(reinstallWaitBudget), expectedOS, hint)
		}
		target, verdict, detail := tryInstallerDone(ctx, host, port, privKey, expectedOS)
		switch verdict {
		case installerHoldDone:
			return target, false, nil
		case installerFinalOS:
			return nil, true, nil
		case installerErrored:
			return nil, false, fmt.Errorf("the installer reported an error and is holding the box in its live env — ssh root@%s -p %d (bootstrap key) to inspect /reinstall.log and /os, then re-run bootstrap. Last log: %s", host, port, detail)
		}
		lastStatus = detail
		if time.Since(lastBeat) >= heartbeatPeriod {
			emit("meta", fmt.Sprintf("installer still writing %s (%s elapsed) — %s", expectedOS, friendly(time.Since(startedAt)), detail))
			lastBeat = time.Now()
		}
		if err := sleepCtx(ctx, retryInterval); err != nil {
			return nil, false, err
		}
	}
}

// tryInstallerDone performs one dial + installer probe. The session
// is returned open ONLY on the hold-done verdict; every other path
// closes it.
func tryInstallerDone(ctx context.Context, host string, port int, privKey []byte, expectedOS string) (*targetSession, int, string) {
	// No expectation is available: the installer environment
	// generates its own ephemeral host key, distinct from both the
	// pre-reinstall system's and the one the installed OS will
	// generate on first boot. Pinning across those transitions would
	// reject the legitimate box. Strict-mode deployments refuse the
	// reinstall before it starts (Validate / runReinstall) rather
	// than relying on a pin that cannot exist here.
	target, err := dialKeyTarget(ctx, host, port, privKey, hostKeyExpectation{})
	if err != nil {
		return nil, installerInstalling, "dial: " + err.Error()
	}
	out, _, err := target.runRoot(ctx, installerProbeScript, "")
	if err != nil {
		_ = target.Close()
		return nil, installerInstalling, "installer probe: " + err.Error()
	}
	verdict, detail := evalInstallerProbe(out, expectedOS)
	if verdict == installerHoldDone {
		return target, verdict, detail
	}
	_ = target.Close()
	return nil, verdict, detail
}

// persistInstallLogScript copies the installer's full log into the
// installed system (mounted at /os during the hold) so it survives
// the reboot — /reinstall.log itself lives in the live env's tmpfs
// and is destroyed the moment the box reboots. sync matters: the
// next step is a reboot we don't control the timing of.
const persistInstallLogScript = `[ -d /os ] || exit 1; mkdir -p /os/var/log && cp /reinstall.log /os/var/log/reinstall-install.log && sync`

// installLogTailScript extracts the last useful lines of the
// install log for the event stream: \r progress spam flattened,
// password/token lines dropped (mirrors upstream's own log-viewer
// filter; emit-side redaction still applies on top).
const installLogTailScript = `tail -n 400 /reinstall.log 2>/dev/null | tr '\r' '\n' | grep -Fiav -e password -e token | tail -n 12`

// installedNetVerifyScript checks the network config rendered into
// the installed system for one of the detected addresses, or for
// DHCP. Directory set covers every renderer trans.sh uses across
// the matrix (netplan, systemd-networkd, ifupdown, cloud-init;
// sysconfig kept for a future redhat-family matrix). Prints exactly
// one token; missing dirs fail open as NO_CONFIG_DIRS rather than
// misreporting an absent address.
func installedNetVerifyScript(ips []net.IP) string {
	quoted := make([]string, 0, len(ips))
	for _, ip := range ips {
		quoted = append(quoted, shellQuote(ip.String()))
	}
	return strings.Join([]string{
		`dirs=""`,
		`for d in /os/etc/netplan /os/etc/systemd/network /os/etc/network /os/etc/cloud /os/etc/sysconfig/network-scripts; do [ -d "$d" ] && dirs="$dirs $d"; done`,
		`[ -n "$dirs" ] || { echo NO_CONFIG_DIRS; exit 0; }`,
		`for ip in ` + strings.Join(quoted, " ") + `; do if grep -raqF -- "$ip" $dirs 2>/dev/null; then echo FOUND_IP; exit 0; fi; done`,
		`if grep -raqi -- dhcp $dirs 2>/dev/null; then echo FOUND_DHCP; exit 0; fi`,
		`echo NOT_FOUND`,
	}, "; ")
}

// verifyInstalledSystem runs over the held installer session:
// persist the log, surface its tail, and gate the reboot on the
// rendered network config mentioning a detected address (or DHCP).
// Only the NOT_FOUND verdict blocks — it means the new system would
// likely boot unreachable, and holding the box beats losing it.
// Everything else fails open: at this point the disk is already
// written, so an inconclusive check must not strand a good install.
func verifyInstalledSystem(ctx context.Context, target *targetSession, host string, netInfo reinstallNetInfo, emit func(typ, text string)) error {
	if _, _, err := target.runRoot(ctx, persistInstallLogScript, ""); err != nil {
		emit("meta", fmt.Sprintf("couldn't persist the install log into the new system (%v) — continuing", err))
	} else {
		emit("ok", "install log saved to /var/log/reinstall-install.log on the new system")
	}

	if out, _, err := target.runRoot(ctx, installLogTailScript, ""); err == nil {
		if tail := strings.TrimSpace(stripANSI(out)); tail != "" {
			emit("meta", "installer log tail:\n"+tail)
		}
	}

	ips := netInfo.ips()
	if len(ips) == 0 {
		emit("meta", "no detected addresses available — skipping the rendered-config check")
		return nil
	}
	out, _, err := target.runRoot(ctx, installedNetVerifyScript(ips), "")
	if err != nil {
		emit("meta", fmt.Sprintf("rendered-config check failed to run (%v) — continuing", err))
		return nil
	}
	switch strings.TrimSpace(out) {
	case "FOUND_IP":
		emit("ok", "rendered network config contains the detected address")
	case "FOUND_DHCP":
		emit("ok", "rendered network config uses DHCP")
	case "NO_CONFIG_DIRS":
		emit("meta", "no known network-config dirs under /os — can't verify the render; continuing")
	case "NOT_FOUND":
		return fmt.Errorf("aborting before first boot: the installed system's network config mentions neither the detected address(es) %s nor DHCP — it would likely boot unreachable. The box is HELD in the installer env: ssh root@%s -p %d (bootstrap key), inspect/fix the config under /os/etc, run `reboot`, then re-run bootstrap without the reinstall step", netInfo.summary(), host, reinstallSSHPort)
	default:
		emit("meta", "rendered-config check returned an unexpected verdict — continuing")
	}
	return nil
}

// sleepCtx waits d or until ctx is cancelled, whichever comes
// first. Shared by the reinstall wait loops.
func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
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
//   - oldMachineID: when requireMachineIDChange is true and this is
//     non-empty, /etc/machine-id must differ. This guards the fallback
//     path where the final OS appeared before we observed and verified
//     the held installer. Cloud images may reuse a template machine-id,
//     so equality is not negative proof after a verified HOLD 2 stage.
type reinstallReadyProbe struct {
	expectedOS             string
	expectedVersion        string
	oldMachineID           string
	requireMachineIDChange bool
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
// or until ctx is cancelled / budget elapses. The probe is what
// distinguishes the reinstaller's live environment (where
// reinstall.sh exposes SSH on :4242 with the same key for
// `screen -r` monitoring) — and a box that wrongly booted back
// into its old system — from the freshly-installed target OS.
// Without it we'd attach to the live env mid-install and run
// `apt install` against an alpine initramfs.
//
// The first 15 seconds are an unconditional sleep — the caller has
// already confirmed the previous stage's system went down or was
// told to reboot, so this only skips the shutdown/BIOS window where
// dialing is pure noise. Subsequent retries are 15s apart; with
// dialKeyTarget's 15s dial timeout the worst-case loop iteration is
// 30s. A heartbeat fires every 60s so the operator sees progress.
func waitForReinstallTarget(ctx context.Context, host string, port int, privKey []byte, probe reinstallReadyProbe, budget time.Duration, emit func(typ, text string)) (*targetSession, error) {
	const (
		initialWait     = 15 * time.Second
		retryInterval   = 15 * time.Second
		heartbeatPeriod = 60 * time.Second
	)
	deadline := time.Now().Add(budget)
	if err := sleepCtx(ctx, initialWait); err != nil {
		return nil, err
	}
	startedAt := time.Now()
	lastBeat := time.Now()
	var lastStatus string
	for {
		if time.Now().After(deadline) {
			// The install itself already finished (the hold stage
			// verified it) but the new system never came back on
			// the expected port. By far the most common cause is
			// networking failing to come up in the new install
			// (NIC rename machinery, or the static config not
			// matching the new interface), which is invisible over
			// SSH. Point the operator at the provider console, the
			// only place that failure is observable — and at the
			// install log the hold stage persisted onto the box.
			hint := fmt.Sprintf("check the provider's serial/VNC console: the install completed but %s isn't reachable on :%d, usually because networking (NIC rename / static config) didn't come up on first boot. The full install log is at /var/log/reinstall-install.log on the box", probe.expectedOS, port)
			if lastStatus == "" {
				return nil, fmt.Errorf("timeout after %s waiting for SSH on :%d — %s", friendly(budget), port, hint)
			}
			return nil, fmt.Errorf("timeout after %s waiting for %s to come up (last status: %s) — %s", friendly(budget), probe.expectedOS, lastStatus, hint)
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
		if err := sleepCtx(ctx, retryInterval); err != nil {
			return nil, err
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
	// Empty expectation for the same reason as tryInstallerDone: this
	// loop legitimately spans the installer-to-installed-OS handover,
	// so the key seen on an early retry is not the key the booted
	// system will present. The security control for this window is
	// the strict-mode refusal up front, not a pin.
	target, err := dialKeyTarget(ctx, host, port, privKey, hostKeyExpectation{})
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
	if probe.requireMachineIDChange && probe.oldMachineID != "" && machineID != "" && machineID == probe.oldMachineID {
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

// reinstallFailureDetail returns a bounded, terminal-safe transcript for a
// failed prep run. reinstall.sh merges stderr into stdout before teeing its
// log, so looking only at runRoot's stderr loses the upstream error that
// caused pipefail to return non-zero. Outer wrapper failures (download,
// checksum, sed) still use stderr, so retain both streams when available.
func reinstallFailureDetail(stdout, stderr string) string {
	const maxLines = 12
	cleanTail := func(s string) string {
		lines := strings.Split(s, "\n")
		cleaned := make([]string, 0, len(lines))
		for _, line := range lines {
			if line = sanitizeLogLine(line); line != "" {
				cleaned = append(cleaned, line)
			}
		}
		if len(cleaned) > maxLines {
			cleaned = cleaned[len(cleaned)-maxLines:]
		}
		return strings.Join(cleaned, "\n")
	}

	stdout = cleanTail(stdout)
	stderr = cleanTail(stderr)
	switch {
	case stdout != "" && stderr != "":
		return "output:\n" + stdout + "\nstderr:\n" + stderr
	case stdout != "":
		return "output:\n" + stdout
	default:
		return stderr
	}
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
