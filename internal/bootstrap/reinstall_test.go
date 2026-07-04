package bootstrap

import (
	"strings"
	"testing"
)

// probeOut assembles a reinstallProbeScript-shaped output the way
// the remote shell would produce it: four sections separated by
// marker lines (os-release, systemd state, machine-id, installer
// log tail).
func probeOut(osRelease, sysState, machineID string) string {
	return probeOutWithLog(osRelease, sysState, machineID, "")
}

func probeOutWithLog(osRelease, sysState, machineID, logLine string) string {
	return osRelease + reinstallProbeMarker + "\n" + sysState + "\n" + reinstallProbeMarker + "\n" + machineID + "\n" + reinstallProbeMarker + "\n" + logLine + "\n"
}

const debian13Release = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n"

func TestEvalReinstallProbe(t *testing.T) {
	probe := reinstallReadyProbe{
		expectedOS:      "debian",
		expectedVersion: "13",
		oldMachineID:    "aaaa1111",
	}
	cases := []struct {
		name       string
		out        string
		probe      reinstallReadyProbe
		wantReady  bool
		wantStatus string // substring the not-ready status must contain
	}{
		{
			name:      "fresh system settled",
			out:       probeOut(debian13Release, "running", "bbbb2222"),
			probe:     probe,
			wantReady: true,
		},
		{
			name:      "degraded still counts as settled",
			out:       probeOut(debian13Release, "degraded", "bbbb2222"),
			probe:     probe,
			wantReady: true,
		},
		{
			name:       "installer live env",
			out:        probeOut("ID=alpine\n", "", "cccc3333"),
			probe:      probe,
			wantReady:  false,
			wantStatus: "installer",
		},
		{
			name:       "installer env surfaces log tail",
			out:        probeOutWithLog("ID=alpine\n", "", "cccc3333", "\x1b[32mDownloading cloud image 43%\x1b[0m"),
			probe:      probe,
			wantReady:  false,
			wantStatus: "installer log: Downloading cloud image 43%",
		},
		{
			name:       "old system answered — machine-id unchanged",
			out:        probeOut(debian13Release, "running", "aaaa1111"),
			probe:      probe,
			wantReady:  false,
			wantStatus: "machine-id is unchanged",
		},
		{
			name:       "wrong version answered",
			out:        probeOut("ID=debian\nVERSION_ID=\"12\"\n", "running", "bbbb2222"),
			probe:      probe,
			wantReady:  false,
			wantStatus: "version 12",
		},
		{
			name:       "systemd still starting",
			out:        probeOut(debian13Release, "starting", "bbbb2222"),
			probe:      probe,
			wantReady:  false,
			wantStatus: "settle",
		},
		{
			name:      "missing VERSION_ID fails open",
			out:       probeOut("ID=debian\n", "running", "bbbb2222"),
			probe:     probe,
			wantReady: true,
		},
		{
			name:      "missing systemd state fails open",
			out:       probeOut(debian13Release, "", "bbbb2222"),
			probe:     probe,
			wantReady: true,
		},
		{
			name: "no old machine-id skips the reinstall proof",
			out:  probeOut(debian13Release, "running", "aaaa1111"),
			probe: reinstallReadyProbe{
				expectedOS:      "debian",
				expectedVersion: "13",
			},
			wantReady: true,
		},
		{
			name:       "malformed probe output",
			out:        "garbage without markers",
			probe:      probe,
			wantReady:  false,
			wantStatus: "probe output",
		},
		{
			name:      "ubuntu dotted version matches",
			out:       probeOut("ID=ubuntu\nVERSION_ID=\"24.04\"\n", "running", "bbbb2222"),
			probe:     reinstallReadyProbe{expectedOS: "ubuntu", expectedVersion: "24.04", oldMachineID: "aaaa1111"},
			wantReady: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ready, status := evalReinstallProbe(tc.out, tc.probe)
			if ready != tc.wantReady {
				t.Fatalf("ready = %v, want %v (status: %q)", ready, tc.wantReady, status)
			}
			if !ready && !strings.Contains(status, tc.wantStatus) {
				t.Fatalf("status %q does not contain %q", status, tc.wantStatus)
			}
			if ready && status != "" {
				t.Fatalf("ready probe returned non-empty status %q", status)
			}
		})
	}
}

// TestReinstallPrepScriptPinsConfhome guards the confhome rewrite:
// the prep script must verify the checksum BEFORE the sed edit and
// must repoint both confhome variables at the pinned commit, so
// install-time helper downloads (trans.sh, debian.cfg, ...) can't
// drift with upstream's main branch.
func TestReinstallPrepScriptPinsConfhome(t *testing.T) {
	script := reinstallPrepScript(ReinstallOpts{Enabled: true, OS: "debian", Version: "13"}, "ssh-ed25519 AAAA test")
	for _, want := range []string{
		"sha256sum -c",
		"confhome=" + reinstallConfhomeURL,
		"confhome_cn=" + reinstallConfhomeURL,
		"--ci",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("prep script missing %q:\n%s", want, script)
		}
	}
	if !strings.Contains(reinstallConfhomeURL, reinstallScriptCommit) {
		t.Fatalf("reinstallConfhomeURL %q not pinned to commit %q", reinstallConfhomeURL, reinstallScriptCommit)
	}
	sedIdx := strings.Index(script, "sed -i")
	shaIdx := strings.Index(script, "sha256sum -c")
	if sedIdx < shaIdx {
		t.Fatalf("confhome rewrite happens before checksum verification")
	}
}

func TestSanitizeLogLine(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain progress line", "plain progress line"},
		{"\x1b[1;32mcoloured\x1b[0m text", "coloured text"},
		{"trailing cr\r", "trailing cr"},
		{"  padded  ", "padded"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := sanitizeLogLine(tc.in); got != tc.want {
			t.Fatalf("sanitizeLogLine(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := strings.Repeat("x", 500)
	if got := sanitizeLogLine(long); len([]rune(got)) != 161 { // 160 + ellipsis
		t.Fatalf("long line not truncated: %d runes", len([]rune(got)))
	}
}

func TestOSReleaseField(t *testing.T) {
	rel := "ID=debian\nVERSION_ID=\"13\"\nPRETTY_NAME=\"Debian GNU/Linux 13\"\n"
	if got := osReleaseField(rel, "VERSION_ID"); got != "13" {
		t.Fatalf("VERSION_ID = %q, want 13", got)
	}
	if got := osReleaseField(rel, "ID"); got != "debian" {
		t.Fatalf("ID = %q, want debian", got)
	}
	if got := osReleaseField(rel, "MISSING"); got != "" {
		t.Fatalf("MISSING = %q, want empty", got)
	}
}
