package bootstrap

import (
	"fmt"
	"net"
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

const (
	debian13Release = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\nVERSION_ID=\"13\"\n"
	alpineRelease   = "ID=alpine\n"
)

func TestEvalReinstallProbe(t *testing.T) {
	probe := reinstallReadyProbe{
		expectedOS:             "debian",
		expectedVersion:        "13",
		oldMachineID:           "aaaa1111",
		requireMachineIDChange: true,
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
			out:        probeOut(alpineRelease, "", "cccc3333"),
			probe:      probe,
			wantReady:  false,
			wantStatus: "installer",
		},
		{
			name:       "installer env surfaces log tail",
			out:        probeOutWithLog(alpineRelease, "", "cccc3333", "\x1b[32mDownloading cloud image 43%\x1b[0m"),
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
			name:      "verified install may reuse cloud image machine-id",
			out:       probeOut(debian13Release, "running", "aaaa1111"),
			probe:     reinstallReadyProbe{expectedOS: "debian", expectedVersion: "13", oldMachineID: "aaaa1111"},
			wantReady: true,
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
		"--hold 2",
		"--user root",
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

// installerProbeOut assembles an installerProbeScript-shaped output:
// os-release, hold-marker count, error-marker count, last log line.
func installerProbeOut(osRelease, holdCount, errCount, logLine string) string {
	return osRelease + reinstallProbeMarker + "\n" + holdCount + "\n" + reinstallProbeMarker + "\n" + errCount + "\n" + reinstallProbeMarker + "\n" + logLine + "\n"
}

func TestEvalInstallerProbe(t *testing.T) {
	cases := []struct {
		name       string
		out        string
		wantstate  int
		wantDetail string // substring the detail must contain ("" = don't care)
	}{
		{
			name:       "still installing with progress line",
			out:        installerProbeOut(alpineRelease, "0", "0", "Downloading cloud image 43%"),
			wantstate:  installerInstalling,
			wantDetail: "Downloading cloud image 43%",
		},
		{
			name:      "missing log counts as installing",
			out:       installerProbeOut(alpineRelease, "", "", ""),
			wantstate: installerInstalling,
		},
		{
			name:      "hold marker present",
			out:       installerProbeOut(alpineRelease, "1", "0", "***** HOLD 2 *****"),
			wantstate: installerHoldDone,
		},
		{
			name:       "error marker present",
			out:        installerProbeOut(alpineRelease, "0", "1", "Error: no space left on device"),
			wantstate:  installerErrored,
			wantDetail: "no space left",
		},
		{
			name:      "hold wins over error",
			out:       installerProbeOut(alpineRelease, "1", "1", ""),
			wantstate: installerHoldDone,
		},
		{
			name:      "final OS answered",
			out:       installerProbeOut(debian13Release, "", "", ""),
			wantstate: installerFinalOS,
		},
		{
			name:       "malformed output keeps waiting",
			out:        "garbage",
			wantstate:  installerInstalling,
			wantDetail: "probe output",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, detail := evalInstallerProbe(tc.out, "debian")
			if verdict != tc.wantstate {
				t.Fatalf("verdict = %d, want %d (detail: %q)", verdict, tc.wantstate, detail)
			}
			if tc.wantDetail != "" && !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("detail %q does not contain %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestInstalledNetVerifyScript(t *testing.T) {
	script := installedNetVerifyScript([]net.IP{net.ParseIP(testIPv4), net.ParseIP(testIPv6)})
	for _, want := range []string{
		"'" + testIPv4 + "'",
		"'" + testIPv6 + "'",
		"/os/etc/netplan",
		"/os/etc/cloud",
		"NO_CONFIG_DIRS",
		"FOUND_IP",
		"FOUND_DHCP",
		"NOT_FOUND",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("verify script missing %q:\n%s", want, script)
		}
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

func TestReinstallFailureDetail(t *testing.T) {
	t.Run("tee output carries upstream error", func(t *testing.T) {
		got := reinstallFailureDetail("checking host\n\x1b[31m***** ERROR *****\x1b[0m\nimage not accessible\n", "")
		want := "output:\nchecking host\n***** ERROR *****\nimage not accessible"
		if got != want {
			t.Fatalf("detail = %q, want %q", got, want)
		}
	})

	t.Run("outer stderr is retained", func(t *testing.T) {
		got := reinstallFailureDetail("reinstall.sh: OK\n", "sha256 mismatch\n")
		if !strings.Contains(got, "output:\nreinstall.sh: OK") || !strings.Contains(got, "stderr:\nsha256 mismatch") {
			t.Fatalf("detail did not retain both streams: %q", got)
		}
	})

	t.Run("tail is bounded", func(t *testing.T) {
		lines := make([]string, 15)
		for i := range lines {
			lines[i] = fmt.Sprintf("line %d", i)
		}
		got := reinstallFailureDetail(strings.Join(lines, "\n"), "")
		if strings.Contains(got, "line 2\n") || !strings.Contains(got, "line 3\n") || !strings.HasSuffix(got, "line 14") {
			t.Fatalf("unexpected bounded tail: %q", got)
		}
	})
}

// Canonical detected/target addresses used across the netconf
// tests (RFC5737/RFC3849 documentation ranges).
const (
	testIPv4 = "203.0.113.5"
	testIPv6 = "2001:db8::5"
)

// prepNetworkInfo mimics the plain-echo block collect_netconf
// writes into the prep output (values as reinstall.sh formats them,
// surrounded by unrelated prep noise).
const prepNetworkInfo = `Downloading cloud image...
***** NETWORK INFO *****
IPv4 MAC: aa:bb:cc:dd:ee:ff
IPv4 Address: ` + testIPv4 + `/24
IPv4 Gateway: 203.0.113.1
---
IPv6 MAC: aa:bb:cc:dd:ee:ff
IPv6 Address: ` + testIPv6 + `/64
IPv6 Gateway: 2001:db8::1
Building initrd...`

func TestParseReinstallNetInfo(t *testing.T) {
	nc := parseReinstallNetInfo(prepNetworkInfo)
	if nc.ipv4Addr != testIPv4+"/24" || nc.ipv4Gateway != "203.0.113.1" {
		t.Fatalf("ipv4 = %q via %q", nc.ipv4Addr, nc.ipv4Gateway)
	}
	if nc.ipv6Addr != testIPv6+"/64" || nc.ipv6Gateway != "2001:db8::1" {
		t.Fatalf("ipv6 = %q via %q", nc.ipv6Addr, nc.ipv6Gateway)
	}
	ips := nc.ips()
	if len(ips) != 2 || ips[0].String() != testIPv4 || ips[1].String() != testIPv6 {
		t.Fatalf("ips() = %v", ips)
	}

	// Last occurrence wins when the block repeats.
	twice := prepNetworkInfo + "\nIPv4 Address: 198.51.100.9/24\n"
	if got := parseReinstallNetInfo(twice).ipv4Addr; got != "198.51.100.9/24" {
		t.Fatalf("repeat block: ipv4Addr = %q", got)
	}

	// Empty fields (v6-less box) stay empty and don't produce IPs.
	v4only := "IPv4 Address: " + testIPv4 + "/24\nIPv4 Gateway: 203.0.113.1\nIPv6 Address:\nIPv6 Gateway:\n"
	nc = parseReinstallNetInfo(v4only)
	if nc.ipv6Addr != "" || len(nc.ips()) != 1 {
		t.Fatalf("v4-only parse: ipv6Addr=%q ips=%v", nc.ipv6Addr, nc.ips())
	}

	if got := parseReinstallNetInfo("no network block here").ips(); len(got) != 0 {
		t.Fatalf("garbage parse produced ips %v", got)
	}
}

func TestClassifyDetectedNetconf(t *testing.T) {
	ip := net.ParseIP
	cases := []struct {
		name     string
		detected []net.IP
		targets  []net.IP
		want     int
	}{
		{"match v4", []net.IP{ip(testIPv4)}, []net.IP{ip(testIPv4)}, netconfMatch},
		{"match v6 among many", []net.IP{ip(testIPv4), ip(testIPv6)}, []net.IP{ip(testIPv6)}, netconfMatch},
		{"no data", nil, []net.IP{ip(testIPv4)}, netconfNoData},
		{"nat private v4", []net.IP{ip("10.0.0.7")}, []net.IP{ip(testIPv4)}, netconfNATLikely},
		{"nat cgnat", []net.IP{ip("100.64.1.2")}, []net.IP{ip(testIPv4)}, netconfNATLikely},
		{"public mismatch", []net.IP{ip("198.51.100.9")}, []net.IP{ip(testIPv4)}, netconfMismatch},
		{"dual public mismatch", []net.IP{ip("198.51.100.9"), ip("2001:db8::9")}, []net.IP{ip(testIPv4)}, netconfMismatch},
		{"private plus public no match", []net.IP{ip("10.0.0.7"), ip("2001:db8::9")}, []net.IP{ip(testIPv4)}, netconfNATLikely},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDetectedNetconf(tc.detected, tc.targets); got != tc.want {
				t.Fatalf("got verdict %d, want %d", got, tc.want)
			}
		})
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
