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
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Tests for the operator-chosen SSH port of the bootstrapped system
// (Request.NewSSHPort). It used to be 4242 for everyone.

func portTestRequest() Request {
	return Request{
		Provider: "hetzner",
		IP:       "example.net",
		Port:     22,
		Username: "root",
		Password: "dummy-password",
		Hostname: "new1.example.com",
	}
}

// A request that names no port keeps getting 4242, so a client from
// before the field existed behaves as it always did.
func TestNewSSHPortDefaultsTo4242(t *testing.T) {
	req := portTestRequest()
	if err := Validate(req); err != nil {
		t.Fatalf("a request without newSshPort is rejected: %v", err)
	}
	if got := req.newSSHPort(); got != 4242 {
		t.Errorf("newSSHPort() = %d, want 4242", got)
	}
	req.NewSSHPort = 2222
	if got := req.newSSHPort(); got != 2222 {
		t.Errorf("newSSHPort() = %d, want the requested 2222", got)
	}
}

func TestValidateNewSSHPort(t *testing.T) {
	for _, port := range []int{1, 22, 2222, 4242, 65535} {
		req := portTestRequest()
		req.NewSSHPort = port
		if err := Validate(req); err != nil {
			t.Errorf("port %d rejected: %v", port, err)
		}
	}
	for _, port := range []int{-1, 65536, 100000} {
		req := portTestRequest()
		req.NewSSHPort = port
		err := Validate(req)
		if err == nil || !strings.Contains(err.Error(), "bootstrapped system") {
			t.Errorf("port %d: error = %v, want it refused as the new system's port", port, err)
		}
	}
}

// The reinstall script is told the chosen port: it is what the
// installer and the installed system are given.
func TestReinstallPrepScriptUsesTheChosenPort(t *testing.T) {
	script := reinstallPrepScript(ReinstallOpts{Enabled: true, OS: "debian", Version: "13"}, "ssh-ed25519 AAAA test", 2222)
	if !strings.Contains(script, " --ssh-port 2222 ") {
		t.Errorf("prep script does not pass --ssh-port 2222:\n%s", script)
	}
	if strings.Contains(script, "4242") {
		t.Errorf("prep script still mentions 4242:\n%s", script)
	}
}

// The sshd move targets the chosen port.
func TestSshdPortScriptUsesTheChosenPort(t *testing.T) {
	script := sshdPortScript(2222)
	if !strings.Contains(script, "TARGET=2222;") || strings.Contains(script, "4242") {
		t.Errorf("sshd port script is not for 2222:\n%s", script)
	}
}

// A new inventory entry records the port sshd was just put on.
// Without it ansible connects on 22 unless the inventory happens to
// set the port for the whole group.
func TestAddHostRecordsThePort(t *testing.T) {
	for _, port := range []int{22, 2222, 4242} {
		out, err := addHostToInventoryYAML([]byte(inventoryBase), "hetzner", "new1.example.com", port)
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		var inv struct {
			All struct {
				Children struct {
					VPS struct {
						Children struct {
							Debian struct {
								Children map[string]struct {
									Hosts map[string]map[string]int `yaml:"hosts"`
								} `yaml:"children"`
							} `yaml:"debian_servers"`
						} `yaml:"children"`
					} `yaml:"vps_servers"`
				} `yaml:"children"`
			} `yaml:"all"`
		}
		if err := yaml.Unmarshal(out, &inv); err != nil {
			t.Fatalf("port %d: output is not valid YAML: %v\n%s", port, err, out)
		}
		hosts := inv.All.Children.VPS.Children.Debian.Children["hetzner"].Hosts
		if got := hosts["new1.example.com"]["ansible_port"]; got != port {
			t.Errorf("new1.example.com ansible_port = %d, want %d:\n%s", got, port, out)
		}
		// The host that was already there is left as it was.
		if vars, ok := hosts["web1.example.com"]; !ok || len(vars) != 0 {
			t.Errorf("existing host was changed (%v):\n%s", vars, out)
		}
	}
}

// Adding a host that is already listed changes nothing, whatever port
// the run used: an entry the operator may have edited is not ours to
// rewrite.
func TestAddHostAlreadyPresentKeepsItsEntry(t *testing.T) {
	first, err := addHostToInventoryYAML([]byte(inventoryBase), "hetzner", "new1.example.com", 4242)
	if err != nil {
		t.Fatal(err)
	}
	second, err := addHostToInventoryYAML(first, "hetzner", "new1.example.com", 2222)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(second, first) {
		t.Errorf("a second add rewrote the entry:\n%s", second)
	}
}

// The host key is carried to whatever port sshd was moved to.
func TestCarryHostKeyUsesTheChosenPort(t *testing.T) {
	store := NewHostKeyStore(t.TempDir() + "/known.json")
	const fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	var probed int
	probe := func(_ context.Context, _ string, port int) (string, error) {
		probed = port
		return fp, nil
	}
	var log emitLog
	carryHostKeyToTargetPort(context.Background(), hostPortMove{host: "192.0.2.9", from: 22, to: 2222}, fp, store, probe, log.emit)
	if probed != 2222 {
		t.Errorf("probed port %d, want 2222", probed)
	}
	got, has, err := store.Get("192.0.2.9:2222")
	if err != nil || !has || got != fp {
		t.Errorf("record for :2222 = %q, %v, %v; want the session's fingerprint", got, has, err)
	}
	if _, has, _ := store.Get("192.0.2.9:4242"); has {
		t.Error("a record was written for :4242, which this run never used")
	}
}

// The form sends the port as "newSshPort"; the API decodes the body
// straight into Request and refuses unknown fields.
func TestRequestDecodesNewSSHPort(t *testing.T) {
	var req Request
	dec := json.NewDecoder(strings.NewReader(`{"port":22,"newSshPort":2222}`))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		t.Fatal(err)
	}
	if req.Port != 22 || req.NewSSHPort != 2222 {
		t.Errorf("decoded port=%d newSshPort=%d", req.Port, req.NewSSHPort)
	}
}
