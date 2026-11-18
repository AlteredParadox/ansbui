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
	"testing"

	"github.com/AlteredParadox/ansbui/internal/config"
)

func TestLockInventoryKeying(t *testing.T) {
	const (
		workDir     = "/opt/ansible"
		mainInv     = "hosts.yml"
		dnsTestFQDN = "host.example.com"
	)
	a := config.Server{ID: "srv-a", WorkDir: workDir, Inventory: mainInv}
	sameAsA := config.Server{ID: "srv-a", WorkDir: workDir, Inventory: mainInv}
	otherServer := config.Server{ID: "srv-b", WorkDir: workDir, Inventory: mainInv}
	otherFile := config.Server{ID: "srv-a", WorkDir: workDir, Inventory: "staging.yml"}

	if lockInventory(a) != lockInventory(sameAsA) {
		t.Error("same server + inventory must share one mutex")
	}
	if lockInventory(a) == lockInventory(otherServer) {
		t.Error("different servers must not share an inventory mutex")
	}
	if lockInventory(a) == lockInventory(otherFile) {
		t.Error("different inventory files must not share a mutex")
	}
	// The three lock domains must be mutually disjoint — no crafted
	// key in one namespace can collide with another, since the NUL
	// separator can't appear in a validated address / id / path / fqdn.
	if lockInventory(a) == lockTarget("inventory") {
		t.Error("inventory key collided with a plain target key")
	}
	if lockDNSRecord("A", "srv-a") == lockTarget("A\x00srv-a") {
		t.Error("dns key collided with a target key")
	}
	if lockDNSRecord("A", dnsTestFQDN) == lockDNSRecord("AAAA", dnsTestFQDN) {
		t.Error("different record types must not share a mutex")
	}
	// DNS fqdn is lower-cased, so case variants share one lock.
	if lockDNSRecord("A", "Host.Example.com") != lockDNSRecord("A", dnsTestFQDN) {
		t.Error("dns fqdn case variants must share one mutex")
	}
}
