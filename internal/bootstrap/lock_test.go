package bootstrap

import (
	"testing"

	"github.com/AlteredParadox/ansbui/internal/config"
)

func TestLockInventoryKeying(t *testing.T) {
	const (
		workDir = "/opt/ansible"
		mainInv = "hosts.yml"
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
	if lockDNSRecord("A", "host.example.com") == lockDNSRecord("AAAA", "host.example.com") {
		t.Error("different record types must not share a mutex")
	}
	// DNS fqdn is lower-cased, so case variants share one lock.
	if lockDNSRecord("A", "Host.Example.com") != lockDNSRecord("A", "host.example.com") {
		t.Error("dns fqdn case variants must share one mutex")
	}
}
