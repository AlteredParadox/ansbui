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
	// The namespace must be disjoint from target keys: a hostile or
	// unlucky ip:port string can never equal an inventory key because
	// of the NUL separators.
	if lockInventory(a) == lockTarget("inventory") {
		t.Error("inventory key collided with a plain target key")
	}
}
