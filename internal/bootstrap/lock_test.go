package bootstrap

import (
	"testing"

	"github.com/AlteredParadox/ansbui/internal/config"
)

func TestLockInventoryKeying(t *testing.T) {
	a := config.Server{ID: "srv-a", WorkDir: "/opt/ansible", Inventory: "hosts.yml"}
	sameAsA := config.Server{ID: "srv-a", WorkDir: "/opt/ansible", Inventory: "hosts.yml"}
	otherServer := config.Server{ID: "srv-b", WorkDir: "/opt/ansible", Inventory: "hosts.yml"}
	otherFile := config.Server{ID: "srv-a", WorkDir: "/opt/ansible", Inventory: "staging.yml"}

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
