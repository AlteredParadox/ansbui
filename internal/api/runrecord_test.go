package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/config"
)

// TestRunRecordsCarryTheConnectionID: a run record names the
// connection it went through by config id as well as by display name.
// The UI compares the id with the active connection before offering to
// replay a record, and a name can be renamed or shared.
func TestRunRecordsCarryTheConnectionID(t *testing.T) {
	srv := config.Server{ID: "srv-1a2b", Name: "prod"}

	adhoc := buildAdhocRecord(srv, &ansible.AdhocRequest{Target: "web", Module: "ansible.builtin.ping"}, "run-1")
	if adhoc.ServerID != srv.ID || adhoc.Server != srv.Name {
		t.Errorf("ad-hoc record: server=%q serverId=%q, want %q / %q", adhoc.Server, adhoc.ServerID, srv.Name, srv.ID)
	}
	pb := buildPlaybookRecord(srv, &ansible.PlaybookRequest{Path: "staging/deploy.yml", Limit: "web"}, "run-2")
	if pb.ServerID != srv.ID || pb.Server != srv.Name {
		t.Errorf("playbook record: server=%q serverId=%q, want %q / %q", pb.Server, pb.ServerID, srv.Name, srv.ID)
	}
	// The path is recorded whole: it is what a re-run is matched on.
	if pb.Playbook != "staging/deploy.yml" {
		t.Errorf("playbook record path = %q", pb.Playbook)
	}

	// And it survives the round trip the history API serves.
	raw, err := json.Marshal(pb)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"serverId":"srv-1a2b"`) {
		t.Errorf("serverId missing from the serialised record: %s", raw)
	}
}
