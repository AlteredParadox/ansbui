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
