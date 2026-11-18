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
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/ansible"
)

// GET /api/runs is the run table: every record, newest first, without
// logs. GET /api/runs/{id} is one record with its log.
func TestRunsEndpoints(t *testing.T) {
	rec, err := ansible.NewRecorder(filepath.Join(t.TempDir(), "runs.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"run-old", "run-new"} {
		err := rec.Append(ansible.RunRecord{
			ID: id, Kind: "playbook", Playbook: "site.yml",
			StartedAt: time.Date(2026, 1, 1+i, 0, 0, 0, 0, time.UTC),
			ExtraVars: map[string]any{"ansible_become_pass": "dummy-secret"},
			Log:       []ansible.Event{{Type: "line", Text: "ok: [web1]"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Runs: rec}

	w := httptest.NewRecorder()
	s.listRuns(w, httptest.NewRequest(http.MethodGet, "/api/runs", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("list: status %d", w.Code)
	}
	var list struct {
		Runs []ansible.RunRecord `json:"runs"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Runs) != 2 || list.Runs[0].ID != "run-new" || list.Runs[1].ID != "run-old" {
		t.Fatalf("list = %+v, want run-new then run-old", list.Runs)
	}
	for _, r := range list.Runs {
		if len(r.Log) != 0 {
			t.Errorf("%s: the list response carries %d log events", r.ID, len(r.Log))
		}
		if r.ExtraVars["ansible_become_pass"] != "<REDACTED>" {
			t.Errorf("%s: extra-vars served as %v", r.ID, r.ExtraVars)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/api/runs/run-old", nil)
	r.SetPathValue("id", "run-old")
	w = httptest.NewRecorder()
	s.getRun(w, r)
	var one ansible.RunRecord
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || one.ID != "run-old" || len(one.Log) != 1 || one.Log[0].Text != "ok: [web1]" {
		t.Errorf("get: status %d, record %+v", w.Code, one)
	}

	r = httptest.NewRequest(http.MethodGet, "/api/runs/nope", nil)
	r.SetPathValue("id", "nope")
	w = httptest.NewRecorder()
	s.getRun(w, r)
	if w.Code != http.StatusNotFound {
		t.Errorf("get of an unknown run: status %d", w.Code)
	}
}
