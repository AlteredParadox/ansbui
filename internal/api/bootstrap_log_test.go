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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/AlteredParadox/ansbui/internal/jobs"
)

// TestBootstrapLogEndpoint verifies the REST log endpoint returns a
// finished job's snapshot plus its buffered events — the payload the
// Bootstrap view's "recent runs" panel renders — and 404s for ids
// the registry doesn't know (backend restarted since the run).
func TestBootstrapLogEndpoint(t *testing.T) {
	s := &Server{
		Addr: selfHost,
		Jobs: jobs.New(),
		WebRoot: fstest.MapFS{
			"index.html": &fstest.MapFile{Data: []byte("<!doctype html>")},
		},
	}
	job, err := s.Jobs.Start("bootstrap", map[string]string{"hostname": "host.example.com"}, func(_ context.Context, emit func(string, string)) error {
		emit("meta", "Connecting...")
		emit("fail", "apt install: exit status 100")
		return context.DeadlineExceeded // any non-nil error → StatusFailed
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()

	req := httptest.NewRequest(http.MethodGet, "/api/bootstrap/jobs/"+job.ID+"/log", nil)
	req.Host = selfHost
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%q", w.Code, http.StatusOK, w.Body.String())
	}
	var body struct {
		Job    jobs.Snapshot `json:"job"`
		Events []jobs.Event  `json:"events"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v; body=%q", err, w.Body.String())
	}
	if body.Job.Status != jobs.StatusFailed {
		t.Fatalf("job.status = %q, want %q", body.Job.Status, jobs.StatusFailed)
	}
	if len(body.Events) != 2 {
		t.Fatalf("events len = %d, want 2; body=%q", len(body.Events), w.Body.String())
	}
	if body.Events[1].Type != "fail" || body.Events[1].Text != "apt install: exit status 100" {
		t.Fatalf("events[1] = %+v, want the fail event", body.Events[1])
	}

	req = httptest.NewRequest(http.MethodGet, "/api/bootstrap/jobs/no-such-id/log", nil)
	req.Host = selfHost
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown id: status = %d, want %d", w.Code, http.StatusNotFound)
	}
}
