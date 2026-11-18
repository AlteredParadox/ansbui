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

package ansible

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AlteredParadox/ansbui/internal/config"
)

const runsFileName = "runs.json"

// TestAppendPersistFailureKeepsRunInMemory: when the durable write
// fails, Append must return a descriptive error BUT keep the executed
// run visible in memory — losing a completed run's output entirely
// (the alternative) is worse than a memory/disk divergence the error
// already surfaces. We force the failure by pointing the recorder's
// path at a location whose parent is a regular file, so the tempfile
// create fails.
func TestAppendPersistFailureKeepsRunInMemory(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(filepath.Join(dir, runsFileName))
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}

	good := RunRecord{ID: "run-1", Kind: "adhoc", StartedAt: time.Now().UTC()}
	if err := rec.Append(good); err != nil {
		t.Fatalf("first Append: %v", err)
	}

	// Break the write path: a file can't have a child tempfile.
	rec.path = filepath.Join(dir, runsFileName, "nested", runsFileName)

	bad := RunRecord{ID: "run-2", Kind: "adhoc", StartedAt: time.Now().UTC()}
	err = rec.Append(bad)
	if err == nil {
		t.Fatal("expected Append to report the persist failure")
	}
	if !strings.Contains(err.Error(), "not persisted") {
		t.Errorf("error should flag the non-persisted state, got: %v", err)
	}
	// The executed run must still be visible in this process.
	if _, ok := rec.Get("run-2"); !ok {
		t.Error("run-2 must stay retrievable in memory after its persist failed")
	}
	list := rec.List()
	if len(list) != 2 {
		t.Fatalf("both runs should be in memory, got %d: %v", len(list), list)
	}
}

func TestNewRecorderScrubsLoadedRuns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, runsFileName)
	raw := []RunRecord{{
		ID:        "run-secret",
		Kind:      "playbook",
		StartedAt: time.Now().UTC(),
		ExtraVars: map[string]any{"db_password": "hunter2"},
		Log:       []Event{{Type: "line", Text: "token=abc123"}},
	}}
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	run, ok := rec.Get("run-secret")
	if !ok {
		t.Fatal("loaded run missing")
	}
	if run.ExtraVars["db_password"] != "<REDACTED>" {
		t.Fatalf("memory extraVars not redacted: %#v", run.ExtraVars)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(onDisk), "hunter2") || strings.Contains(string(onDisk), "abc123") {
		t.Fatalf("runs file still contains secret material: %s", onDisk)
	}
}

// TestInsertRunOrderingAndPurity checks insertRun keeps newest-first
// order for an out-of-order record and never mutates its input.
func TestInsertRunOrderingAndPurity(t *testing.T) {
	base := time.Now().UTC()
	runs := []RunRecord{
		{ID: "new", StartedAt: base},
		{ID: "old", StartedAt: base.Add(-time.Hour)},
	}
	mid := RunRecord{ID: "mid", StartedAt: base.Add(-30 * time.Minute)}
	out := insertRun(runs, mid)

	want := []string{"new", "mid", "old"}
	for i, id := range want {
		if out[i].ID != id {
			t.Errorf("out[%d] = %q, want %q", i, out[i].ID, id)
		}
	}
	// Input untouched.
	if len(runs) != 2 || runs[0].ID != "new" || runs[1].ID != "old" {
		t.Errorf("insertRun mutated its input: %v", runs)
	}
}

// TestRecorderListCarriesNoLogs: List is for the run table. One run's
// log is fetched with Get.
func TestRecorderListCarriesNoLogs(t *testing.T) {
	rec, err := NewRecorder(filepath.Join(t.TempDir(), runsFileName))
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"run-a", "run-b"} {
		err := rec.Append(RunRecord{
			ID: id, Kind: "playbook", Playbook: "site.yml",
			StartedAt: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Log:       []Event{{Type: "line", Text: "ok: [web1]"}, {Type: "recap-ok", Host: "web1"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	list := rec.List()
	if len(list) != 2 || list[0].ID != "run-b" || list[1].ID != "run-a" {
		t.Fatalf("List = %v, want run-b then run-a", list)
	}
	for _, r := range list {
		if r.Log != nil {
			t.Errorf("%s: List returned %d log events", r.ID, len(r.Log))
		}
		if r.Playbook != "site.yml" {
			t.Errorf("%s: header fields lost: %+v", r.ID, r)
		}
	}
	// Dropping the log from the copies must not have touched the store.
	got, ok := rec.Get("run-a")
	if !ok || len(got.Log) != 2 || got.Log[0].Text != "ok: [web1]" {
		t.Fatalf("Get after List: ok=%v log=%v", ok, got.Log)
	}
	if _, ok := rec.Get("run-missing"); ok {
		t.Error("Get found a run that does not exist")
	}
}

// TestRecorderServesWhatAppendRedacted pins the invariant List and Get
// now rely on: nothing reaches r.runs unredacted, so nothing needs
// redacting on the way out. Covers both ways in — Append and the load
// at start — with the key names and value shapes that used to survive.
func TestRecorderServesWhatAppendRedacted(t *testing.T) {
	const secret = "SHHH-5555"
	leaky := func(id string) RunRecord {
		return RunRecord{
			ID: id, Kind: "playbook", StartedAt: time.Now().UTC(),
			Command: `$ ansible-playbook x --extra-vars '{"ansible_become_pass":"` + secret + `"}'`,
			Args:    map[string]string{"ansible_ssh_pass": secret},
			ExtraVars: map[string]any{
				"ansible_become_pass": secret,
				"deploy_tokens":       []any{secret, secret},
			},
			Log: []Event{
				{Type: "line", Text: `ansible_sudo_pass: ` + secret},
				{Type: "line", Text: `"api_tokens": ["` + secret + `","` + secret + `"]`},
			},
		}
	}
	served := func(t *testing.T, rec *Recorder, id string) string {
		t.Helper()
		got, ok := rec.Get(id)
		if !ok {
			t.Fatalf("%s not found", id)
		}
		data, err := json.Marshal([]any{got, rec.List()})
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	path := filepath.Join(t.TempDir(), runsFileName)
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(leaky("run-appended")); err != nil {
		t.Fatal(err)
	}
	if out := served(t, rec, "run-appended"); strings.Contains(out, secret) {
		t.Errorf("an appended record is served with the secret in it:\n%s", out)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(onDisk), secret) {
		t.Errorf("runs.json holds the secret:\n%s", onDisk)
	}

	// A history file written before these rules existed: the load at
	// start scrubs it, in memory and on disk.
	old := filepath.Join(t.TempDir(), runsFileName)
	data, err := json.Marshal([]RunRecord{leaky("run-loaded")})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rec2, err := NewRecorder(old)
	if err != nil {
		t.Fatal(err)
	}
	if out := served(t, rec2, "run-loaded"); strings.Contains(out, secret) {
		t.Errorf("a loaded record is served with the secret in it:\n%s", out)
	}
	rewritten, err := os.ReadFile(old)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rewritten), secret) {
		t.Errorf("the old history file was not scrubbed on load:\n%s", rewritten)
	}
}

// TestRecorderListCostDoesNotDependOnLogSize: List used to run the
// redaction pattern over every event of every retained log while
// holding the mutex, about half a second per MiB, with run completion
// and every inventory poll waiting behind it. Twenty runs at the 1 MiB
// log cap took around ten seconds; with nothing to scan it is
// microseconds, so the one-second bound here is far from both.
func TestRecorderListCostDoesNotDependOnLogSize(t *testing.T) {
	line := strings.Repeat("ok: [web1] => {\"changed\": false, \"msg\": \"nothing to see here\"}  ", 16) // ~1 KiB
	log := make([]Event, 1024)                                                                           // ~1 MiB per run
	for i := range log {
		log[i] = Event{Type: "line", Text: line}
	}
	rec := &Recorder{limit: 200, lastPlay: map[string]LastPlay{}}
	for i := 0; i < 20; i++ {
		rec.runs = append(rec.runs, RunRecord{ID: "run-" + strconv.Itoa(i), Kind: "playbook", Log: log})
	}

	// One call each: if the scan ever comes back, this test should
	// fail in seconds, not sit through a hundred of them.
	started := time.Now()
	list := rec.List()
	took := time.Since(started)
	if len(list) != 20 {
		t.Fatalf("List returned %d records", len(list))
	}
	if took > time.Second {
		t.Errorf("List over 20 MiB of retained logs took %s — the logs are being scanned", took)
	}
	// Get of one large record is as cheap, and returns the log intact.
	started = time.Now()
	got, ok := rec.Get("run-7")
	if !ok || len(got.Log) != len(log) {
		t.Fatalf("Get: ok=%v, %d events", ok, len(got.Log))
	}
	if took := time.Since(started); took > time.Second {
		t.Errorf("Get of a 1 MiB record took %s — the log is being scanned", took)
	}
}

// legacyRedactRE is the redaction pattern as it was before command
// lines were rendered from redacted inputs. The migration test below
// uses it to produce exactly what an older ansbui wrote to runs.json.
var legacyRedactRE = regexp.MustCompile(
	`(?i)"?([\w.]*(?:password|passphrase|token|secret|api[_-]?key|apikey|private[_-]?key|credential)[\w.]*)"?\s*[:=]\s*` +
		`("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}\]"\n]+)`)

// TestNewRecorderRepairsLegacyCommandLines is the upgrade path for
// history that is already on disk. An older ansbui saved the executed
// command with the pattern applied to its text; for a secret with a
// single quote in it, or a list of them, that left part of the value
// behind, right after the marker. Scrubbing such a line again cannot
// help — the part the pattern could recognise is already gone — so
// the loader has to deal with it some other way, and the live history
// must not go on serving the remainder after an upgrade.
func TestNewRecorderRepairsLegacyCommandLines(t *testing.T) {
	const (
		tail     = "DUMMY-TAIL-2222"
		listTok  = "LIST-TOKEN-3333"
		passTail = "PASS-TAIL-4444"
	)
	srv := config.Server{WorkDir: "/srv/ansible", Inventory: "hosts.yml"}
	req := PlaybookRequest{
		Path: "site.yml", Limit: "web", Become: true,
		ExtraVars: map[string]any{
			"db_password":         "HEAD'" + tail,
			"deploy_tokens":       []any{listTok + "-a", listTok + "-b"},
			"ansible_become_pass": "HEAD'" + passTail, // not a secret name under the old rules
			"version":             "1.2.3",
		},
	}
	executed, _, err := buildPlaybookCmd(srv, req)
	if err != nil {
		t.Fatal(err)
	}
	legacyLine := "$ " + legacyRedactRE.ReplaceAllString(executed, "${1}: <REDACTED>")
	// This is the stored leak the finding describes; if the old
	// pipeline's output did not contain it, the test would prove nothing.
	for _, leaked := range []string{tail, listTok, passTail} {
		if !strings.Contains(legacyLine, leaked) {
			t.Fatalf("the legacy pipeline's output does not contain %q — fixture is wrong:\n%s", leaked, legacyLine)
		}
	}

	legacy := []map[string]any{{
		"id": "run-legacy", "kind": "playbook", "server": "prod", "playbook": "site.yml",
		"startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T00:00:05Z", "status": "ok",
		"command": legacyLine,
		// The old structured redaction: by the old key list.
		"extraVars": map[string]any{
			"db_password": "<REDACTED>", "deploy_tokens": "<REDACTED>",
			"ansible_become_pass": "HEAD'" + passTail, "version": "1.2.3",
		},
		"limit": "web", "become": true,
		"log": []map[string]any{
			{"type": "meta", "text": legacyLine},
			{"type": "line", "text": "ok: [web1]"},
			{"type": "meta", "text": "run finished"},
		},
	}, {
		// A legacy run with nothing redacted in its command line.
		"id": "run-plain", "kind": "adhoc", "server": "prod", "startedAt": "2025-12-31T00:00:00Z",
		"log": []map[string]any{{"type": "meta", "text": "$ cd '/srv/ansible' && ANSIBLE_FORCE_COLOR=0 ansible 'all' -m 'ansible.builtin.ping' 2>&1"}},
	}}
	path := filepath.Join(t.TempDir(), runsFileName)
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := rec.Get("run-legacy")
	if !ok {
		t.Fatal("legacy run lost on load")
	}
	served, err := json.Marshal([]any{got, rec.List()})
	if err != nil {
		t.Fatal(err)
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{tail, listTok, passTail} {
		if strings.Contains(string(served), leaked) {
			t.Errorf("after the upgrade the history API still serves %q:\n%s", leaked, served)
		}
		if strings.Contains(string(onDisk), leaked) {
			t.Errorf("after the upgrade runs.json still holds %q", leaked)
		}
	}

	// What survives of the line is the part before anything was
	// redacted, and it says that the rest was removed.
	line := got.Log[0].Text
	if !strings.HasPrefix(line, "$ cd '/srv/ansible' && ANSIBLE_FORCE_COLOR=0 ansible-playbook 'site.yml'") {
		t.Errorf("the start of the legacy command line was lost: %s", line)
	}
	if !strings.Contains(line, "<REDACTED>") || !strings.Contains(line, "command line was removed") {
		t.Errorf("the cut is not marked: %s", line)
	}
	if got.Command != line {
		t.Errorf("Command and the log's command line were treated differently:\n%s\n%s", got.Command, line)
	}
	// The other events and the structured inputs are untouched.
	if got.Log[1].Text != "ok: [web1]" || got.Log[2].Text != "run finished" {
		t.Errorf("other events changed: %+v", got.Log)
	}
	if got.Limit != "web" || !got.Become || got.ExtraVars["version"] != "1.2.3" {
		t.Errorf("replay inputs changed: %+v", got)
	}
	// A legacy line with no redaction in it is kept whole.
	plain, _ := rec.Get("run-plain")
	if !strings.HasSuffix(plain.Log[0].Text, "-m 'ansible.builtin.ping' 2>&1") {
		t.Errorf("an unredacted legacy command line was cut: %s", plain.Log[0].Text)
	}

	// Repaired once: loading the repaired file changes nothing.
	if _, err := NewRecorder(path); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, onDisk) {
		t.Errorf("a second load rewrote the history:\nfirst:  %s\nsecond: %s", onDisk, again)
	}
}

// TestRecorderDoesNotCutCurrentCommandLines: the cut is for lines
// produced the old way. A line rendered from redacted inputs has
// markers in the middle and real flags after them, and must come back
// from a restart exactly as it was stored.
func TestRecorderDoesNotCutCurrentCommandLines(t *testing.T) {
	_, preview, err := buildPlaybookCmd(
		config.Server{WorkDir: "/srv/ansible"},
		PlaybookRequest{Path: "site.yml", Check: true, Become: true, ExtraVars: map[string]any{"db_password": "x'y", "version": "1"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	line := "$ " + RedactText(preview)
	path := filepath.Join(t.TempDir(), runsFileName)
	rec, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Append(RunRecord{ID: "run-new", Kind: "playbook", StartedAt: time.Now().UTC(), Log: []Event{{Type: "meta", Text: line}}}); err != nil {
		t.Fatal(err)
	}
	stored, _ := rec.Get("run-new")
	if stored.Redaction != redactionCurrent {
		t.Errorf("Append stamped generation %d, want %d", stored.Redaction, redactionCurrent)
	}
	reloaded, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := reloaded.Get("run-new")
	if got.Log[0].Text != stored.Log[0].Text {
		t.Errorf("a current command line changed across a restart:\nstored:   %s\nreloaded: %s", stored.Log[0].Text, got.Log[0].Text)
	}
	if !strings.Contains(got.Log[0].Text, "--check --become") || strings.Contains(got.Log[0].Text, "command line was removed") {
		t.Errorf("a current command line was cut: %s", got.Log[0].Text)
	}
}
