package ansible

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
