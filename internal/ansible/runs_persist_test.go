package ansible

import (
	"path/filepath"
	"testing"
	"time"
)

const runsFileName = "runs.json"

// TestAppendPersistFailureNoDivergence: when the durable write fails,
// Append must return the error AND leave the in-memory list unchanged
// — otherwise List() shows a run that was never saved, and it
// vanishes on the next restart. We force the failure by pointing the
// recorder's path at a location whose parent is a regular file, so
// the tempfile create fails.
func TestAppendPersistFailureNoDivergence(t *testing.T) {
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
	if err := rec.Append(bad); err == nil {
		t.Fatal("expected Append to fail when the write path is broken")
	}

	list := rec.List()
	if len(list) != 1 || list[0].ID != "run-1" {
		t.Fatalf("in-memory state diverged from disk: got %d records %v, want only run-1", len(list), list)
	}
	if _, ok := rec.Get("run-2"); ok {
		t.Error("run-2 should not be retrievable after its persist failed")
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
