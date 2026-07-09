package api

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/AlteredParadox/ansbui/internal/ansible"
	"github.com/AlteredParadox/ansbui/internal/jobs"
)

// TestBootstrapRunRecordPersists drives the real wiring main.go
// uses: a bootstrap job finishing → OnFinish → BootstrapRunRecord →
// Recorder.Append, then reads the run back through a fresh Recorder
// on the same file to prove the log survives a "restart".
func TestBootstrapRunRecordPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.json")
	rec, err := ansible.NewRecorder(path)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	m := jobs.New()
	m.OnFinish = func(j *jobs.Job) {
		r, ok := BootstrapRunRecord(j)
		if !ok {
			return
		}
		if err := rec.Append(r); err != nil {
			t.Errorf("Append: %v", err)
		}
	}

	summary := map[string]string{"hostname": "host.example.com", "provider": "hetzner", "server": "ctrl"}
	job, err := m.Start("bootstrap", summary, func(_ context.Context, emit func(string, string)) error {
		emit("meta", "Connecting...")
		emit("fail", "apt install: exit status 100")
		return errors.New("apt install: exit status 100")
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()

	reopened, err := ansible.NewRecorder(path)
	if err != nil {
		t.Fatalf("reopen recorder: %v", err)
	}
	run, ok := reopened.Get(job.ID)
	if !ok {
		t.Fatalf("run %s not found after reopen", job.ID)
	}
	if run.Kind != "bootstrap" || run.Status != "err" {
		t.Fatalf("kind/status = %q/%q, want bootstrap/err", run.Kind, run.Status)
	}
	if run.Target != "host.example.com" || run.Args["provider"] != "hetzner" {
		t.Fatalf("target/args = %q/%v — summary did not round-trip", run.Target, run.Args)
	}
	if len(run.Log) != 2 || run.Log[1].Type != "fail" || run.Log[1].Text != "apt install: exit status 100" {
		t.Fatalf("log = %+v, want the two emitted events", run.Log)
	}
	if run.Failed != 1 || run.OK != 0 {
		t.Fatalf("failed/ok = %d/%d, want 1/0", run.Failed, run.OK)
	}
}

// TestBootstrapRunRecordSynthesizesTerminal covers the cancel path:
// the orchestrator dies mid-emit without a done/fail, so the
// converter must append the verdict line the WS path synthesizes.
func TestBootstrapRunRecordSynthesizesTerminal(t *testing.T) {
	m := jobs.New()
	started := make(chan struct{})
	job, err := m.Start("bootstrap", nil, func(ctx context.Context, emit func(string, string)) error {
		emit("meta", "Rebooting target...")
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-started
	job.Cancel()
	<-job.Done()

	run, ok := BootstrapRunRecord(job)
	if !ok {
		t.Fatal("BootstrapRunRecord returned ok=false for finished bootstrap job")
	}
	if run.Status != "err" {
		t.Fatalf("status = %q, want err", run.Status)
	}
	last := run.Log[len(run.Log)-1]
	if last.Type != "fail" || last.Text != "cancelled" {
		t.Fatalf("last log event = %+v, want synthesized fail/cancelled", last)
	}
}

// TestBootstrapRunRecordSkipsOtherKinds guards the OnFinish hook
// against a future job kind leaking into the ansible run history.
func TestBootstrapRunRecordSkipsOtherKinds(t *testing.T) {
	m := jobs.New()
	job, err := m.Start("some-future-kind", nil, func(_ context.Context, _ func(string, string)) error {
		return nil
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()
	if _, ok := BootstrapRunRecord(job); ok {
		t.Fatal("BootstrapRunRecord accepted a non-bootstrap job")
	}
}
