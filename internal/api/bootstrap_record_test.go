package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	assertPersistedBootstrapRun(t, run)
}

// assertPersistedBootstrapRun checks the reloaded record against the
// events TestBootstrapRunRecordPersists emitted. Split out to keep
// the test body under the cognitive-complexity ceiling (S3776).
func assertPersistedBootstrapRun(t *testing.T, run ansible.RunRecord) {
	t.Helper()
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
	// The synthesized verdict is a failure like any other: History
	// shows the Failed count next to the status.
	if run.Failed != 1 || run.OK != 0 {
		t.Fatalf("ok/failed = %d/%d, want 0/1 (the synthesized fail must be counted)", run.OK, run.Failed)
	}
}

// TestBootstrapRunRecordCountsVerdictOnce covers the ways a job can
// end and what the summary counts for each: a verdict the converter
// had to synthesize counts once, and one the job emitted itself is
// not counted a second time.
func TestBootstrapRunRecordCountsVerdictOnce(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fn         jobs.Func
		wantStatus string
		wantOK     int
		wantFailed int
		wantLast   ansible.Event
	}{
		{
			name: "error returned without a fail event",
			fn: func(_ context.Context, emit func(string, string)) error {
				emit("ok", "connected.")
				return errors.New("inventory edit: exit status 1")
			},
			wantStatus: "err", wantOK: 1, wantFailed: 1,
			wantLast: ansible.Event{Type: "fail", Text: "inventory edit: exit status 1"},
		},
		{
			name: "panic",
			fn: func(_ context.Context, emit func(string, string)) error {
				emit("ok", "connected.")
				panic("boom")
			},
			wantStatus: "err", wantOK: 1, wantFailed: 1,
			wantLast: ansible.Event{Type: "fail", Text: "orchestrator panic — check server log for details"},
		},
		{
			name: "fail event emitted by the job",
			fn: func(_ context.Context, emit func(string, string)) error {
				emit("ok", "connected.")
				emit("fail", "apt install: exit status 100")
				return errors.New("apt install: exit status 100")
			},
			wantStatus: "err", wantOK: 1, wantFailed: 1,
			wantLast: ansible.Event{Type: "fail", Text: "apt install: exit status 100"},
		},
		{
			name: "success without a done event",
			fn: func(_ context.Context, emit func(string, string)) error {
				emit("ok", "connected.")
				return nil
			},
			wantStatus: "ok", wantOK: 1, wantFailed: 0,
			wantLast: ansible.Event{Type: "done", Text: "complete"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			job, err := jobs.New().Start("bootstrap", nil, tc.fn)
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			<-job.Done()
			run, ok := BootstrapRunRecord(job)
			if !ok {
				t.Fatal("BootstrapRunRecord returned ok=false")
			}
			if run.Status != tc.wantStatus || run.OK != tc.wantOK || run.Failed != tc.wantFailed {
				t.Fatalf("status/ok/failed = %s/%d/%d, want %s/%d/%d", run.Status, run.OK, run.Failed, tc.wantStatus, tc.wantOK, tc.wantFailed)
			}
			if last := run.Log[len(run.Log)-1]; last.Type != tc.wantLast.Type || last.Text != tc.wantLast.Text {
				t.Fatalf("last log event = %+v, want %+v", last, tc.wantLast)
			}
		})
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

// A bootstrap record obeys the same history caps as an ad-hoc or
// playbook run. Before, BootstrapRunRecord copied every job event into
// runs.json at whatever size the target's output gave it.
func TestBootstrapRunRecordObeysHistoryCaps(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runs.json")
	rec, err := ansible.NewRecorder(path)
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	m := jobs.New()
	m.OnFinish = func(j *jobs.Job) {
		if r, ok := BootstrapRunRecord(j); ok {
			if err := rec.Append(r); err != nil {
				t.Errorf("Append: %v", err)
			}
		}
	}
	const verdict = "unsupported distro — v1 only handles debian/ubuntu"
	big := strings.Repeat("A", 2<<20)
	job, err := m.Start("bootstrap", map[string]string{"hostname": "host.example.com"}, func(_ context.Context, emit func(string, string)) error {
		for range 6 {
			emit("ok", "distro: "+big)
		}
		for range 200 {
			emit("meta", strings.Repeat("B", 12<<10))
		}
		emit("fail", verdict)
		return errors.New(verdict + " " + big)
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()

	run, ok := rec.Get(job.ID)
	if !ok {
		t.Fatalf("run %s not recorded", job.ID)
	}
	total := 0
	for _, e := range run.Log {
		total += len(e.Text)
	}
	if total > maxLogBytes+4096 {
		t.Fatalf("record keeps %d bytes of log text, history cap is %d", total, maxLogBytes)
	}
	if len(run.Log) > maxLogEvents+2 {
		t.Fatalf("record keeps %d events, history cap is %d", len(run.Log), maxLogEvents)
	}
	if last := run.Log[len(run.Log)-1]; last.Type != "fail" || last.Text != verdict {
		t.Fatalf("record does not end with the job's verdict: %+v", last)
	}
	if run.Status != "err" || run.Failed != 1 || run.OK != 6 {
		t.Fatalf("status/ok/failed = %s/%d/%d, want err/6/1", run.Status, run.OK, run.Failed)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat runs.json: %v", err)
	}
	if info.Size() > 2<<20 {
		t.Fatalf("runs.json is %d bytes after one capped bootstrap record", info.Size())
	}
}

// cappedHistory keeps the closing verdict after the truncation marker
// and leaves a log under the caps untouched.
func TestCappedHistory(t *testing.T) {
	small := []ansible.Event{{Type: "meta", Text: "Connecting..."}, {Type: "done", Text: "complete"}}
	if got := cappedHistory(small); len(got) != 2 || got[1].Text != "complete" {
		t.Fatalf("a log under the caps was changed: %+v", got)
	}

	var long []ansible.Event
	for range maxLogEvents + 500 {
		long = append(long, ansible.Event{Type: "meta", Text: "tick"})
	}
	long = append(long, ansible.Event{Type: "fail", Text: "boom"})
	got := cappedHistory(long)
	if len(got) != maxLogEvents+2 {
		t.Fatalf("got %d events, want cap + marker + verdict = %d", len(got), maxLogEvents+2)
	}
	if !strings.Contains(got[maxLogEvents].Text, "history log truncated") {
		t.Fatalf("no truncation marker at the cap: %+v", got[maxLogEvents])
	}
	if last := got[len(got)-1]; last.Type != "fail" || last.Text != "boom" {
		t.Fatalf("verdict not kept after the marker: %+v", last)
	}

	// No verdict to keep: the marker is the end.
	noVerdict := cappedHistory(long[:len(long)-1])
	if len(noVerdict) != maxLogEvents+1 {
		t.Fatalf("got %d events without a verdict, want %d", len(noVerdict), maxLogEvents+1)
	}
}
