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

package jobs

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Shared error-message templates so a single test-helper rename
// doesn't fan out to ~10 sites (S1192).
const (
	startErr        = "Start: %v"
	statusMismatch  = "Status = %q, want %q"
	startErrIndexed = "Start #%d: %v"
)

// TestManagerLifecycle exercises the basic happy path: a job
// transitions running → succeeded, the events log captures emits,
// and Subscribe replays the backlog after the job finished.
func TestManagerLifecycle(t *testing.T) {
	m := New()
	job, err := m.Start("test", nil, func(_ context.Context, emit func(string, string)) error {
		emit("meta", "starting")
		emit("ok", "done")
		return nil
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	<-job.Done()
	snap := job.Snapshot()
	if snap.Status != StatusSucceeded {
		t.Fatalf(statusMismatch, snap.Status, StatusSucceeded)
	}
	if snap.EventCount != 2 {
		t.Fatalf("EventCount = %d, want 2", snap.EventCount)
	}
	backlog, ch, unsub := job.Subscribe()
	defer unsub()
	if len(backlog) != 2 {
		t.Fatalf("backlog len = %d, want 2", len(backlog))
	}
	// chan should be already closed for finished jobs.
	if _, ok := <-ch; ok {
		t.Fatalf("expected channel closed for finished job")
	}
}

// TestManagerCancel verifies a cancelled job ends as StatusCancelled
// and the orchestrator's ctx-cancel propagates promptly.
func TestManagerCancel(t *testing.T) {
	m := New()
	started := make(chan struct{})
	job, err := m.Start("test", nil, func(ctx context.Context, _ func(string, string)) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	<-started
	job.Cancel()
	select {
	case <-job.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("job didn't honour ctx.Cancel within 2s")
	}
	if snap := job.Snapshot(); snap.Status != StatusCancelled {
		t.Fatalf(statusMismatch, snap.Status, StatusCancelled)
	}
}

// TestManagerPanicRecovery verifies an orchestrator panic is
// captured as a regular failed status and doesn't crash the
// process / corrupt the cap accounting.
func TestManagerPanicRecovery(t *testing.T) {
	m := New()
	job, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error {
		panic("oops")
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	<-job.Done()
	snap := job.Snapshot()
	if snap.Status != StatusFailed {
		t.Fatalf(statusMismatch, snap.Status, StatusFailed)
	}
	// Cap accounting must still be honest after the recovery.
	for i := 0; i < defaultMaxRunning; i++ {
		_, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error { return nil })
		if err != nil {
			t.Fatalf("Start #%d after panic: %v", i, err)
		}
	}
}

// TestManagerCapAccounting verifies the running-cap kicks in at
// MaxRunning and recovers as jobs finish.
func TestManagerCapAccounting(t *testing.T) {
	m := New()
	m.maxRunning = 2
	hold := make(chan struct{})
	for i := 0; i < 2; i++ {
		_, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error {
			<-hold
			return nil
		})
		if err != nil {
			t.Fatalf(startErrIndexed, i, err)
		}
	}
	if _, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error { return nil }); !errors.Is(err, ErrTooManyRunning) {
		t.Fatalf("Start #3 err = %v, want ErrTooManyRunning", err)
	}
	close(hold)
	if err := waitRunningCount(m, 0, 2*time.Second); err != "" {
		t.Fatal(err)
	}
	if _, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error { return nil }); err != nil {
		t.Fatalf("Start after drain: %v", err)
	}
}

// TestManagerConcurrentStartCancel hits Start / Cancel / Subscribe
// in parallel under the race detector. The expected outcome is "no
// race, no panic, no goroutine leak"; we don't assert specific
// per-job outcomes because many jobs race their Cancel against
// natural completion.
func TestManagerConcurrentStartCancel(t *testing.T) {
	m := New()
	m.maxRunning = 32 // loose cap for the burst
	const N = 200
	var started atomic.Int64
	var wg sync.WaitGroup
	starts := make(chan *Job, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go burstStarter(t, m, &started, starts, &wg)
	}
	go drainStarts(starts)
	wg.Wait()
	close(starts)
	if err := waitRunningCount(m, 0, 5*time.Second); err != "" {
		t.Fatalf("after stress: %s", err)
	}
	if started.Load() == 0 {
		t.Fatalf("no jobs started — cap or wait logic is wrong")
	}
}

// burstStarter loops on Start until it gets a slot (the manager is
// at maxRunning during the burst). Reports an error and bails on
// any error other than ErrTooManyRunning.
func burstStarter(t *testing.T, m *Manager, started *atomic.Int64, out chan<- *Job, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		job, err := m.Start("stress", nil, stressFn)
		if err == nil {
			started.Add(1)
			out <- job
			return
		}
		if !errors.Is(err, ErrTooManyRunning) {
			t.Errorf("unexpected Start err: %v", err)
			return
		}
		time.Sleep(time.Millisecond)
	}
}

// stressFn is the per-job orchestrator body for the concurrent
// stress test: emit one event then either honour ctx.Done or
// finish naturally after 10ms.
func stressFn(ctx context.Context, emit func(string, string)) error {
	emit("meta", "tick")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Millisecond):
		return nil
	}
}

// drainStarts pulls each newly-started job off the channel and
// sometimes cancels / subscribes to it, exercising the
// concurrent-mutation paths Subscribe / Cancel race against the
// natural lifecycle.
func drainStarts(starts <-chan *Job) {
	count := 0
	for j := range starts {
		count++
		if count%3 == 0 {
			j.Cancel()
		}
		if count%5 == 0 {
			_, _, unsub := j.Subscribe()
			unsub()
		}
	}
}

// waitRunningCount polls m.runningCount until it hits target or
// the deadline expires. Returns "" on success, or a short reason
// string. Inlined polling kept the original test over Sonar's
// complexity ceiling; pulling it out here reuses across cap and
// stress tests.
func waitRunningCount(m *Manager, target int, within time.Duration) string {
	deadline := time.Now().Add(within)
	for {
		m.mu.Lock()
		count := m.runningCount
		m.mu.Unlock()
		if count == target {
			return ""
		}
		if time.Now().After(deadline) {
			return fmt.Sprintf("runningCount stuck at %d (want %d)", count, target)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestManagerSubscribeRace exercises Subscribe / emit / unsub
// concurrently while a job is producing events. The race detector
// catches any unsynchronised access to j.events / j.waiters.
func TestManagerSubscribeRace(t *testing.T) {
	m := New()
	job, err := m.Start("subrace", nil, func(ctx context.Context, emit func(string, string)) error {
		for i := 0; i < 500; i++ {
			emit("meta", "x")
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 50; k++ {
				_, ch, unsub := job.Subscribe()
				// Drain a few then unsubscribe.
				for j := 0; j < 3; j++ {
					select {
					case <-ch:
					case <-time.After(2 * time.Millisecond):
					}
				}
				unsub()
			}
		}()
	}
	wg.Wait()
	<-job.Done()
}

// TestFinishSuccessBeatsLateCancel: a job whose orchestrator returned
// nil must end Succeeded even if Cancel() raced in just before the
// return — the work actually completed, and mislabeling a
// bootstrapped box as "cancelled" misleads the operator.
func TestFinishSuccessBeatsLateCancel(t *testing.T) {
	m := New()
	release := make(chan struct{})
	job, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error {
		<-release // hold until we've cancelled, then succeed anyway
		return nil
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	job.Cancel()   // ctx is now cancelled
	close(release) // fn returns nil despite the cancel
	<-job.Done()
	if got := job.Snapshot().Status; got != StatusSucceeded {
		t.Fatalf(statusMismatch, got, StatusSucceeded)
	}
}

// TestShutdownRefusesNewJobs: once Shutdown has latched, Start must
// refuse — otherwise a job born after Shutdown's snapshot runs on an
// uncancelled background context and outlives the process.
func TestShutdownRefusesNewJobs(t *testing.T) {
	m := New()
	m.Shutdown(context.Background()) // no running jobs; latches the flag
	_, err := m.Start("test", nil, func(context.Context, func(string, string)) error { return nil })
	if !errors.Is(err, ErrShuttingDown) {
		t.Fatalf("Start after Shutdown = %v, want ErrShuttingDown", err)
	}
}

// TestShutdownCancelsInFlight: a running job is cancelled and awaited
// by Shutdown.
func TestShutdownCancelsInFlight(t *testing.T) {
	m := New()
	started := make(chan struct{})
	job, err := m.Start("test", nil, func(ctx context.Context, _ func(string, string)) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	<-started
	m.Shutdown(context.Background())
	if got := job.Snapshot().Status; got != StatusCancelled {
		t.Fatalf(statusMismatch, got, StatusCancelled)
	}
}

// TestOnFinishHook verifies the hook fires after the terminal state
// is recorded (Snapshot/Events are complete inside it) and that a
// panicking hook is contained — the running-count slot still frees,
// so a persistence bug can't wedge the cap.
func TestOnFinishHook(t *testing.T) {
	m := New()
	var got atomic.Pointer[Snapshot]
	m.OnFinish = func(j *Job) {
		snap := j.Snapshot()
		got.Store(&snap)
		panic("hook bug")
	}
	job, err := m.Start("bootstrap", nil, func(_ context.Context, emit func(string, string)) error {
		emit("ok", "step 1")
		return nil
	})
	if err != nil {
		t.Fatalf(startErr, err)
	}
	<-job.Done()
	snap := got.Load()
	if snap == nil {
		t.Fatal("OnFinish was not called")
	}
	if snap.Status != StatusSucceeded {
		t.Fatalf(statusMismatch, snap.Status, StatusSucceeded)
	}
	if snap.EventCount != 1 {
		t.Fatalf("EventCount inside hook = %d, want 1", snap.EventCount)
	}
	// Slot accounting must survive the hook panic.
	for i := 0; i < defaultMaxRunning; i++ {
		if _, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error { return nil }); err != nil {
			t.Fatalf("Start #%d after hook panic: %v", i, err)
		}
	}
}
