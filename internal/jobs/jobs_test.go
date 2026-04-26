package jobs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()
	snap := job.Snapshot()
	if snap.Status != StatusSucceeded {
		t.Fatalf("Status = %q, want %q", snap.Status, StatusSucceeded)
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
		t.Fatalf("Start: %v", err)
	}
	<-started
	job.Cancel()
	select {
	case <-job.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("job didn't honour ctx.Cancel within 2s")
	}
	if snap := job.Snapshot(); snap.Status != StatusCancelled {
		t.Fatalf("Status = %q, want %q", snap.Status, StatusCancelled)
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
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()
	snap := job.Snapshot()
	if snap.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q", snap.Status, StatusFailed)
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
			t.Fatalf("Start #%d: %v", i, err)
		}
	}
	if _, err := m.Start("test", nil, func(_ context.Context, _ func(string, string)) error { return nil }); !errors.Is(err, ErrTooManyRunning) {
		t.Fatalf("Start #3 err = %v, want ErrTooManyRunning", err)
	}
	close(hold)
	// Wait for the two held jobs to drain.
	deadline := time.Now().Add(2 * time.Second)
	for {
		m.mu.Lock()
		count := m.runningCount
		m.mu.Unlock()
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runningCount stuck at %d", count)
		}
		time.Sleep(5 * time.Millisecond)
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
		go func() {
			defer wg.Done()
			for {
				job, err := m.Start("stress", nil, func(ctx context.Context, emit func(string, string)) error {
					emit("meta", "tick")
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(10 * time.Millisecond):
						return nil
					}
				})
				if err == nil {
					started.Add(1)
					starts <- job
					return
				}
				if !errors.Is(err, ErrTooManyRunning) {
					t.Errorf("unexpected Start err: %v", err)
					return
				}
				time.Sleep(time.Millisecond)
			}
		}()
	}
	// Subscribe + cancel a slice of jobs concurrently with the
	// starters.
	go func() {
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
	}()
	wg.Wait()
	close(starts)
	// Wait for everyone to finish so the race detector sees the
	// lifecycle in full.
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		count := m.runningCount
		m.mu.Unlock()
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("runningCount stuck at %d after stress", count)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if started.Load() == 0 {
		t.Fatalf("no jobs started — cap or wait logic is wrong")
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
		t.Fatalf("Start: %v", err)
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
