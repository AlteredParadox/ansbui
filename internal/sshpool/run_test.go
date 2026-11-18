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

package sshpool

import (
	"context"
	"strings"
	"testing"
	"time"
)

// cappedBuffer must fail the write once the cap is exceeded — that
// error is what aborts the SSH copy loop and tears the command down.
func TestCappedBuffer(t *testing.T) {
	t.Parallel()
	b := &cappedBuffer{name: "stdout", max: 8}
	if _, err := b.Write([]byte("12345678")); err != nil {
		t.Fatalf("write at cap should succeed: %v", err)
	}
	if _, err := b.Write([]byte("9")); err == nil {
		t.Fatal("write past cap must error")
	} else if !strings.Contains(err.Error(), "stdout exceeded 8 bytes") {
		t.Fatalf("unhelpful cap error: %v", err)
	}
	if got := b.buf.String(); got != "12345678" {
		t.Fatalf("buffer corrupted by rejected write: %q", got)
	}
}

// When every runSem slot is taken, Run must give up when the
// caller's context does — queued callers are bounded, not parked
// forever. The nil client is safe because a saturated semaphore
// fails the call before any SSH use.
func TestRun_SemaphoreSaturationHonorsContext(t *testing.T) {
	// NOT t.Parallel(): the test drains a package-global semaphore.
	for range cap(runSem) {
		runSem <- struct{}{}
	}
	defer func() {
		for range cap(runSem) {
			<-runSem
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := Run(ctx, nil, "true")
	if err == nil {
		t.Fatal("expected an error while the semaphore is saturated")
	}
	if !strings.Contains(err.Error(), "waiting for an SSH query slot") {
		t.Fatalf("expected slot-wait error, got: %v", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("Run blocked %s past its context deadline", waited)
	}
}

// RunStdin must honour ctx while waiting on the shared session
// semaphore, and must not touch the SSH client before it holds a
// slot. A nil client proves the point: if acquisition were
// unconditional, the call would panic dereferencing it instead of
// returning the queue error.
func TestRunStdinRespectsCancelledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() {
		_, _, err := RunStdin(ctx, nil, "echo hi", strings.NewReader("in"))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled context should not have run the command")
		}
		if !strings.Contains(err.Error(), "SSH query slot") {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunStdin ignored the cancelled context")
	}
}

// The semaphore must be released on every path, including the error
// ones, or a handful of failed calls would wedge the pool for good.
func TestRunStdinReleasesSlotOnError(t *testing.T) {
	for i := 0; i < cap(runSem)+2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _, _ = RunStdin(ctx, nil, "echo hi", nil)
	}
	if len(runSem) != 0 {
		t.Fatalf("runSem still holds %d slots after failed calls", len(runSem))
	}
}
