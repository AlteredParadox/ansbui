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
