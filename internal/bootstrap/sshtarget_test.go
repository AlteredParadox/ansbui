package bootstrap

import (
	"context"
	"strings"
	"testing"
	"time"
)

// tailBuffer is the memory bound for target command output: it must
// keep the most recent bytes (tails feed parseReinstallNetInfo and
// the failure-detail helpers), flag truncation, and never grow past
// its cap.
func TestTailBuffer(t *testing.T) {
	t.Parallel()

	t.Run("under cap keeps everything verbatim", func(t *testing.T) {
		b := &tailBuffer{max: 16}
		if _, err := b.Write([]byte("hello ")); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Write([]byte("world")); err != nil {
			t.Fatal(err)
		}
		if got := b.String(); got != "hello world" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("overflow keeps the tail and flags truncation", func(t *testing.T) {
		b := &tailBuffer{max: 8}
		_, _ = b.Write([]byte("0123456789")) // single write over cap
		if !b.truncated {
			t.Fatal("expected truncated flag")
		}
		if !strings.HasSuffix(b.String(), "23456789") {
			t.Fatalf("tail not kept: %q", b.String())
		}
		if !strings.Contains(b.String(), "output exceeded") {
			t.Fatalf("missing truncation notice: %q", b.String())
		}
	})

	t.Run("incremental overflow drops the oldest bytes", func(t *testing.T) {
		b := &tailBuffer{max: 8}
		for _, chunk := range []string{"aaaa", "bbbb", "cccc"} {
			if n, err := b.Write([]byte(chunk)); err != nil || n != 4 {
				t.Fatalf("write: n=%d err=%v", n, err)
			}
		}
		if !strings.HasSuffix(b.String(), "bbbbcccc") {
			t.Fatalf("expected last 8 bytes, got %q", b.String())
		}
		if len(b.buf) > 8 {
			t.Fatalf("buffer grew past cap: %d", len(b.buf))
		}
	})
}

// stepContext must impose the default step deadline ONLY when the
// caller didn't budget the step itself — reinstall prep's 15-minute
// budget has to survive.
func TestStepContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := stepContext(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected a default deadline on an unbudgeted ctx")
	}
	if until := time.Until(dl); until > defaultStepTimeout || until < defaultStepTimeout-time.Minute {
		t.Fatalf("default deadline %s away, want ~%s", until, defaultStepTimeout)
	}

	parentDL := time.Now().Add(15 * time.Minute)
	parent, parentCancel := context.WithDeadline(context.Background(), parentDL)
	defer parentCancel()
	ctx2, cancel2 := stepContext(parent)
	defer cancel2()
	got, ok := ctx2.Deadline()
	if !ok || !got.Equal(parentDL) {
		t.Fatalf("caller-budgeted deadline not preserved: got %v ok=%v want %v", got, ok, parentDL)
	}
}
