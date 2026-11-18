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
	cases := []struct {
		name          string
		max           int
		writes        []string
		wantSuffix    string
		wantTruncated bool
	}{
		{
			name:       "under cap keeps everything verbatim",
			max:        16,
			writes:     []string{"hello ", "world"},
			wantSuffix: "hello world",
		},
		{
			name:          "single write over cap keeps the tail",
			max:           8,
			writes:        []string{"0123456789"},
			wantSuffix:    "23456789",
			wantTruncated: true,
		},
		{
			name:          "incremental overflow drops the oldest bytes",
			max:           8,
			writes:        []string{"aaaa", "bbbb", "cccc"},
			wantSuffix:    "bbbbcccc",
			wantTruncated: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertTailBuffer(t, tc.max, tc.writes, tc.wantSuffix, tc.wantTruncated)
		})
	}
}

// assertTailBuffer runs one TestTailBuffer case. Top-level so the
// branching lives outside the subtest closure (S3776).
func assertTailBuffer(t *testing.T, max int, writes []string, wantSuffix string, wantTruncated bool) {
	t.Helper()
	b := &tailBuffer{max: max}
	for _, w := range writes {
		n, err := b.Write([]byte(w))
		if err != nil || n != len(w) {
			t.Fatalf("write %q: n=%d err=%v", w, n, err)
		}
	}
	got := b.String()
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("tail = %q, want suffix %q", got, wantSuffix)
	}
	if b.truncated != wantTruncated {
		t.Fatalf("truncated = %v, want %v", b.truncated, wantTruncated)
	}
	if wantTruncated != strings.Contains(got, "output exceeded") {
		t.Fatalf("truncation notice mismatch: %q", got)
	}
	if len(b.buf) > max {
		t.Fatalf("buffer grew past cap: %d > %d", len(b.buf), max)
	}
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

// outputWasTruncated must recognise exactly what tailBuffer.String()
// emits on overflow — the reinstall netinfo recovery keys off it.
func TestOutputWasTruncated(t *testing.T) {
	t.Parallel()
	b := &tailBuffer{max: 4}
	_, _ = b.Write([]byte("12345678"))
	if !outputWasTruncated(b.String()) {
		t.Fatalf("truncated output not detected: %q", b.String())
	}
	ok := &tailBuffer{max: 64}
	_, _ = ok.Write([]byte("IPv4 Address: 1.2.3.4/24"))
	if outputWasTruncated(ok.String()) {
		t.Fatal("clean output misdetected as truncated")
	}
}
