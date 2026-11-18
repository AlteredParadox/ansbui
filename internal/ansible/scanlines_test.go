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

package ansible

import (
	"context"
	"io"
	"strings"
	"testing"
)

// collectScanEvents runs scanLines over the given writes and returns
// every event it emitted plus the first write error. A write error
// is a legitimate outcome: when the scanner aborts, scanLines fails
// the pipe's read end precisely so blocked writers return instead of
// wedging — callers assert on it where that's the expected path.
func collectScanEvents(t *testing.T, writes ...string) ([]Event, error) {
	t.Helper()
	pr, pw := io.Pipe()
	out := make(chan Event, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanLines(context.Background(), pr, "stdout", out)
	}()
	var writeErr error
	for _, w := range writes {
		if _, err := pw.Write([]byte(w)); err != nil {
			writeErr = err
			break
		}
	}
	_ = pw.Close()
	<-done
	close(out)
	var events []Event
	for evt := range out {
		events = append(events, evt)
	}
	return events, writeErr
}

// A line longer than maxLiveLineBytes (but under maxScanLine) must
// be truncated BEFORE it enters the events channel — that cap is
// what bounds live buffering against a slow WebSocket peer — and
// must not abort the stream.
func TestScanLines_TruncatesLongLiveLines(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", maxLiveLineBytes+1000)
	events, writeErr := collectScanEvents(t, long+"\n", "ok: [host1]\n")

	if writeErr != nil {
		t.Fatalf("pipe write should succeed under maxScanLine: %v", writeErr)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	first := events[0]
	if !strings.HasSuffix(first.Text, "… [line truncated]") {
		t.Fatalf("long line not marked truncated (len=%d)", len(first.Text))
	}
	if len(first.Text) > maxLiveLineBytes+len("… [line truncated]") {
		t.Fatalf("event text exceeds live cap: %d bytes", len(first.Text))
	}
	if first.Type == "error" {
		t.Fatalf("truncation must not be an error event: %+v", first)
	}
	// The stream keeps going after a truncated line.
	if events[1].Type != "ok" || events[1].Host != "host1" {
		t.Fatalf("classification lost after truncation: %+v", events[1])
	}
}

// A line over maxScanLine still aborts the stream with an explicit
// error event (and a closed pipe) rather than wedging the run —
// regression cover for the Scanner.Err() handling.
func TestScanLines_OverScannerLimitEmitsError(t *testing.T) {
	t.Parallel()
	huge := strings.Repeat("y", maxScanLine+10)
	events, writeErr := collectScanEvents(t, huge+"\n")

	// The blocked writer must be released WITH the scanner's error —
	// that's the guarantee that stops the SSH session from wedging.
	if writeErr == nil || !strings.Contains(writeErr.Error(), "token too long") {
		t.Fatalf("writer not failed with the scan error, got: %v", writeErr)
	}
	if len(events) == 0 {
		t.Fatal("expected an error event")
	}
	last := events[len(events)-1]
	if last.Type != "error" || !strings.Contains(last.Text, "stream aborted") {
		t.Fatalf("expected stream-aborted error event, got %+v", last)
	}
}
