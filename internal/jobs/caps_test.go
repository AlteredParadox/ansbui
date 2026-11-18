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
	"strings"
	"testing"
	"unicode/utf8"
)

// Tests for the per-job retention caps. Event text comes from the
// machine being bootstrapped as much as from ansbui, so one job must
// not be able to keep more than a fixed amount of it.

func runJob(t *testing.T, fn Func) *Job {
	t.Helper()
	job, err := New().Start("bootstrap", nil, fn)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	<-job.Done()
	return job
}

func totalText(events []Event) int {
	n := 0
	for _, e := range events {
		n += len(e.Text)
	}
	return n
}

func TestEmitClipsOneOversizedEvent(t *testing.T) {
	huge := "HEAD-" + strings.Repeat("x", 2<<20) + "-TAIL"
	job := runJob(t, func(_ context.Context, emit func(string, string)) error {
		emit("ok", huge)
		emit("ok", "small")
		return nil
	})
	events := job.Events()
	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
	got := events[0].Text
	if len(got) > maxEventText+64 {
		t.Fatalf("event kept %d bytes, cap is %d", len(got), maxEventText)
	}
	if !strings.HasPrefix(got, "HEAD-") || !strings.HasSuffix(got, "-TAIL") {
		t.Fatalf("clipped event lost its head or tail: %.20q … %q", got, got[len(got)-20:])
	}
	if !strings.Contains(got, "bytes omitted") {
		t.Fatal("clipped event does not say that text was removed")
	}
	if events[1].Text != "small" {
		t.Fatalf("a short event was changed: %q", events[1].Text)
	}
}

func TestClipMiddleKeepsValidUTF8(t *testing.T) {
	s := strings.Repeat("é", 4000) // two bytes each; an odd cut lands mid-rune
	got := clipMiddle(s, 1001)
	if !utf8.ValidString(got) {
		t.Fatal("clipMiddle produced invalid UTF-8")
	}
	if clipMiddle("short", 1001) != "short" {
		t.Fatal("clipMiddle changed a string under the cap")
	}
}

func TestEmitStopsAtByteBudgetAndKeepsVerdict(t *testing.T) {
	line := strings.Repeat("y", 8<<10)
	job := runJob(t, func(_ context.Context, emit func(string, string)) error {
		for range 1000 { // 8 MiB offered
			emit("meta", line)
		}
		emit("fail", "apt install: exit status 100")
		return errors.New("apt install: exit status 100")
	})
	events := job.Events()
	if n := totalText(events); n > maxJobBytes+1024 {
		t.Fatalf("job kept %d bytes of event text, cap is %d", n, maxJobBytes)
	}
	markers := 0
	for _, e := range events {
		if strings.Contains(e.Text, "job log truncated") {
			markers++
		}
	}
	if markers != 1 {
		t.Fatalf("want exactly one truncation marker, got %d", markers)
	}
	last := events[len(events)-1]
	if last.Type != "fail" || last.Text != "apt install: exit status 100" {
		t.Fatalf("log does not end with the job's own verdict: %+v", last)
	}
	for i, e := range events {
		if e.Seq != i+1 {
			t.Fatalf("event %d has seq %d; sequence numbers must stay gapless", i, e.Seq)
		}
	}
}

func TestEmitStopsAtEventCount(t *testing.T) {
	job := runJob(t, func(_ context.Context, emit func(string, string)) error {
		for range maxJobEvents * 3 {
			emit("meta", "tick")
		}
		for range maxLateVerdicts * 3 { // a verdict flood is bounded too
			emit("fail", "boom")
		}
		return errors.New("boom")
	})
	events := job.Events()
	if want := maxJobEvents + 1 + maxLateVerdicts; len(events) != want {
		t.Fatalf("job kept %d events, want %d (cap + marker + late verdicts)", len(events), want)
	}
	if got := job.Snapshot().EventCount; got != len(events) {
		t.Fatalf("snapshot counts %d events, log has %d", got, len(events))
	}
}

func TestFinishClipsErrorString(t *testing.T) {
	job := runJob(t, func(_ context.Context, _ func(string, string)) error {
		return errors.New("unsupported distro " + strings.Repeat("z", 2<<20))
	})
	snap := job.Snapshot()
	if snap.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", snap.Status)
	}
	if len(snap.Error) > maxJobError+64 {
		t.Fatalf("snapshot error is %d bytes, cap is %d", len(snap.Error), maxJobError)
	}
	if !strings.HasPrefix(snap.Error, "unsupported distro ") {
		t.Fatalf("clipped error lost its head: %.40q", snap.Error)
	}
}
