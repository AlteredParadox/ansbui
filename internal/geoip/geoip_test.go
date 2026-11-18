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

package geoip

import (
	"context"
	"fmt"
	"testing"
)

func TestEntryTTLClassification(t *testing.T) {
	c := NewClient()
	permanent := []error{
		nil,
		errBogon,
		statusError(404),
		statusError(400),
	}
	for _, err := range permanent {
		if got := c.entryTTL(err); got != c.ttl {
			t.Errorf("entryTTL(%v) = %v, want full ttl %v", err, got, c.ttl)
		}
	}
	transient := []error{
		context.Canceled,
		context.DeadlineExceeded,
		fmt.Errorf("ipinfo: %w", context.Canceled),
		fmt.Errorf("ipinfo: connection refused"),
		statusError(429),
		statusError(500),
		statusError(408),
	}
	for _, err := range transient {
		if got := c.entryTTL(err); got != transientErrTTL {
			t.Errorf("entryTTL(%v) = %v, want transient ttl %v", err, got, transientErrTTL)
		}
	}
}
