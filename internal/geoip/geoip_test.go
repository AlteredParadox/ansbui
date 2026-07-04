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
