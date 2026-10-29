// Package testhang bounds helper processes started by tests. The bound only
// catches a real hang: macOS assesses each newly written executable on its
// first exec, queued system-wide, so under full-suite load a healthy helper
// can take far longer than any fixed wall time (BUG-261029-zl7l9q). The bound
// follows the test binary's own -timeout instead, and leaves time for the
// helper's output pipe to drain and for the test to report the hang before
// the test-binary timeout panic. Only tests import this package.
package testhang

import (
	"testing"
	"time"
)

const (
	// NoDeadline bounds a helper when the test binary runs with -timeout 0.
	NoDeadline = 5 * time.Minute
	// MaxReserve is the most time kept back for the test to report a hang.
	MaxReserve = 30 * time.Second
	// MinGuard is the shortest bound worth starting a helper under.
	MinGuard = 100 * time.Millisecond
)

// Guard returns how long a helper may run, given the test binary's deadline
// and the time the caller needs after stopping the helper to drain its pipes.
// It keeps back min(MaxReserve, a quarter of the remaining budget) for
// reporting. ok is false when too little time remains to start a helper.
func Guard(deadline time.Time, hasDeadline bool, now time.Time, drain time.Duration) (time.Duration, bool) {
	if !hasDeadline {
		return NoDeadline, true
	}
	left := deadline.Sub(now) - drain
	reserve := min(MaxReserve, left/4)
	if guard := left - reserve; guard >= MinGuard {
		return guard, true
	}
	return 0, false
}

// For returns the bound for a helper started now by t, failing t at once
// (without starting anything) when its binary has too little time left.
func For(t *testing.T, drain time.Duration) time.Duration {
	t.Helper()
	deadline, hasDeadline := t.Deadline()
	guard, ok := Guard(deadline, hasDeadline, time.Now(), drain)
	if !ok {
		t.Fatalf("testhang: only %s left before the test binary deadline; not starting a helper", time.Until(deadline).Round(time.Millisecond))
	}
	return guard
}
