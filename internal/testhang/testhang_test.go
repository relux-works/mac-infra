package testhang

import (
	"testing"
	"time"
)

// Claim: the guard follows the binary deadline, never outlives it (drain and reserve included), and refuses when time is short.
func TestGuardFollowsTestDeadline(t *testing.T) {
	now := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name        string
		left, drain time.Duration
		hasDeadline bool
		want        time.Duration
		ok          bool
	}{
		{"go test default 10m", 10 * time.Minute, 2 * time.Second, true, 10*time.Minute - 2*time.Second - 30*time.Second, true},
		{"custom 60s, reserve is a quarter", 60 * time.Second, 0, true, 45 * time.Second, true},
		{"3s left, as in the review probe", 3 * time.Second, 0, true, 2250 * time.Millisecond, true},
		{"3s left with a 2s drain", 3 * time.Second, 2 * time.Second, true, 750 * time.Millisecond, true},
		{"drain uses up the budget", 2 * time.Second, 2 * time.Second, true, 0, false},
		{"already past the deadline", -time.Second, 0, true, 0, false},
		{"no deadline (-timeout 0)", 0, 2 * time.Second, false, NoDeadline, true},
	} {
		got, ok := Guard(now.Add(c.left), c.hasDeadline, now, c.drain)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: Guard = %s, %v; want %s, %v", c.name, got, ok, c.want, c.ok)
		}
		if c.hasDeadline && ok && got+c.drain >= c.left {
			t.Errorf("%s: guard %s plus drain %s does not end before the deadline %s", c.name, got, c.drain, c.left)
		}
	}
}
