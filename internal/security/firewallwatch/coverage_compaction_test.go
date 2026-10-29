package firewallwatch

import (
	"fmt"
	"testing"
	"time"
)

// Pending compaction preserves storm accounting without truncating later clean coverage, even after delayed reports.
func TestDeltaCleanAfterPendingCompaction(t *testing.T) {
	for _, limit := range []int{4, 10000} {
		for _, late := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/late=%t", limit, late), func(t *testing.T) {
				c := testConfig(t)
				c.MaxEntries = limit
				s, err := OpenStore(c)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now().Add(-48 * time.Hour).Truncate(time.Second)
				stormEnd := start.Add(time.Duration(limit+1)*time.Second + 20*time.Millisecond)
				s.BeginCoverage(start)
				if late {
					// Model a save snapshot that preceded the feeder's reports.
					if err := s.Save(stormEnd.Add(time.Millisecond)); err != nil {
						t.Fatal(err)
					}
				}
				for i := 1; i <= limit+1; i++ {
					at := start.Add(time.Duration(i) * time.Second)
					s.StallCoverage(at)
					s.ResumeCoverage(at.Add(20 * time.Millisecond))
				}
				for _, elapsed := range []time.Duration{4 * time.Hour, 47 * time.Hour} {
					if err := s.Save(start.Add(elapsed)); err != nil {
						t.Fatal(err)
					}
				}
				loaded, err := OpenStore(c)
				if err != nil {
					t.Fatal(err)
				}
				for _, since := range []time.Time{stormEnd, start.Add(46 * time.Hour)} {
					w := loaded.Split(since, start.Add(47*time.Hour)).Window
					if w.Truncated || w.CoalescedShortStalls != (CoalescedShortStalls{}) || len(w.CoverageGaps) != 0 {
						t.Fatalf("clean window inherited historical counters: %+v; spans=%+v", w, loaded.State.Coverage)
					}
				}
				storm := loaded.Split(start, stormEnd).Window
				want := CoalescedShortStalls{Count: uint64(limit + 1), StalledNS: int64(limit+1) * int64(20*time.Millisecond)}
				if !storm.Truncated || len(storm.CoverageGaps) != 0 || storm.CoalescedShortStalls != want {
					t.Fatalf("storm hidden or miscounted: %+v; want %+v", storm, want)
				}
				if len(loaded.State.Coverage) > limit || loaded.validateState() != nil {
					t.Fatal("unbounded or invalid state")
				}
			})
		}
	}
}

// Persisted-span compaction keeps later clean collection independent while retaining storm counters.
func TestDeltaCleanAfterPersistedCompaction(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 3
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	s.BeginCoverage(start)
	for i := 1; i <= 5; i++ {
		at := start.Add(time.Duration(i) * time.Second)
		s.StallCoverage(at)
		s.ResumeCoverage(at.Add(20 * time.Millisecond))
		if err := s.Save(at.Add(50 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Save(start.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	w := loaded.Split(start.Add(time.Minute), start.Add(10*time.Minute)).Window
	if w.Truncated || w.CoalescedShortStalls != (CoalescedShortStalls{}) || len(w.CoverageGaps) != 0 {
		t.Fatalf("clean tail inherited historical counters: %+v", w)
	}
	storm := loaded.Split(start, start.Add(time.Minute)).Window
	if !storm.Truncated || storm.CoalescedShortStalls.Count == 0 || storm.CoalescedShortStalls.StalledNS == 0 {
		t.Fatalf("storm counters lost: %+v", storm)
	}
}
