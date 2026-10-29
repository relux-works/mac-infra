package firewallwatch

// Regression witness from the independent PR69 review r3 (Codex,
// review-pr69-r3.md), kept as written by the reviewer except where noted.

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// Historical complete windows must have the same gaps and truncated verdict
// in the running store and a journal reader, not only in the newest span.
// Full snapshot is an explicit second control for the reader's transformation.
func TestR3HistoricalCoverageEquality(t *testing.T) {
	s := pruneFixture(t, 3)
	base := time.Now().Add(-time.Hour).Round(0)
	s.BeginCoverage(base)
	c := s.Coverage("")
	c.StallCoverage(base.Add(time.Second))
	c.ResumeCoverage(base.Add(1100 * time.Millisecond))
	if e := s.Save(base.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	c.StallCoverage(base.Add(3 * time.Second))
	c.ResumeCoverage(base.Add(3100 * time.Millisecond))
	c.StallCoverage(base.Add(4 * time.Second))
	c.ResumeCoverage(base.Add(4100 * time.Millisecond))
	if e := s.Checkpoint(base.Add(6 * time.Second)); e != nil {
		t.Fatal(e)
	}
	hashes := dirHashes(t, s.Config.StateDir)
	reader := reopen(t, s.Config)
	if !reflect.DeepEqual(hashes, dirHashes(t, s.Config.StateDir)) {
		t.Fatal("reader wrote artifacts")
	}
	windows := [][2]time.Duration{{100 * time.Millisecond, 900 * time.Millisecond}, {1200 * time.Millisecond, 2800 * time.Millisecond}, {4200 * time.Millisecond, 5800 * time.Millisecond}, {0, 6 * time.Second}}
	for _, w := range windows {
		a := s.Split(base.Add(w[0]), base.Add(w[1])).Window
		b := reader.Split(base.Add(w[0]), base.Add(w[1])).Window
		t.Logf("window %v runtime truncated=%t gaps=%+v counters=%+v; reader truncated=%t gaps=%+v counters=%+v", w, a.Truncated, a.CoverageGaps, a.CoalescedShortStalls, b.Truncated, b.CoverageGaps, b.CoalescedShortStalls)
		if a.Truncated != b.Truncated || !reflect.DeepEqual(a.CoverageGaps, b.CoverageGaps) {
			t.Errorf("runtime versus replay semantics differ for %v", w)
		}
	}
	// Keeper's adaptation: readers no longer transform coverage (r3 finding 1),
	// so the reader equals the running watcher above, not a later snapshot. A
	// snapshot compacts under count pressure; a reader of that snapshot must
	// then equal the watcher after it.
	if e := s.Save(base.Add(6 * time.Second)); e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(s.State.Coverage)
	b, _ := json.Marshal(reopen(t, s.Config).State.Coverage)
	if !bytes.Equal(a, b) {
		t.Errorf("snapshot control differs: %s versus %s", a, b)
	}
}
