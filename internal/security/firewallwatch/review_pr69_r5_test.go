package firewallwatch

// Regression witness from the independent PR69 review r5 (Codex,
// review-pr69-r5.md), kept as written by the reviewer.

import (
	"reflect"
	"testing"
	"time"
)

// A restarted run after a backward wall correction must retain its new span
// even when the prior run's latest span starts later by wall time. Control:
// forward wall order. All spans are individually valid, and startup Save is
// exactly the production order before BeginCoverage.
func TestR5CoverageRestartClockStep(t *testing.T) {
	for _, back := range []bool{false, true} {
		t.Run(map[bool]string{false: "forward", true: "backward"}[back], func(t *testing.T) {
			s, c := journalStore(t)
			b := time.Now().Add(-time.Hour).Round(0)
			s.BeginCoverage(b)
			s.EndCoverage(b.Add(10 * time.Second))
			if e := s.Save(b.Add(10 * time.Second)); e != nil {
				t.Fatal(e)
			}
			s = reopen(t, c)
			restart := b.Add(20 * time.Second)
			if back {
				restart = b.Add(-20 * time.Second)
			}
			if e := s.Save(restart); e != nil {
				t.Fatal(e)
			}
			s.BeginCoverage(restart.Add(time.Second))
			end := restart.Add(5 * time.Second)
			if e := s.Checkpoint(end); e != nil {
				t.Fatal(e)
			}
			if s.journalRecords != 1 {
				t.Fatal("fixture snapshotted", s.journalRecords)
			}
			hashes := dirHashes(t, c.StateDir)
			r := reopen(t, c)
			if !reflect.DeepEqual(hashes, dirHashes(t, c.StateDir)) {
				t.Fatal("reader wrote files")
			}
			a, z := s.Split(restart.Add(2*time.Second), end).Window, r.Split(restart.Add(2*time.Second), end).Window
			t.Logf("backward=%t runtime spans=%s reader spans=%s runtime gaps=%+v reader gaps=%+v runtime truncated=%t reader truncated=%t", back, canonicalCoverage(s.State.Coverage), canonicalCoverage(r.State.Coverage), a.CoverageGaps, z.CoverageGaps, a.Truncated, z.Truncated)
			if canonicalCoverage(s.State.Coverage) != canonicalCoverage(r.State.Coverage) || !reflect.DeepEqual(a.CoverageGaps, z.CoverageGaps) || a.Truncated != z.Truncated {
				t.Error("heartbeat omitted new running span after restart")
			}
			// A full snapshot of precisely this runtime state is the second control.
			if e := s.Save(end); e != nil {
				t.Fatal(e)
			}
			snap := reopen(t, c).Split(restart.Add(2*time.Second), end).Window
			if !reflect.DeepEqual(a.CoverageGaps, snap.CoverageGaps) || a.Truncated != snap.Truncated {
				t.Error("snapshot control differs")
			}
		})
	}
}
