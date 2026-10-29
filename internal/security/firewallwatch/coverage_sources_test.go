package firewallwatch

import (
	"fmt"
	"testing"
	"time"
)

// The reviewer's interleaved-source witness retains both running tails after eviction, in either source direction.
func TestReviewerCompactionKeepsActiveSources(t *testing.T) {
	for _, source := range []string{"", SourceNetfilter} {
		name := source
		if name == "" {
			name = "alf"
		}
		for _, limit := range []int{2, 10000} {
			t.Run(fmt.Sprintf("%s/%d", name, limit), func(t *testing.T) {
				c := testConfig(t)
				c.MaxEntries = limit
				*c.NetfilterSource = true
				s, err := OpenStore(c)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
				at := func(d time.Duration) time.Time { return start.Add(d) }
				other := ""
				if source == "" {
					other = SourceNetfilter
				}
				s.BeginSourceCoverage(source, start)
				s.BeginSourceCoverage(other, start)
				if err = s.Save(at(time.Second)); err != nil {
					t.Fatal(err)
				}
				active := s.Coverage(source)
				active.StallCoverage(at(10 * time.Second))
				active.ResumeCoverage(at(10*time.Second + 20*time.Millisecond))
				stalls := s.Coverage(other)
				for i := 0; i < limit-1; i++ {
					stalls.StallCoverage(at(20*time.Second + time.Duration(i)*3*time.Second))
					stalls.ResumeCoverage(at(22*time.Second + time.Duration(i)*3*time.Second))
				}
				saved := (30 + time.Duration(limit)*3) * time.Second
				if err = s.Save(at(saved)); err != nil {
					t.Fatal(err)
				}
				if len(s.State.Coverage) != limit || s.State.CoverageEvictedThrough.IsZero() {
					t.Fatalf("eviction witness did not reach its bound: spans=%d watermark=%s", len(s.State.Coverage), s.State.CoverageEvictedThrough)
				}
				if err = s.Save(at(saved + 30*time.Second)); err != nil {
					t.Fatal(err)
				}
				loaded, err := OpenStore(c)
				if err != nil {
					t.Fatal(err)
				}
				for _, src := range []string{"", SourceNetfilter} {
					found := false
					for i, span := range loaded.State.Coverage {
						if i > 0 && span.Start.Before(loaded.State.Coverage[i-1].Start) {
							t.Fatal("coverage is not in start-time order")
						}
						if span.Source == src && span.End.Equal(at(saved+30*time.Second)) {
							found = true
						}
					}
					if !found {
						t.Fatalf("running source %q lost its extending span", src)
					}
				}
				w := loaded.Split(at(saved+time.Second), at(saved+30*time.Second)).Window
				if w.Truncated || len(w.CoverageGaps) != 0 {
					t.Fatalf("active collectors became downtime after compaction: %+v", w)
				}
				t.Logf("spans=%d watermark=%s; both sources reach the last save", len(loaded.State.Coverage), loaded.State.CoverageEvictedThrough)
			})
		}
	}
}

// A bound smaller than the source count reopens evicted tails, applies queued stalls/end, and never invents downtime.
func TestCoverageActiveSourcesExceedBound(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 1
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	s.BeginCoverage(start)
	s.BeginSourceCoverage(SourceNetfilter, start.Add(time.Second))
	save := func(at time.Time) {
		t.Helper()
		if err := s.Save(at); err != nil {
			t.Fatal(err)
		}
		if len(s.State.Coverage) != 1 || s.validateState() != nil {
			t.Fatal("hard span bound or validation failed")
		}
		loaded, err := OpenStore(c)
		if err != nil {
			t.Fatal(err)
		}
		for _, gap := range loaded.Split(start, at).Window.CoverageGaps {
			if gap.Kind == GapNotRunning {
				t.Fatalf("evicted running source became downtime: %+v", gap)
			}
		}
	}
	save(start.Add(time.Minute))
	save(start.Add(2 * time.Minute))
	if !s.State.CoverageEvictedThrough.Equal(start.Add(2 * time.Minute)) {
		t.Fatal("evicted source was not extended on the next save")
	}
	// The absent source receives a stall while only its runtime snapshot exists.
	s.StallCoverage(start.Add(3 * time.Minute))
	s.ResumeCoverage(start.Add(4 * time.Minute))
	s.Coverage(SourceNetfilter).EndCoverage(start.Add(4 * time.Minute))
	save(start.Add(5 * time.Minute))
	span := s.State.Coverage[0]
	if span.Source != "" || !span.Start.Equal(start.Add(4*time.Minute)) || !span.End.Equal(start.Add(5*time.Minute)) {
		t.Fatalf("reopened source did not apply pending stall: %+v", span)
	}
	w := s.Split(start.Add(4*time.Minute+time.Second), start.Add(5*time.Minute)).Window
	if w.Truncated || len(w.CoverageGaps) != 0 {
		t.Fatal(w)
	}
	// A later real end must still stop extension of the restored source.
	s.EndCoverage(start.Add(6 * time.Minute))
	if err = s.Save(start.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	requireGap(t, s.Split(start.Add(5*time.Minute), start.Add(10*time.Minute)).Window,
		GapNotRunning, start.Add(6*time.Minute), start.Add(10*time.Minute))
}

// Start-time pruning removes the oldest unprotected history, even when its end is newer than another span's.
func TestCoveragePrunesOldestHistory(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 2
	start := time.Now().Add(-time.Hour)
	s := &Store{Config: c, State: State{Coverage: []CoverageSpan{
		{Start: start.Add(2 * time.Minute), End: start.Add(3 * time.Minute)},
		{Start: start, End: start.Add(10 * time.Minute), Source: SourceNetfilter},
		{Start: start.Add(time.Minute), End: start.Add(2 * time.Minute)},
	}}}
	s.prune(start.Add(time.Hour))
	if len(s.State.Coverage) != 2 || !s.State.Coverage[0].Start.Equal(start.Add(time.Minute)) || !s.State.CoverageEvictedThrough.Equal(start.Add(10*time.Minute)) {
		t.Fatalf("oldest history was not evicted: %+v", s.State)
	}
}
