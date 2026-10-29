package firewallwatch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func writeUnversionedCoverage(t *testing.T, c Config, spans []CoverageSpan) {
	t.Helper()
	if err := safeDir(c.StateDir); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{
		"entries": map[string]any{}, "signers": map[string]any{}, "coverage": spans,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.StateDir, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// Old stall-split spans yield three unknown gaps and exactly one stop at the new run, including touching and zero-length spans.
func TestCoverageLegacyRestartWitness(t *testing.T) {
	c := testConfig(t)
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	at := func(d time.Duration) time.Time { return start.Add(d) }
	writeUnversionedCoverage(t, c, []CoverageSpan{
		{Start: start, End: at(time.Minute)},
		{Start: at(time.Minute), End: at(2 * time.Minute)},
		{Start: at(2*time.Minute + 20*time.Millisecond), End: at(3 * time.Minute)},
		{Start: at(3*time.Minute + 20*time.Millisecond), End: at(3*time.Minute + 20*time.Millisecond)},
		{Start: at(3*time.Minute + 20*time.Millisecond), End: at(5 * time.Minute)},
		{Start: at(5*time.Minute + time.Nanosecond), End: at(6 * time.Minute)},
		{Start: start, End: at(6 * time.Minute), Source: SourceNetfilter},
	})
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, span := range s.State.Coverage {
		if !span.Legacy {
			t.Fatal("unversioned span was not migrated", span)
		}
	}
	s.BeginCoverage(at(10 * time.Minute))
	if err = s.Save(at(15 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []SplitGap{
		{Kind: GapLegacyUnknown, From: at(2 * time.Minute), To: at(2*time.Minute + 20*time.Millisecond)},
		{Kind: GapLegacyUnknown, From: at(3 * time.Minute), To: at(3*time.Minute + 20*time.Millisecond)},
		{Kind: GapLegacyUnknown, From: at(5 * time.Minute), To: at(5*time.Minute + time.Nanosecond)},
		{Kind: GapNotRunning, From: at(6 * time.Minute), To: at(10 * time.Minute)},
	}
	w := s.Split(start, at(15*time.Minute)).Window
	if !w.Truncated || !reflect.DeepEqual(w.CoverageGaps, want) {
		t.Fatalf("want exactly 3 legacy_unknown and 1 not_running: got %+v", w)
	}
	// Both bounding spans are outside this narrow window, but their provenance still applies.
	requireGap(t, s.Split(at(2*time.Minute+time.Millisecond), at(2*time.Minute+10*time.Millisecond)).Window,
		GapLegacyUnknown, at(2*time.Minute+time.Millisecond), at(2*time.Minute+10*time.Millisecond))
	t.Log("legacy_unknown=3 not_running=1; touching/zero-length spans create no extra gaps")
}

// A wholly new-format history retains exact eviction, restart and stall kinds after save and load.
func TestCoverageNewFormatKindsControl(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 2
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	at := func(m int) time.Time { return start.Add(time.Duration(m) * time.Minute) }
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginCoverage(start)
	s.EndCoverage(at(1))
	if err = s.Save(at(1)); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginCoverage(at(2))
	s.StallCoverage(at(3))
	s.ResumeCoverage(at(4))
	s.EndCoverage(at(5))
	if err = s.Save(at(5)); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []SplitGap{
		{Kind: GapCoverageEvicted, From: start, To: at(1)},
		{Kind: GapNotRunning, From: at(1), To: at(2)},
		{Kind: GapStall, From: at(3), To: at(4)},
	}
	if got := s.Split(start, at(5)).Window.CoverageGaps; !reflect.DeepEqual(got, want) {
		t.Fatalf("new-format kinds changed: %+v", got)
	}
	for _, span := range s.State.Coverage {
		if span.Legacy {
			t.Fatal("new-format span reflagged", span)
		}
	}
	t.Log("coverage_evicted=1 not_running=1 stall=1 legacy_unknown=0; span bound=2")
}

// Repeated mixed-history round trips preserve legacy flags without reflagging new ALF or netfilter spans.
func TestCoverageLegacyRoundTrip(t *testing.T) {
	c := testConfig(t)
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	writeUnversionedCoverage(t, c, []CoverageSpan{{Start: start, End: start.Add(time.Minute)}})
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"", SourceNetfilter} {
		s.BeginSourceCoverage(source, start.Add(2*time.Minute))
	}
	var want []CoverageSpan
	for i := 0; i < 2; i++ {
		if err = s.Save(start.Add(3 * time.Minute)); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
		if err != nil {
			t.Fatal(err)
		}
		var saved State
		if err = json.Unmarshal(raw, &saved); err != nil || saved.CoverageVersion != coverageVersion {
			t.Fatalf("format marker not saved: version=%d err=%v", saved.CoverageVersion, err)
		}
		if i == 0 {
			want = append([]CoverageSpan(nil), s.State.Coverage...)
		}
		s, err = OpenStore(c)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(s.State.Coverage, want) || len(want) != 3 || !want[0].Legacy || want[1].Legacy || want[2].Legacy {
			t.Fatalf("provenance changed on round trip: %+v", s.State.Coverage)
		}
	}
}

// Compaction ORs legacy provenance from either input, and count/age pruning preserves unknown gaps and real restarts.
func TestCoverageLegacyCompactionPruning(t *testing.T) {
	for _, flags := range [][2]bool{{true, false}, {false, true}, {true, true}, {false, false}} {
		for _, mode := range []string{"count", "age"} {
			t.Run(fmt.Sprintf("%t/%t/%s", flags[0], flags[1], mode), func(t *testing.T) {
				c := testConfig(t)
				c.MaxEntries = 3
				if mode == "age" {
					c.MaxEntries = 4
				}
				s, err := OpenStore(c)
				if err != nil {
					t.Fatal(err)
				}
				start := time.Now().Add(-time.Hour).Truncate(time.Second)
				at := func(m int) time.Time { return start.Add(time.Duration(m) * time.Minute) }
				s.State.Coverage = []CoverageSpan{
					{Start: start, End: at(1), Legacy: true},
					{Start: at(2), End: at(3), Legacy: flags[0], StallAfter: &CoverageStall{From: at(3), To: at(3).Add(20 * time.Millisecond)}},
					{Start: at(3).Add(20 * time.Millisecond), End: at(4), Legacy: flags[1]},
					{Start: at(6), End: at(7), Legacy: true},
					{Start: at(9), End: at(10)},
				}
				cutoff := start
				if mode == "age" {
					cutoff = at(2)
				}
				s.pruneCoverage(cutoff)
				legacy := flags[0] || flags[1]
				if len(s.State.Coverage) != 3 || s.State.Coverage[0].Legacy != legacy || s.State.Coverage[0].ShortStalls != 1 || !s.State.CoverageEvictedThrough.Equal(at(1)) {
					t.Fatalf("compaction/pruning lost provenance or bound: %+v", s.State)
				}
				if err = s.Save(at(10)); err != nil {
					t.Fatal(err)
				}
				s, err = OpenStore(c)
				if err != nil {
					t.Fatal(err)
				}
				kind := GapNotRunning
				if legacy {
					kind = GapLegacyUnknown
				}
				requireGap(t, s.Split(at(4), at(6)).Window, kind, at(4), at(6))
				requireGap(t, s.Split(at(7), at(9)).Window, GapNotRunning, at(7), at(9))
				requireGap(t, s.Split(start, at(1)).Window, GapCoverageEvicted, start, at(1))
			})
		}
	}
}

// Legacy classification respects source, overlap boundaries and exact-stall/eviction precedence without changing tails.
func TestCoverageLegacyBoundaries(t *testing.T) {
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	at := func(m int) time.Time { return start.Add(time.Duration(m) * time.Minute) }
	for _, tc := range []struct {
		name    string
		spans   []CoverageSpan
		kind    string
		evicted time.Time
	}{
		{"legacy", []CoverageSpan{{Start: start, End: at(1), Legacy: true}, {Start: at(2), End: at(3), Legacy: true}}, GapLegacyUnknown, time.Time{}},
		{"new_left", []CoverageSpan{{Start: start, End: at(1)}, {Start: at(2), End: at(3), Legacy: true}}, GapNotRunning, time.Time{}},
		{"new_right", []CoverageSpan{{Start: start, End: at(1), Legacy: true}, {Start: at(2), End: at(3)}}, GapNotRunning, time.Time{}},
		{"other_source", []CoverageSpan{{Start: start, End: at(1), Legacy: true}, {Start: at(2), End: at(3), Legacy: true, Source: SourceNetfilter}}, GapNotRunning, time.Time{}},
		{"overlapping_new_boundary", []CoverageSpan{{Start: start, End: at(1)}, {Start: start, End: start.Add(30 * time.Second), Legacy: true}, {Start: at(2), End: at(3), Legacy: true}}, GapNotRunning, time.Time{}},
		{"tied_boundaries", []CoverageSpan{{Start: start, End: at(1)}, {Start: start, End: at(1), Legacy: true}, {Start: at(2), End: at(3)}, {Start: at(2), End: at(3), Legacy: true}}, GapLegacyUnknown, time.Time{}},
		{"explicit_stall", []CoverageSpan{{Start: start, End: at(1), Legacy: true, StallAfter: &CoverageStall{From: at(1), To: at(2)}}, {Start: at(2), End: at(3), Legacy: true}}, GapStall, time.Time{}},
		{"evicted", []CoverageSpan{{Start: start, End: at(1), Legacy: true, StallAfter: &CoverageStall{From: at(1), To: at(2)}}, {Start: at(2), End: at(3), Legacy: true}}, GapCoverageEvicted, at(2)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Store{Config: testConfig(t), State: State{Coverage: tc.spans, CoverageEvictedThrough: tc.evicted}}
			requireGap(t, s.Split(at(1), at(2)).Window, tc.kind, at(1), at(2))
		})
	}
	s := &Store{Config: testConfig(t), State: State{Coverage: []CoverageSpan{{Start: at(1), End: at(2), Legacy: true}}}}
	requireGap(t, s.Split(start, at(1)).Window, GapNotRunning, start, at(1))
	requireGap(t, s.Split(at(2), at(3)).Window, GapNotRunning, at(2), at(3))
}

// Unsupported coverage versions are refused instead of silently assigning historical gap causes.
func TestCoverageVersionBounds(t *testing.T) {
	c := testConfig(t)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{-1, coverageVersion + 1} {
		s.State.CoverageVersion = version
		if s.validateState() == nil {
			t.Fatalf("unsupported coverage version %d admitted", version)
		}
	}
}
