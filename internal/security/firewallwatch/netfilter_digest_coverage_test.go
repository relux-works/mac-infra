package firewallwatch

import (
	"math"
	"reflect"
	"testing"
	"time"
)

// Only positively overlapping netfilter spans establish coverage availability.
// ALF, touching endpoints and missing history cannot turn unknown time healthy;
// the source's last saved boundary has no extrapolated tail grace.
func TestNetfilterCoverageSourceAndTail(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	end := at.Add(time.Hour)
	span := CoverageSpan{Source: SourceNetfilter, Start: at, End: end}
	for _, tc := range []struct {
		name   string
		spans  []CoverageSpan
		status string
		gaps   []netfilterGap
	}{
		{"covered", []CoverageSpan{span}, "covered", []netfilterGap{}},
		{"absent", nil, "unavailable", []netfilterGap{{From: at, To: end, Kind: GapNotRunning}}},
		{"ALF only", []CoverageSpan{{Start: at, End: end}}, "unavailable", []netfilterGap{{From: at, To: end, Kind: GapNotRunning}}},
		{"touching start", []CoverageSpan{{Source: SourceNetfilter, Start: at.Add(-time.Minute), End: at}}, "unavailable", []netfilterGap{{From: at, To: end, Kind: GapNotRunning}}},
		{"touching end", []CoverageSpan{{Source: SourceNetfilter, Start: end, End: end.Add(time.Minute)}}, "unavailable", []netfilterGap{{From: at, To: end, Kind: GapNotRunning}}},
		{"zero-width source", []CoverageSpan{{Source: SourceNetfilter, Start: at.Add(time.Minute), End: at.Add(time.Minute)}}, "unavailable", []netfilterGap{{From: at, To: end, Kind: GapNotRunning}}},
		{"no tail grace", []CoverageSpan{{Source: SourceNetfilter, Start: at, End: end.Add(-time.Nanosecond)}, {Start: at, End: end}}, "partial", []netfilterGap{{From: end.Add(-time.Nanosecond), To: end, Kind: GapNotRunning}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildNetfilterCoverage(tc.spans, time.Time{}, time.Time{}, at, end)
			if got.Status != tc.status || !reflect.DeepEqual(got.Gaps, tc.gaps) || got.Truncated != (tc.status != "covered") || got.EvictedThrough != nil {
				t.Fatalf("got %+v want status=%s gaps=%+v", got, tc.status, tc.gaps)
			}
		})
	}
}

// Exact stalls override overlapping coverage; global eviction overrides stalls.
// ALF stalls and counters never contaminate the source-specific result.
func TestNetfilterCoveragePrecedence(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	minute := func(n int) time.Time { return at.Add(time.Duration(n) * time.Minute) }
	spans := []CoverageSpan{
		{Source: SourceNetfilter, Start: at, End: minute(60)},
		{Source: SourceNetfilter, Start: minute(-1), End: minute(10), StallAfter: &CoverageStall{From: minute(10), To: minute(30)}},
		{Start: minute(-1), End: minute(1), StallAfter: &CoverageStall{From: minute(1), To: minute(60)}, ShortStalls: 99, ShortStalledNS: 999},
	}
	got := buildNetfilterCoverage(spans, minute(20), time.Time{}, at, minute(60))
	want := []netfilterGap{{From: at, To: minute(20), Kind: GapCoverageEvicted}, {From: minute(20), To: minute(30), Kind: GapStall}}
	if got.Status != "partial" || !got.Truncated || !reflect.DeepEqual(got.Gaps, want) || got.EvictedThrough == nil || !got.EvictedThrough.Equal(minute(20)) || got.CoalescedShortStalls != (CoalescedShortStalls{}) {
		t.Fatalf("precedence: %+v", got)
	}
	// Event loss marks truncation without fabricating a coverage gap or count.
	got = buildNetfilterCoverage(spans[:1], time.Time{}, at, at, minute(60))
	if got.Status != "covered" || !got.Truncated || len(got.Gaps) != 0 {
		t.Fatalf("event-loss watermark: %+v", got)
	}
	got = buildNetfilterCoverage(spans[:1], time.Time{}, at.Add(-time.Nanosecond), at, minute(60))
	if got.Status != "covered" || got.Truncated {
		t.Fatalf("old event loss is outside the window: %+v", got)
	}
}

// Legacy provenance is ORed at tied outer union boundaries, even outside the
// requested window; an interior legacy marker alone cannot relabel a gap.
func TestNetfilterCoverageLegacyUnion(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	minute := func(n int) time.Time { return at.Add(time.Duration(n) * time.Minute) }
	left := CoverageSpan{Source: SourceNetfilter, Start: minute(-1), End: minute(10), Legacy: true}
	right := CoverageSpan{Source: SourceNetfilter, Start: minute(50), End: minute(61), Legacy: true}
	tiedLeft, tiedRight := left, right
	tiedLeft.Legacy, tiedRight.Legacy = false, false
	spans := []CoverageSpan{right, tiedLeft, tiedRight, left}
	want := []netfilterGap{{From: minute(10), To: minute(50), Kind: GapLegacyUnknown}}
	got := buildNetfilterCoverage(spans, time.Time{}, time.Time{}, at, minute(60))
	if got.Status != "partial" || !reflect.DeepEqual(got.Gaps, want) {
		t.Fatalf("legacy union: %+v", got)
	}
	for i, j := 0, len(spans)-1; i < j; i, j = i+1, j-1 {
		spans[i], spans[j] = spans[j], spans[i]
	}
	if other := buildNetfilterCoverage(spans, time.Time{}, time.Time{}, at, minute(60)); !reflect.DeepEqual(got, other) {
		t.Fatal("tied boundary result depends on input order")
	}
	// This window lies wholly between source spans outside its bounds.
	inside := buildNetfilterCoverage(spans, time.Time{}, time.Time{}, minute(20), minute(40))
	if inside.Status != "unavailable" || !reflect.DeepEqual(inside.Gaps, []netfilterGap{{From: minute(20), To: minute(40), Kind: GapLegacyUnknown}}) {
		t.Fatalf("outside bounding spans: %+v", inside)
	}
	left.Legacy = false
	interior := CoverageSpan{Source: SourceNetfilter, Start: minute(1), End: minute(2), Legacy: true}
	got = buildNetfilterCoverage([]CoverageSpan{left, interior, right}, time.Time{}, time.Time{}, at, minute(60))
	if !reflect.DeepEqual(got.Gaps, []netfilterGap{{From: minute(10), To: minute(50), Kind: GapNotRunning}}) {
		t.Fatalf("interior marker changed outer provenance: %+v", got)
	}
}

// Whole intersecting source-span counters saturate; touching or foreign spans
// do not contribute. Counter uncertainty marks partial even without exact gaps.
func TestNetfilterCoverageCompactedCounters(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	end := at.Add(time.Hour)
	spans := []CoverageSpan{
		{Source: SourceNetfilter, Start: at.Add(-time.Minute), End: end, ShortStalls: math.MaxUint64, ShortStalledNS: math.MaxInt64},
		{Source: SourceNetfilter, Start: at, End: end.Add(time.Minute), ShortStalls: 1, ShortStalledNS: 1},
		{Source: SourceNetfilter, Start: end, End: end.Add(time.Hour), ShortStalls: 30, ShortStalledNS: 30},
		{Start: at, End: end, ShortStalls: 50, ShortStalledNS: 50},
	}
	got := buildNetfilterCoverage(spans, time.Time{}, time.Time{}, at, end)
	if got.Status != "partial" || !got.Truncated || len(got.Gaps) != 0 || got.CoalescedShortStalls.Count != math.MaxUint64 || got.CoalescedShortStalls.StalledNS != math.MaxInt64 {
		t.Fatalf("compacted source counters: %+v", got)
	}
}

// Accepted finite recipes exercise the production reducer at the retained
// reader-tail limit. Every gap is checked against the independent formula;
// source admission and the excessive wire-bound plant are separate tests.
func TestNetfilterCoverageFiniteRecipes(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	end := at.Add(time.Hour)
	ms := func(n int) time.Time { return at.Add(time.Duration(n) * time.Millisecond) }
	for _, tc := range []struct {
		name     string
		n        int
		stall    bool
		gapCount int
	}{
		{"disjoint-2", 2, false, 3},
		{"disjoint-100000", 100000, false, 100001},
		{"disjoint-100256", 100256, false, 100257},
		{"exact-stalls-2", 2, true, 5},
		{"exact-stalls-100256", 100256, true, 200513},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := 2
			if tc.stall {
				step = 4
			}
			spans := make([]CoverageSpan, tc.n)
			for i := range spans {
				spans[i] = CoverageSpan{Source: SourceNetfilter, Start: ms(step*i + 1), End: ms(step*i + 2)}
				if tc.stall {
					spans[i].StallAfter = &CoverageStall{From: ms(4*i + 2), To: ms(4*i + 3)}
				}
			}
			got := buildNetfilterCoverage(spans, time.Time{}, time.Time{}, at, end)
			if got.Status != "partial" || !got.Truncated || len(got.Gaps) != tc.gapCount {
				t.Fatalf("status=%s truncated=%t gaps=%d want=%d", got.Status, got.Truncated, len(got.Gaps), tc.gapCount)
			}
			check := func(index int, from, to time.Time, kind string) {
				t.Helper()
				want := netfilterGap{From: from, To: to, Kind: kind}
				if got.Gaps[index] != want {
					t.Fatalf("gap %d: got %+v want %+v", index, got.Gaps[index], want)
				}
			}
			check(0, at, ms(1), GapNotRunning)
			if tc.stall {
				for i := range spans {
					check(2*i+1, ms(4*i+2), ms(4*i+3), GapStall)
					if i < tc.n-1 {
						check(2*i+2, ms(4*i+3), ms(4*i+5), GapNotRunning)
					}
				}
				check(tc.gapCount-1, ms(4*tc.n-1), end, GapNotRunning)
			} else {
				for i := 0; i < tc.n-1; i++ {
					check(i+1, ms(2*i+2), ms(2*i+3), GapNotRunning)
				}
				check(tc.gapCount-1, ms(2*tc.n), end, GapNotRunning)
			}
		})
	}
}
