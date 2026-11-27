package firewallwatch

import (
	"slices"
	"time"
)

// netfilterGap has no ALF refusal annotations or private details.
type netfilterGap struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	Kind string    `json:"kind"`
}

type netfilterCoverage struct {
	Status               string               `json:"status"`
	Gaps                 []netfilterGap       `json:"gaps"`
	CoalescedShortStalls CoalescedShortStalls `json:"coalesced_short_stalls"`
	EvictedThrough       *time.Time           `json:"evicted_through"`
	Truncated            bool                 `json:"truncated"`
}

// buildNetfilterCoverage reduces already validated spans and a valid window.
// Global watermarks remain conservative; neither one claims source-only loss.
// Coverage has no grace beyond the last saved source boundary and does not
// inherit collection flags, ALF coverage, health or write-refusal annotations.
func buildNetfilterCoverage(spans []CoverageSpan, evicted, eventEvicted, since, asOf time.Time) netfilterCoverage {
	out := netfilterCoverage{Status: "unavailable", Gaps: []netfilterGap{}, Truncated: true}
	if !evicted.IsZero() {
		at := evicted.UTC()
		out.EvictedThrough = &at
	}
	type boundary struct {
		at                       time.Time
		covered, stalled, legacy int
	}
	points := []boundary{{at: since.UTC()}, {at: asOf.UTC()}}
	add := func(from, to time.Time, covered, stalled, legacy int) {
		if wallBefore(from, since) {
			from = since
		}
		if wallBefore(asOf, to) {
			to = asOf
		}
		if !wallBefore(from, to) {
			return
		}
		points = append(points, boundary{from.UTC(), covered, stalled, legacy}, boundary{to.UTC(), -covered, -stalled, -legacy})
	}
	source := make([]CoverageSpan, 0)
	overlaps := false
	for _, span := range spans {
		if span.Source != SourceNetfilter {
			continue
		}
		source = append(source, span)
		add(span.Start, span.End, 1, 0, 0)
		if wallBefore(span.Start, span.End) && wallBefore(span.Start, asOf) && wallBefore(since, span.End) {
			overlaps = true
			out.CoalescedShortStalls.Count = addCount(out.CoalescedShortStalls.Count, span.ShortStalls)
			out.CoalescedShortStalls.StalledNS = addNS(out.CoalescedShortStalls.StalledNS, span.ShortStalledNS)
		}
		if stall := span.StallAfter; stall != nil {
			add(stall.From, stall.To, 0, 1, 0)
		}
	}
	// Union un-clipped source intervals first: the two boundaries establishing
	// legacy provenance may both lie outside the requested window.
	slices.SortFunc(source, func(a, b CoverageSpan) int { return a.Start.Round(0).Compare(b.Start.Round(0)) })
	type interval struct {
		start, end             time.Time
		startLegacy, endLegacy bool
	}
	intervals := make([]interval, 0)
	for _, span := range source {
		if len(intervals) == 0 || wallBefore(intervals[len(intervals)-1].end, span.Start) {
			intervals = append(intervals, interval{span.Start, span.End, span.Legacy, span.Legacy})
			continue
		}
		last := &intervals[len(intervals)-1]
		if span.Start.Round(0).Equal(last.start.Round(0)) {
			last.startLegacy = last.startLegacy || span.Legacy
		}
		if wallBefore(last.end, span.End) {
			last.end, last.endLegacy = span.End, span.Legacy
		} else if span.End.Round(0).Equal(last.end.Round(0)) {
			last.endLegacy = last.endLegacy || span.Legacy
		}
	}
	for i := 1; i < len(intervals); i++ {
		left, right := intervals[i-1], intervals[i]
		if left.endLegacy && right.startLegacy {
			add(left.end, right.start, 0, 0, 1)
		}
	}
	if wallBefore(since, evicted) && wallBefore(evicted, asOf) {
		points = append(points, boundary{at: evicted.UTC()})
	}
	slices.SortFunc(points, func(a, b boundary) int { return a.at.Compare(b.at) })
	covered, stalled, legacy := 0, 0, 0
	for i := 0; i < len(points); {
		from := points[i].at
		for i < len(points) && points[i].at.Equal(from) {
			covered += points[i].covered
			stalled += points[i].stalled
			legacy += points[i].legacy
			i++
		}
		if i == len(points) {
			break
		}
		to := points[i].at
		kind := ""
		switch {
		case wallBefore(from, evicted):
			kind = GapCoverageEvicted
		case stalled > 0:
			kind = GapStall
		case covered > 0:
		case legacy > 0:
			kind = GapLegacyUnknown
		default:
			kind = GapNotRunning
		}
		if kind == "" {
			continue
		}
		if n := len(out.Gaps); n > 0 && out.Gaps[n-1].Kind == kind && out.Gaps[n-1].To.Equal(from) {
			out.Gaps[n-1].To = to
		} else {
			out.Gaps = append(out.Gaps, netfilterGap{From: from, To: to, Kind: kind})
		}
	}
	if overlaps {
		out.Status = "covered"
		if len(out.Gaps) != 0 || out.CoalescedShortStalls.Count > 0 || (!evicted.IsZero() && wallBefore(since, evicted)) {
			out.Status = "partial"
		}
	}
	out.Truncated = out.Status != "covered" || (!eventEvicted.IsZero() && !wallBefore(eventEvicted, since))
	return out
}
