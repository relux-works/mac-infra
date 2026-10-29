package firewallwatch

import (
	"sort"
	"time"
)

func coverageEnd(v CoverageSpan) time.Time {
	if v.StallAfter != nil && v.StallAfter.To.After(v.End) {
		return v.StallAfter.To
	}
	return v.End
}

func (s *Store) coverageEvicted(at time.Time) {
	if at.After(s.State.CoverageEvictedThrough) {
		s.State.CoverageEvictedThrough = at
	}
}

// pruneCoverage drops the oldest history by start time, preserving each running
// source's newest span whenever the count bound can hold all active sources.
func (s *Store) pruneCoverage(cutoff time.Time) {
	spans := s.State.Coverage
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start.Before(spans[j].Start) })
	if len(spans) > s.Config.MaxEntries {
		spans = compactCoverage(spans, s.coverage)
	}
	active := map[string]int{}
	for i, span := range spans {
		if c := s.coverage[span.Source]; c != nil && c.covering {
			active[span.Source] = i
		}
	}
	isActive := func(i int) bool {
		last, ok := active[spans[i].Source]
		return ok && last == i
	}
	remove := make([]bool, len(spans))
	left := len(spans)
	for i, span := range spans {
		if !isActive(i) && coverageEnd(span).Before(cutoff) {
			remove[i] = true
			left--
		}
	}
	for i := range spans {
		if left <= s.Config.MaxEntries {
			break
		}
		if !remove[i] && !isActive(i) {
			remove[i] = true
			left--
		}
	}
	// A configuration smaller than the active source count must still obey its
	// hard bound. Keep an evicted open span in the runtime tracker so the next
	// save can extend it, including any stall/end observations received meanwhile.
	for i := range spans {
		if left <= s.Config.MaxEntries {
			break
		}
		if !remove[i] {
			remove[i] = true
			left--
		}
	}
	kept := spans[:0]
	for i, span := range spans {
		if remove[i] {
			s.coverageEvicted(coverageEnd(span))
			if isActive(i) {
				snapshot := span
				s.coverage[span.Source].evictedSpan = &snapshot
			}
		} else {
			kept = append(kept, span)
		}
	}
	s.State.Coverage = append([]CoverageSpan(nil), kept...)
}

// compactCoverage keeps long stalls and run boundaries exact. Only a recorded
// sub-second stall joining two spans of the same source can be coalesced.
// A running source's newest span stays separate: extending a historical span
// with coalesced stalls would make even later, complete windows truncated.
func compactCoverage(spans []CoverageSpan, active map[string]*SourceCoverage) []CoverageSpan {
	newest := map[string]int{}
	for i, span := range spans {
		if c := active[span.Source]; c != nil && c.covering {
			newest[span.Source] = i
		}
	}
	result := make([]CoverageSpan, 0, len(spans))
	last := map[string]int{}
	for n, v := range spans {
		tail, running := newest[v.Source]
		if i, ok := last[v.Source]; ok && (!running || n != tail) {
			prev := &result[i]
			stall := prev.StallAfter
			if stall != nil && stall.From.Equal(prev.End) && stall.To.Equal(v.Start) && stall.To.Sub(stall.From) < shortStallThreshold {
				prev.End = v.End
				prev.StallAfter = v.StallAfter
				prev.Legacy = prev.Legacy || v.Legacy
				prev.ShortStalls = addCount(addCount(prev.ShortStalls, v.ShortStalls), 1)
				prev.ShortStalledNS = addNS(addNS(prev.ShortStalledNS, v.ShortStalledNS), int64(stall.To.Sub(stall.From)))
				continue
			}
		}
		last[v.Source] = len(result)
		result = append(result, v)
	}
	return result
}

// compactPending also bounds observations while a save or classifier is busy.
// Consecutive short stalls can share a counter, but cannot cross a long stall.
func compactPending(stalls []pendingStall) []pendingStall {
	result := make([]pendingStall, 0, len(stalls))
	for _, v := range stalls {
		if v.ShortStalls == 0 && v.End.Sub(v.Start) < shortStallThreshold {
			v.ShortStalls, v.ShortStalledNS = 1, int64(v.End.Sub(v.Start))
		}
		if len(result) > 0 && v.ShortStalls > 0 && result[len(result)-1].ShortStalls > 0 {
			prev := &result[len(result)-1]
			prev.End = v.End
			prev.ShortStalls = addCount(prev.ShortStalls, v.ShortStalls)
			prev.ShortStalledNS = addNS(prev.ShortStalledNS, v.ShortStalledNS)
			continue
		}
		result = append(result, v)
	}
	return result
}
