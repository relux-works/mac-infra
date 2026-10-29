package firewallwatch

import "time"

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

// compactCoverage keeps long stalls and run boundaries exact. Only a recorded
// sub-second stall joining two spans of the same source can be coalesced.
func compactCoverage(spans []CoverageSpan) []CoverageSpan {
	result := make([]CoverageSpan, 0, len(spans))
	last := map[string]int{}
	for _, v := range spans {
		if i, ok := last[v.Source]; ok {
			prev := &result[i]
			stall := prev.StallAfter
			if stall != nil && stall.From.Equal(prev.End) && stall.To.Equal(v.Start) && stall.To.Sub(stall.From) < shortStallThreshold {
				prev.End = v.End
				prev.StallAfter = v.StallAfter
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
