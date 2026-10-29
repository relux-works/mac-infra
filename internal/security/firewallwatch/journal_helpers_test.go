package firewallwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"sort"
	"testing"
)

// readJournal returns the complete records of a journal file, none if absent.
func readJournal(t *testing.T, path string) []journalRecord {
	t.Helper()
	raw, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		t.Fatal(e)
	}
	var records []journalRecord
	for _, line := range bytes.Split(raw, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var r journalRecord
		if e := json.Unmarshal(line, &r); e != nil {
			t.Fatalf("journal line %q: %v", line, e)
		}
		records = append(records, r)
	}
	return records
}

// canonicalCoverage renders coverage in start order (then source), the order
// independent of how the spans were appended or replayed.
func canonicalCoverage(spans []CoverageSpan) string {
	spans = slices.Clone(spans)
	sort.SliceStable(spans, func(i, j int) bool {
		if spans[i].Start.Equal(spans[j].Start) {
			return spans[i].Source < spans[j].Source
		}
		return spans[i].Start.Before(spans[j].Start)
	})
	raw, _ := json.Marshal(spans)
	return string(raw)
}
