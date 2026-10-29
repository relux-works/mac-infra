package firewallwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
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
