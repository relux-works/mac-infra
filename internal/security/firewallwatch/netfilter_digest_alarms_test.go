package firewallwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
)

func netfilterAlarmJournal(t *testing.T, capacity int) (string, *journal.Journal) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "incidents")
	j, err := journal.Open(dir, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return dir, j
}

func appendNetfilterAlarm(t *testing.T, j *journal.Journal, at time.Time, kind string) {
	t.Helper()
	_, err := j.Append(journal.Entry{TS: at, Kind: kind, Source: "fixture", Actor: "private-actor", Target: "private-host.example", Action: "private-action"})
	if err != nil {
		t.Fatal(err)
	}
}

// Only the three incident kinds in the inclusive window count. The entire
// existing journal remains byte-identical; private payloads never enter the
// summary wire shape. A verified empty selection is distinct from absence.
func TestNetfilterAlarmsWindowAndShape(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	end := at.Add(time.Hour)
	dir, j := netfilterAlarmJournal(t, journal.Capacity)
	for _, e := range []struct {
		at   time.Time
		kind string
	}{
		{at.Add(-time.Nanosecond), "warning"},
		{at, "alarm"},
		{at.Add(time.Minute), "reconcile_mismatch"},
		{at.Add(time.Minute), "block_intent"},
		{end, "warning"},
		{end.Add(time.Nanosecond), "alarm"},
	} {
		appendNetfilterAlarm(t, j, e.at, e.kind)
	}
	file := filepath.Join(dir, "journal.ndjson")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	got := readNetfilterAlarms(dir, at, end)
	want := netfilterAlarmSummary{Status: "verified", Reason: "none", Counts: &netfilterAlarmCounts{Warning: 1, Alarm: 1, ReconcileMismatch: 1}, SeqRefs: []uint64{2, 3, 5}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	data, err := json.Marshal(got)
	const expected = `{"status":"verified","reason":"none","counts":{"warning":1,"alarm":1,"reconcile_mismatch":1},"seq_refs":[2,3,5],"truncated":false}`
	if err != nil || string(data) != expected {
		t.Fatalf("summary shape: %s %v", data, err)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != string(before) {
		t.Fatal("summary changed journal", err)
	}
	empty := readNetfilterAlarms(dir, end.Add(time.Hour), end.Add(2*time.Hour))
	if empty.Status != "verified" || empty.Reason != "none" || empty.Truncated || empty.Counts == nil || *empty.Counts != (netfilterAlarmCounts{}) || empty.SeqRefs == nil || len(empty.SeqRefs) != 0 {
		t.Fatalf("safe verified empty selection: %+v", empty)
	}
}

// Verification precedes selection: tampering in an out-of-window entry
// invalidates the whole summary instead of producing an apparently healthy zero.
// Missing history likewise has no counts and never creates a directory.
func TestNetfilterAlarmsMissingAndTamperedHistory(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	missing := filepath.Join(t.TempDir(), "absent")
	got := readNetfilterAlarms(missing, at, at.Add(time.Hour))
	if got.Status != "unavailable" || got.Reason != "not_found" || got.Counts != nil || got.SeqRefs == nil || len(got.SeqRefs) != 0 || !got.Truncated {
		t.Fatalf("missing: %+v", got)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("summary created directory", err)
	}
	dir, j := netfilterAlarmJournal(t, journal.Capacity)
	appendNetfilterAlarm(t, j, at.Add(-time.Hour), "alarm")
	appendNetfilterAlarm(t, j, at, "warning")
	file := filepath.Join(dir, "journal.ndjson")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), "private-host.example", "edited-host.example", 1)
	if edited == string(raw) {
		t.Fatal("tamper plant did not apply")
	}
	if err := os.WriteFile(file, []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	got = readNetfilterAlarms(dir, at, at.Add(time.Hour))
	if got.Status != "invalid" || got.Reason != "chain_invalid" || got.Counts != nil || len(got.SeqRefs) != 0 || !got.Truncated {
		t.Fatalf("out-of-window tamper: %+v", got)
	}
	after, err := os.ReadFile(file)
	if err != nil || string(after) != edited {
		t.Fatal("summary repaired journal", err)
	}
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if restored := readNetfilterAlarms(dir, at, at.Add(time.Hour)); restored.Status != "verified" || restored.Counts.Warning != 1 {
		t.Fatalf("valid neighbor: %+v", restored)
	}
}

// Compaction discloses retained-chain truncation even for an empty later window.
func TestNetfilterAlarmsCompactedHistory(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	dir, j := netfilterAlarmJournal(t, 1)
	for i := range 3 {
		appendNetfilterAlarm(t, j, at.Add(time.Duration(i)*time.Second), "alarm")
	}
	got := readNetfilterAlarms(dir, at.Add(time.Hour), at.Add(2*time.Hour))
	if got.Status != "verified" || !got.Truncated || got.Counts == nil || *got.Counts != (netfilterAlarmCounts{}) || len(got.SeqRefs) != 0 {
		t.Fatalf("compacted history: %+v", got)
	}
}

// Only the five typed acquisition/history reasons reach the wire. Unknown or
// private error payloads cannot introduce a new reason or verified-zero result.
func TestNetfilterAlarmsClosedRefusals(t *testing.T) {
	for _, tc := range []struct {
		name           string
		err            error
		status, reason string
	}{
		{"missing", &journal.ReadError{Reason: "not_found"}, "unavailable", "not_found"},
		{"unreadable", &journal.ReadError{Reason: "unreadable"}, "unavailable", "unreadable"},
		{"unsafe", &journal.ReadError{Reason: "unsafe_path"}, "unavailable", "unsafe_path"},
		{"malformed", &journal.ReadError{Reason: "malformed"}, "invalid", "malformed"},
		{"chain", fmt.Errorf("private-host: %w", &journal.ReadError{Reason: "chain_invalid"}), "invalid", "chain_invalid"},
		{"unknown-typed", &journal.ReadError{Reason: "private-actor"}, "invalid", "malformed"},
		{"untyped", errors.New("private-host.example"), "invalid", "malformed"},
		{"nil", nil, "invalid", "malformed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := netfilterAlarmRefusal(tc.err)
			if got.Status != tc.status || got.Reason != tc.reason || got.Counts != nil || got.SeqRefs == nil || len(got.SeqRefs) != 0 || !got.Truncated {
				t.Fatalf("closed refusal: %+v", got)
			}
			data, err := json.Marshal(got)
			if err != nil || strings.Contains(string(data), "private-") {
				t.Fatalf("private refusal payload: %s %v", data, err)
			}
		})
	}
}
