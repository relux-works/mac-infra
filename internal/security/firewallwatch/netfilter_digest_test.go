package firewallwatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func netfilterDigestStore(t *testing.T, enabled bool) *Store {
	t.Helper()
	return &Store{
		Config: Config{MaxEntries: 100000, NetfilterSource: &enabled, NetfilterJournalDir: filepath.Join(t.TempDir(), "missing-incidents")},
		State:  State{Entries: map[string]*Entry{}, Signers: map[string]SignerEntry{}, CoverageVersion: coverageVersion},
	}
}

func netfilterDigestEvent(at time.Time) Event {
	return Event{TS: at, Source: SourceNetfilter, App: "fixture-app", Signer: "unsigned", Verdict: "allow", RemoteClass: "internet", Bucket: "fixture-bucket", Kind: "outbound", Counts: 99, Label: "digest", Reason: map[string]any{"kind": "fixture"}, Mode: "shadow"}
}

// The additive method preserves every legacy member byte-for-byte for the
// same bounds (including their offset), while the new section uses UTC and
// retained row counts. Neither state nor an absent incident path is written.
func TestNetfilterDigestAdditiveLegacyProjection(t *testing.T) {
	since := time.Date(2026, 10, 31, 11, 0, 0, 0, time.FixedZone("fixture-offset", 3*3600))
	asOf := since.Add(time.Hour)
	s := netfilterDigestStore(t, false)
	s.State.Events = []Event{netfilterDigestEvent(since)}
	s.State.Coverage = []CoverageSpan{{Start: since, End: asOf, Source: SourceNetfilter}}
	before, err := json.Marshal(s.State)
	if err != nil {
		t.Fatal(err)
	}
	old, err := json.Marshal(s.Split(since, asOf))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.SplitWithNetfilter(since, asOf)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var oldMembers, newMembers map[string]json.RawMessage
	if json.Unmarshal(old, &oldMembers) != nil || json.Unmarshal(data, &newMembers) != nil {
		t.Fatal("invalid digest JSON")
	}
	if len(oldMembers) != 5 || len(newMembers) != 6 {
		t.Fatalf("unexpected top level: %s", data)
	}
	for key, value := range oldMembers {
		if string(value) != string(newMembers[key]) {
			t.Fatalf("legacy member %s changed", key)
		}
	}
	n := got.Netfilter
	if n == nil || n.Schema != "mac-infra.netfilter-digest/v1" || n.Basis != "retained_events" || n.Status != "available" || n.Reason != "none" || n.CollectionStatus != "disabled" {
		t.Fatalf("availability: %+v", n)
	}
	if n.Window.EventRows != 1 || n.Window.OutboundEventRows != 1 || n.Window.Coverage.Status != "covered" || n.Window.Coverage.Truncated || n.Window.Since.Location() != time.UTC || !n.Window.Since.Equal(since) || n.Window.EventEvictedThrough != nil {
		t.Fatalf("window: %+v", n.Window)
	}
	if n.Capabilities.FlowWindowCounts != "unavailable" || n.Capabilities.FullCodeIdentity != "unavailable" || n.Capabilities.DestinationNovelty != "unavailable" || n.Capabilities.DestinationCompleteness != "retained_tuples_only" {
		t.Fatal("fabricated capabilities")
	}
	if n.Alarms.Status != "unavailable" || n.Alarms.Reason != "not_found" || n.Alarms.Counts != nil {
		t.Fatalf("absent incident history: %+v", n.Alarms)
	}
	var section map[string]json.RawMessage
	if json.Unmarshal(newMembers["netfilter"], &section) != nil || len(section) != 13 || string(section["known_fp"]) != "{}" {
		t.Fatal("new section is not the closed13-member object")
	}
	after, err := json.Marshal(s.State)
	if err != nil || string(after) != string(before) {
		t.Fatal("state mutated", err)
	}
	if _, err := os.Lstat(s.Config.NetfilterJournalDir); !os.IsNotExist(err) {
		t.Fatal("incident path created", err)
	}
}

// No retained source evidence stays explicitly unavailable. A zero-duration
// span or an ALF span cannot make source coverage available; rows can do so
// independently without inventing coverage or flow counts.
func TestNetfilterDigestAvailabilityNeighbors(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name             string
		events           []Event
		spans            []CoverageSpan
		status, coverage string
	}{
		{"absent", nil, nil, "unavailable", "unavailable"},
		{"zero-width", nil, []CoverageSpan{{Start: at, End: at, Source: SourceNetfilter}}, "unavailable", "unavailable"},
		{"alf-only", nil, []CoverageSpan{{Start: at, End: at.Add(time.Hour)}}, "unavailable", "unavailable"},
		{"row-only", []Event{netfilterDigestEvent(at)}, nil, "available", "unavailable"},
		{"coverage-only", nil, []CoverageSpan{{Start: at, End: at.Add(time.Hour), Source: SourceNetfilter}}, "available", "covered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := netfilterDigestStore(t, true)
			s.State.Events, s.State.Coverage = tc.events, tc.spans
			d, err := s.SplitWithNetfilter(at, at.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			n := d.Netfilter
			if n.Status != tc.status || n.Window.Coverage.Status != tc.coverage || n.CollectionStatus != "enabled" {
				t.Fatalf("availability: %+v", n)
			}
			wantReason := "none"
			if tc.status == "unavailable" {
				wantReason = "history_absent"
			}
			if n.Reason != wantReason || n.PerApp == nil || n.Destinations == nil || n.UnsignedOutbound.Rows == nil || n.OddPorts.Rows == nil {
				t.Fatal("missing/nullable required arrays")
			}
		})
	}
}

// Source shape and wire constraints reject their intended invalid neighbor
// before producing any digest. A nearby valid legacy-unknown observation
// remains admitted, so refusal cannot satisfy the suite by rejecting all data.
func TestNetfilterDigestRefusals(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		mutate func(*Store)
	}{
		{"zero-bound", func(s *Store) { s.Config.MaxEntries = 0 }},
		{"excess-bound", func(s *Store) { s.Config.MaxEntries = 100001 }},
		{"missing-collection", func(s *Store) { s.Config.NetfilterSource = nil }},
		{"missing-state-map", func(s *Store) { s.State.Entries = nil }},
		{"excess-event", func(s *Store) { s.Config.MaxEntries = 1; s.State.Events = append(s.State.Events, s.State.Events[0]) }},
		{"invalid-mode", func(s *Store) { s.State.Events[0].Mode = "other" }},
		{"invalid-class", func(s *Store) { s.State.Events[0].RemoteClass = "not-a-class" }},
		{"control-bucket", func(s *Store) { s.State.Events[0].Bucket = "private\nvalue" }},
		{"invalid-utf8", func(s *Store) { s.State.Events[0].Bucket = string([]byte{0xff}) }},
		{"excess-coverage", func(s *Store) { s.Config.MaxEntries = 1; s.State.Coverage = make([]CoverageSpan, 258) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := netfilterDigestStore(t, true)
			s.State.Events = []Event{netfilterDigestEvent(at)}
			tc.mutate(s)
			got, err := s.SplitWithNetfilter(at, at.Add(time.Hour))
			if err == nil || !strings.HasPrefix(err.Error(), "netfilter digest: invalid retained state") || !reflect.DeepEqual(got, DigestSplit{}) {
				t.Fatalf("refusal: %+v %v", got, err)
			}
			if _, err := os.Lstat(s.Config.NetfilterJournalDir); !os.IsNotExist(err) {
				t.Fatal("refused operation wrote journal", err)
			}
		})
	}
	s := netfilterDigestStore(t, true)
	e := netfilterDigestEvent(at)
	e.Kind = ""
	e.RemoteClass = "unknown"
	s.State.Events = []Event{e}
	if d, err := s.SplitWithNetfilter(at, at.Add(time.Hour)); err != nil || d.Netfilter.Window.UnknownDirectionEventRows != 1 {
		t.Fatalf("valid legacy neighbor: %+v %v", d, err)
	}
	for _, bounds := range [][2]time.Time{{at, at}, {at.Add(time.Second), at}, {{}, at}} {
		if d, err := s.SplitWithNetfilter(bounds[0], bounds[1]); err == nil || err.Error() != "netfilter digest: invalid window" || !reflect.DeepEqual(d, DigestSplit{}) {
			t.Fatalf("invalid window produced digest: %+v %v", d, err)
		}
	}
}

// The actual additive source path accepts the complete loaded replay-tail
// bound, not merely MaxEntries, then refuses the next otherwise valid span.
// Both sources share this bound; filtering cannot conceal an excessive array.
func TestNetfilterDigestLoadedCoverageBound(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	s := netfilterDigestStore(t, true)
	s.State.Coverage = make([]CoverageSpan, 100000+journalMaxTailSpans)
	for i := range s.State.Coverage {
		s.State.Coverage[i] = CoverageSpan{Start: at, End: at, Source: SourceNetfilter}
	}
	if d, err := s.SplitWithNetfilter(at, at.Add(time.Hour)); err != nil || d.Netfilter.Status != "unavailable" {
		t.Fatalf("100256 valid loaded spans: %+v %v", d, err)
	}
	s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: at, End: at})
	if d, err := s.SplitWithNetfilter(at, at.Add(time.Hour)); err == nil || err.Error() != "netfilter digest: invalid retained state" || !reflect.DeepEqual(d, DigestSplit{}) {
		t.Fatalf("100257 span refusal: %+v %v", d, err)
	}
	if len(s.State.Coverage) != 100257 {
		t.Fatal("reader pruned excessive coverage instead of refusing it")
	}
}

// Coverage eviction contributes only a positive unknown prefix. Equality at
// since cannot make complete source coverage partial; event-loss equality is
// independently conservative and still truncates that covered window.
func TestNetfilterDigestCoverageEvictionBoundary(t *testing.T) {
	at := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	end := at.Add(time.Hour)
	for _, tc := range []struct {
		name      string
		watermark time.Time
		status    string
		gaps      []netfilterGap
	}{
		{"before", at.Add(-time.Nanosecond), "covered", []netfilterGap{}},
		{"equal", at, "covered", []netfilterGap{}},
		{"after", at.Add(time.Nanosecond), "partial", []netfilterGap{{From: at, To: at.Add(time.Nanosecond), Kind: GapCoverageEvicted}}},
	} {
		for _, eventLoss := range []bool{false, true} {
			name := tc.name + "/no-event-loss"
			if eventLoss {
				name = tc.name + "/event-loss-at-since"
			}
			t.Run(name, func(t *testing.T) {
				s := netfilterDigestStore(t, true)
				s.State.Coverage = []CoverageSpan{{Source: SourceNetfilter, Start: at, End: end}}
				s.State.CoverageEvictedThrough = tc.watermark
				if eventLoss {
					s.State.EvictedThrough = at
				}
				d, err := s.SplitWithNetfilter(at, end)
				if err != nil || d.Netfilter == nil {
					t.Fatal("valid source boundary refused", err)
				}
				got := d.Netfilter.Window.Coverage
				wantTruncated := tc.status != "covered" || eventLoss
				if got.Status != tc.status || !reflect.DeepEqual(got.Gaps, tc.gaps) || got.Truncated != wantTruncated || got.EvictedThrough == nil || !got.EvictedThrough.Equal(tc.watermark) {
					t.Fatalf("coverage boundary: got %+v want status=%s gaps=%+v truncated=%t", got, tc.status, tc.gaps, wantTruncated)
				}
				if d.Netfilter.Status != "available" || d.Netfilter.Window.EventRows != 0 {
					t.Fatal("source-only availability changed")
				}
			})
		}
	}
}
