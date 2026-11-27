package firewallwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// These twelve independently specified source-event witnesses pass through
// the production additive method. They prove the retained analytics against
// literal expectations, including Counts-vs-rows and policy precedence. They
// do not claim coverage/journal fixture materialization or room privacy checks;
// the consumer exercises all forty-one wire cases and its separate output plant.
func TestNetfilterDigestLiteralEventWitnesses(t *testing.T) {
	raw, err := os.ReadFile("testdata/netfilter-digest-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := decodeNetfilterLiteralFixtures(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixtures) != 41 {
		t.Fatalf("fixture set changed: %d", len(fixtures))
	}
	witnesses := 0
	for _, fixture := range fixtures {
		if len(fixture.ProducerWitness) == 0 {
			continue
		}
		var witness struct {
			Events []Event `json:"retained_source_events"`
		}
		if err := json.Unmarshal(fixture.ProducerWitness, &witness); err != nil {
			t.Fatal(err)
		}
		if witness.Events == nil {
			continue
		}
		witnesses++
		t.Run(fixture.ID, func(t *testing.T) {
			want, err := decodeNetfilterLiteralSection(fixture.Netfilter)
			if err != nil {
				t.Fatal(err)
			}
			s := netfilterDigestStore(t, true)
			s.State.Events = witness.Events
			digest, err := s.SplitWithNetfilter(want.Window.Since, want.Window.AsOf)
			if err != nil {
				t.Fatal(err)
			}
			got := digest.Netfilter
			if got.Status != "available" || got.Window.EventRows != want.Window.EventRows || got.Window.OutboundEventRows != want.Window.OutboundEventRows || got.Window.UnknownDirectionEventRows != want.Window.UnknownDirectionEventRows || !reflect.DeepEqual(got.Window.FirstTS, want.Window.FirstTS) || !reflect.DeepEqual(got.Window.LastTS, want.Window.LastTS) {
				t.Fatalf("retained counts or timestamps: %+v want %+v", got.Window, want.Window)
			}
			if !reflect.DeepEqual(got.PerApp, want.PerApp) || !reflect.DeepEqual(got.Destinations, want.Destinations) || !reflect.DeepEqual(got.UnsignedOutbound, want.UnsignedOutbound) || !reflect.DeepEqual(got.OddPorts, want.OddPorts) {
				t.Fatalf("retained analytics mismatch: got %+v want %+v", got, want)
			}
			if fixture.ID == "deny-not-exempt" && len(digest.RealDeny) != 1 {
				t.Fatal("existing deny lost its legacy bucket")
			}
		})
	}
	if witnesses != 12 {
		t.Fatalf("source-event witnesses applied=%d, want12", witnesses)
	}
}

// The four explicit source-coverage witnesses exercise the complete production
// section against literal expectations. A safe empty existing incident file is
// an independent fixture, not inferred from the reducer's output. The invalid
// legacy-status neighbor must not be reproduced from the same recorded spans.
func TestNetfilterDigestLiteralCoverageWitnesses(t *testing.T) {
	raw, err := os.ReadFile("testdata/netfilter-digest-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := decodeNetfilterLiteralFixtures(raw)
	if err != nil {
		t.Fatal(err)
	}
	var legacyValid, legacyInvalid *netfilterDigest
	witnesses := 0
	for _, fixture := range fixtures {
		if fixture.ID == "legacy-span-wrong-unavailable-status" {
			legacyInvalid, err = decodeNetfilterLiteralSection(fixture.Netfilter)
			if err != nil {
				t.Fatal(err)
			}
		}
		switch fixture.ID {
		case "available-empty", "enabled-absent-history", "legacy-source-coverage", "two-source-spans-three-gaps":
		default:
			continue
		}
		witnesses++
		t.Run(fixture.ID, func(t *testing.T) {
			want, err := decodeNetfilterLiteralSection(fixture.Netfilter)
			if err != nil {
				t.Fatal(err)
			}
			var witness struct {
				Enabled  bool           `json:"source_enabled"`
				Coverage []CoverageSpan `json:"coverage"`
			}
			if err := json.Unmarshal(fixture.ProducerWitness, &witness); err != nil {
				t.Fatal(err)
			}
			s := netfilterDigestStore(t, witness.Enabled)
			s.State.Coverage = witness.Coverage
			if err := os.Mkdir(s.Config.NetfilterJournalDir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(s.Config.NetfilterJournalDir, "journal.ndjson")
			if err := os.WriteFile(file, nil, 0600); err != nil {
				t.Fatal(err)
			}
			digest, err := s.SplitWithNetfilter(want.Window.Since, want.Window.AsOf)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(digest.Netfilter, want) {
				t.Fatalf("whole literal section: got %+v want %+v", digest.Netfilter, want)
			}
			if fixture.ID == "legacy-source-coverage" {
				legacyValid = digest.Netfilter
			}
			if data, err := os.ReadFile(file); err != nil || len(data) != 0 {
				t.Fatal("producer changed incident fixture", err)
			}
		})
	}
	if witnesses != 4 || legacyValid == nil || legacyInvalid == nil {
		t.Fatal("literal source coverage controls not all applied")
	}
	if reflect.DeepEqual(legacyValid, legacyInvalid) || legacyValid.Status != "available" || legacyInvalid.Status != "unavailable" {
		t.Fatal("producer reproduced invalid legacy coverage status")
	}
}

// The independently supplied literal entry, including its recorded digest,
// must pass the actual read-only verifier before its one alarm is projected.
// A separate fully covered synthetic source span supplies availability; it
// does not stand in for journal verification or a live journal qualification.
func TestNetfilterDigestLiteralJournalWitness(t *testing.T) {
	raw, err := os.ReadFile("testdata/netfilter-digest-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := decodeNetfilterLiteralFixtures(raw)
	if err != nil {
		t.Fatal(err)
	}
	applied := 0
	for _, fixture := range fixtures {
		if fixture.ID != "journal-verified-one-alarm" {
			continue
		}
		applied++
		var witness struct {
			JournalRaw string `json:"journal_raw"`
		}
		if err := json.Unmarshal(fixture.ProducerWitness, &witness); err != nil {
			t.Fatal(err)
		}
		if witness.JournalRaw == "" {
			t.Fatal("literal journal witness absent")
		}
		want, err := decodeNetfilterLiteralSection(fixture.Netfilter)
		if err != nil {
			t.Fatal(err)
		}
		s := netfilterDigestStore(t, true)
		s.State.Coverage = []CoverageSpan{{Start: want.Window.Since, End: want.Window.AsOf, Source: SourceNetfilter}}
		if err := os.Mkdir(s.Config.NetfilterJournalDir, 0700); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(s.Config.NetfilterJournalDir, "journal.ndjson")
		if err := os.WriteFile(file, []byte(witness.JournalRaw), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := s.SplitWithNetfilter(want.Window.Since, want.Window.AsOf)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Netfilter, want) {
			t.Fatalf("literal journal section: got %+v want %+v", got.Netfilter, want)
		}
		if data, err := os.ReadFile(file); err != nil || string(data) != witness.JournalRaw {
			t.Fatal("literal journal changed", err)
		}
	}
	if applied != 1 {
		t.Fatalf("literal journal witness applied=%d", applied)
	}
}

// A malformed unselected wire case must not stop selected valid producer
// witnesses. Selecting that malformed case still refuses its concrete typed
// error with no partial section; missing/null selected sections also refuse.
// This checks fixture decoding only, not the complete wire semantic validator.
func TestNetfilterDigestFixtureSelection(t *testing.T) {
	raw, err := os.ReadFile("testdata/netfilter-digest-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := decodeNetfilterLiteralFixtures(raw)
	if err != nil || len(fixtures) != 41 {
		t.Fatalf("raw envelope: count=%d err=%v", len(fixtures), err)
	}
	applied := 0
	for _, fixture := range fixtures {
		switch fixture.ID {
		case "available-empty":
			got, err := decodeNetfilterLiteralSection(fixture.Netfilter)
			if err != nil || got == nil || got.Status != "available" || got.Window.EventRows != 0 {
				t.Fatalf("valid selected section: %+v %v", got, err)
			}
			applied++
		case "boolean-count", "fractional-counter":
			got, err := decodeNetfilterLiteralSection(fixture.Netfilter)
			var typed *json.UnmarshalTypeError
			if got != nil || !errors.As(err, &typed) || typed.Type.Kind() != reflect.Int || typed.Field != "window.event_rows" {
				t.Fatalf("selected %s must refuse its integer field with no partial result: %+v %v", fixture.ID, got, err)
			}
			applied++
		}
	}
	if applied != 3 {
		t.Fatalf("selection controls applied=%d, want3", applied)
	}
	for _, raw := range []json.RawMessage{nil, json.RawMessage("null")} {
		if got, err := decodeNetfilterLiteralSection(raw); got != nil || err == nil {
			t.Fatalf("absent section accepted: %+v %v", got, err)
		}
	}
	if got, err := decodeNetfilterLiteralFixtures([]byte(`{"cases":[`)); got != nil || err == nil {
		t.Fatalf("malformed envelope accepted: %+v %v", got, err)
	}
}

// Preserve unrelated invalid wire cases as raw data until a witness is selected.
// This typed decoder is a fixture materializer, not the wire admission boundary.
type netfilterLiteralFixture struct {
	ID              string          `json:"id"`
	ProducerWitness json.RawMessage `json:"producer_witness"`
	Netfilter       json.RawMessage `json:"netfilter"`
}

func decodeNetfilterLiteralFixtures(raw []byte) ([]netfilterLiteralFixture, error) {
	var envelope struct {
		Cases []netfilterLiteralFixture `json:"cases"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	return envelope.Cases, nil
}

func decodeNetfilterLiteralSection(raw json.RawMessage) (*netfilterDigest, error) {
	var section *netfilterDigest
	if err := json.Unmarshal(raw, &section); err != nil {
		return nil, err
	}
	if section == nil {
		return nil, fmt.Errorf("missing literal netfilter section")
	}
	return section, nil
}
