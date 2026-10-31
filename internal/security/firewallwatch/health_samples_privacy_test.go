package firewallwatch

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Synthetic current-parser and saved/reloaded samples must not disclose their
// private marker through status or split health. Counters and private samples
// must survive projection; known ALF app metadata is a separate contract.
func TestHealthSamplesPublicPrivacy(t *testing.T) {
	const marker = "confidential-fixture-alpha"
	for _, message := range []string{
		"unrecognized shape /private/fixture/" + marker,
		"unrecognized shape file:///private/fixture/" + marker,
		"unrecognized shape ../relative/" + marker,
		"unrecognized shape /private/Данные/" + marker,
		"unrecognized shape /private/fixture/" + marker + "\nextra",
		"unrecognized shape opaque-" + marker,
	} {
		for _, storage := range []string{"current", "snapshot", "journal"} {
			name := message + "/" + storage
			t.Run(name, func(t *testing.T) {
				config := testConfig(t)
				s, err := OpenStore(config)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				if storage == "journal" {
					if err := s.Save(now); err != nil {
						t.Fatal(err)
					}
				}
				raw, err := json.Marshal(map[string]string{"category": "fw", "eventMessage": message})
				if err != nil {
					t.Fatal(err)
				}
				if s.State.Parser.Parse(raw) != nil {
					t.Fatal("unknown fixture became a recognized ALF item")
				}
				s.State.Parser.Parse([]byte("{"))
				if storage == "snapshot" {
					if err := s.Save(now); err != nil {
						t.Fatal(err)
					}
				}
				if storage == "journal" {
					if err := s.Checkpoint(now.Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					data, err := os.ReadFile(filepath.Join(config.StateDir, "state-journal.jsonl"))
					if err != nil || !strings.Contains(string(data), marker) {
						t.Fatal("private marker not persisted in journal fixture")
					}
				}
				if storage != "current" {
					s, err = OpenStore(config)
					if err != nil {
						t.Fatal(err)
					}
				}
				private := append([]string(nil), s.State.Parser.Samples...)
				if len(private) != 1 || !strings.Contains(private[0], marker) {
					t.Fatal("private fixture marker missing before projection")
				}
				for name, health := range map[string]map[string]any{
					"status": s.Status(),
					"split":  s.Split(now.Add(-time.Hour), now).Health,
				} {
					if health["unrecognized"] != uint64(1) || health["invalid_json"] != uint64(1) {
						t.Errorf("%s lost diagnostic counters", name)
					}
					if samples, ok := health["unrecognized_samples"].([]string); !ok || !reflect.DeepEqual(samples, []string{"unrecognized-fw-template-1"}) {
						t.Errorf("%s changed public sample type/count or ordinal contract", name)
					}
					data, err := json.Marshal(health)
					if err != nil {
						t.Fatal(err)
					}
					if strings.Contains(string(data), marker) {
						t.Errorf("%s exposes private unknown-message marker", name)
					}
				}
				if !reflect.DeepEqual(s.State.Parser.Samples, private) {
					t.Fatal("public projection changed retained private samples")
				}
			})
		}
	}
}

// Empty/null and the admitted 16-template boundary retain their wire shape,
// numeric diagnostics and order; public-slice mutation cannot edit private state.
func TestHealthSamplesProjectionCompatibility(t *testing.T) {
	full := make([]string, SampleLimit)
	for i := range full {
		full[i] = fmt.Sprintf("private template %c", 'a'+i)
	}
	for _, tc := range []struct {
		name    string
		samples []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"full", full},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := OpenStore(testConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			s.State.Parser = ALFParser{Unrecognized: 42, Invalid: 7, Samples: tc.samples}
			s.State.NettopUnrecognized = 3
			before, err := json.Marshal(s.State.Parser)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			for name, health := range map[string]map[string]any{"status": s.Status(), "split": s.Split(now.Add(-time.Hour), now).Health} {
				labels, ok := health["unrecognized_samples"].([]string)
				if !ok || len(labels) != len(tc.samples) || (labels == nil) != (tc.samples == nil) {
					t.Fatalf("%s changed nil/empty/count contract", name)
				}
				if health["unrecognized"] != uint64(45) || health["invalid_json"] != uint64(7) {
					t.Fatalf("%s changed counters", name)
				}
				for i, label := range labels {
					if label != fmt.Sprintf("unrecognized-fw-template-%d", i+1) {
						t.Fatalf("%s changed ordinal order", name)
					}
				}
				if len(labels) != 0 {
					labels[0] = "public caller mutation"
				}
			}
			after, err := json.Marshal(s.State.Parser)
			if err != nil || string(before) != string(after) {
				t.Fatal("projection or public caller changed private samples")
			}
		})
	}
}

// Recognized ALF metadata and unknown/invalid input counters remain usable;
// this control does not assert that every existing app field is path-free.
func TestHealthSamplesValidALFControl(t *testing.T) {
	var p ALFParser
	item := p.Parse([]byte(`{"category":"fw","eventMessage":"KNOWN APP FLOW: /Applications/Example.app, return known verdict: 1"}`))
	if item == nil || item.App != "/Applications/Example.app" || item.Verdict != "allow" || p.Unrecognized != 0 || p.Invalid != 0 || len(p.Samples) != 0 {
		t.Fatal("recognized ALF positive control changed")
	}
}
