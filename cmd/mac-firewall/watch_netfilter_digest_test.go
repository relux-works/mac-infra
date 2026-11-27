package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/security/firewallwatch"
)

type digestFileWitness struct {
	bytes []byte
	mode  os.FileMode
	mtime time.Time
}

func digestFixtureFiles(t *testing.T, roots ...string) map[string]digestFileWitness {
	t.Helper()
	files := make(map[string]digestFileWitness)
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			files[path] = digestFileWitness{data, info.Mode(), info.ModTime()}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func requireDigestFilesUnchanged(t *testing.T, before map[string]digestFileWitness, roots ...string) {
	t.Helper()
	after := digestFixtureFiles(t, roots...)
	if len(after) != len(before) {
		t.Fatal("digest changed fixture file set")
	}
	for path, b := range before {
		a, ok := after[path]
		if !ok || !bytes.Equal(a.bytes, b.bytes) || a.mode != b.mode || !a.mtime.Equal(b.mtime) {
			t.Fatal("digest changed fixture file", path)
		}
	}
}

// The real CLI emits the additive section from retained state and a safe empty
// incident fixture, with collection disabled still exposing historical rows.
// The same read leaves fixture bytes, modes, mtimes and file set unchanged.
// Invalid new-section state returns a specific nonzero refusal and no JSON;
// non-split JSON remains byte-identical across that neighboring state change.
func TestWatchNetfilterDigestReadOnlyAndRefusal(t *testing.T) {
	config, c := watchConfig(t, 0)
	c.NetfilterJournalDir = filepath.Join(t.TempDir(), "incidents")
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(c.NetfilterJournalDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(c.NetfilterJournalDir, "journal.ndjson"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := firewallwatch.OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Add(-time.Minute)
	s.State.Events = []firewallwatch.Event{{TS: now, Source: firewallwatch.SourceNetfilter, App: "fixture-app", Signer: "unsigned", Verdict: "observed", RemoteClass: "internet", Bucket: "fixture-bucket", Kind: "outbound", Counts: 100, Label: "digest", Reason: "knn", Mode: "shadow"}}
	s.State.Coverage = []firewallwatch.CoverageSpan{{Start: now.Add(-time.Hour), End: now, Source: firewallwatch.SourceNetfilter}}
	if err := s.Save(now); err != nil {
		t.Fatal(err)
	}
	before := digestFixtureFiles(t, c.StateDir, c.NetfilterJournalDir)
	var out, stderr bytes.Buffer
	args := []string{"watch", "digest", "--config", config, "--json", "--since", "1h"}
	if code := run(args, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	nonSplit := append([]byte(nil), out.Bytes()...)
	out.Reset()
	stderr.Reset()
	if code := run(append(args, "--split"), &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	var document struct {
		Netfilter struct {
			Status     string `json:"status"`
			Collection string `json:"collection_status"`
			Window     struct {
				Rows int `json:"event_rows"`
			} `json:"window"`
			Alarms struct {
				Status string `json:"status"`
				Reason string `json:"reason"`
			} `json:"alarms"`
		} `json:"netfilter"`
	}
	if err := json.Unmarshal(out.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	n := document.Netfilter
	if n.Status != "available" || n.Collection != "disabled" || n.Window.Rows != 1 || n.Alarms.Status != "verified" || n.Alarms.Reason != "none" {
		t.Fatalf("CLI section: %s", out.Bytes())
	}
	requireDigestFilesUnchanged(t, before, c.StateDir, c.NetfilterJournalDir)

	// Save's original state format permits this field text. The additive wire
	// contract has a stricter enum, so the real digest route must refuse it.
	s.State.Events[0].RemoteClass = "not-a-class"
	if err := s.Save(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	before = digestFixtureFiles(t, c.StateDir, c.NetfilterJournalDir)
	out.Reset()
	stderr.Reset()
	if code := run(append(args, "--split"), &out, &stderr); code != 1 || out.Len() != 0 || !strings.Contains(stderr.String(), "netfilter digest: invalid retained state") {
		t.Fatalf("invalid section not refused: code=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	requireDigestFilesUnchanged(t, before, c.StateDir, c.NetfilterJournalDir)
	out.Reset()
	stderr.Reset()
	if code := run(args, &out, &stderr); code != 0 || !bytes.Equal(out.Bytes(), nonSplit) {
		t.Fatalf("non-split changed: code=%d stdout=%q stderr=%q", code, out.String(), stderr.String())
	}
	requireDigestFilesUnchanged(t, before, c.StateDir, c.NetfilterJournalDir)
}
