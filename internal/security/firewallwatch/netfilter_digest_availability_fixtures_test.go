package firewallwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// These eight supported literal sections exercise the complete producer output,
// independent legacy projection, and unchanged fixture journal surfaces. Each
// journal refusal has a nearby real readable positive control. The unreadable
// case requires an unprivileged caller and verifies permission denial explicitly.
func TestNetfilterDigestLiteralAvailabilityAndJournalWitnesses(t *testing.T) {
	raw, err := os.ReadFile("testdata/netfilter-digest-wire-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := decodeNetfilterLiteralFixtures(raw)
	if err != nil || len(fixtures) != 41 {
		t.Fatalf("literal envelope: count=%d err=%v", len(fixtures), err)
	}
	byID := make(map[string]netfilterLiteralFixture, len(fixtures))
	for _, fixture := range fixtures {
		if _, exists := byID[fixture.ID]; exists {
			t.Fatalf("duplicate fixture id %q", fixture.ID)
		}
		byID[fixture.ID] = fixture
	}
	section := func(t *testing.T, id string) *netfilterDigest {
		t.Helper()
		fixture, ok := byID[id]
		if !ok {
			t.Fatalf("missing literal fixture %q", id)
		}
		want, err := decodeNetfilterLiteralSection(fixture.Netfilter)
		if err != nil {
			t.Fatal(err)
		}
		return want
	}
	var validJournal struct {
		Raw string `json:"journal_raw"`
	}
	if err := json.Unmarshal(byID["journal-verified-one-alarm"].ProducerWitness, &validJournal); err != nil || validJournal.Raw == "" {
		t.Fatalf("literal verified journal: %v", err)
	}
	since := time.Date(2026, 10, 31, 8, 0, 0, 0, time.UTC)
	asOf := since.Add(time.Hour)
	for _, tc := range []struct {
		id      string
		enabled bool
		covered bool
	}{
		{"disabled-current-historical-covered", false, true},
		{"disabled-no-history", false, false},
		{"journal-not_found", true, true},
		{"journal-unreadable", true, true},
		{"journal-unsafe_path", true, true},
		{"journal-malformed", true, true},
		{"journal-chain_invalid", true, true},
		{"netfilter-stall-alf-covered", true, true},
	} {
		t.Run(tc.id, func(t *testing.T) {
			s := netfilterDigestStore(t, tc.enabled)
			if tc.covered {
				s.State.Coverage = []CoverageSpan{{Start: since, End: asOf, Source: SourceNetfilter}}
			}
			if tc.id == "netfilter-stall-alf-covered" {
				s.State.Coverage = []CoverageSpan{
					{Start: since, End: asOf},
					{Start: since.Add(-time.Nanosecond), End: since, Source: SourceNetfilter, StallAfter: &CoverageStall{From: since, To: since.Add(time.Second)}},
					{Start: since.Add(time.Second), End: asOf, Source: SourceNetfilter},
				}
			}
			journalDir := s.Config.NetfilterJournalDir
			realDir := journalDir
			var blockedParent string
			if tc.id == "journal-unreadable" {
				blockedParent = filepath.Join(t.TempDir(), "restricted")
				if err := os.Mkdir(blockedParent, 0700); err != nil {
					t.Fatal(err)
				}
				journalDir = filepath.Join(blockedParent, "incidents")
				realDir = journalDir
				s.Config.NetfilterJournalDir = journalDir
			}
			if tc.id == "journal-unsafe_path" {
				realDir = filepath.Join(filepath.Dir(journalDir), "safe-target")
			}
			data := []byte{}
			var err error
			switch tc.id {
			case "journal-malformed":
				data = []byte("{\n")
			case "journal-chain_invalid":
				var entry map[string]json.RawMessage
				if err := json.Unmarshal([]byte(validJournal.Raw), &entry); err != nil || string(entry["kind"]) != `"alarm"` {
					t.Fatalf("literal tamper input: %v", err)
				}
				entry["kind"] = json.RawMessage(`"warning"`)
				data, err = json.Marshal(entry)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, '\n')
				if bytes.Equal(data, []byte(validJournal.Raw)) {
					t.Fatal("journal tamper plant did not apply")
				}
			}
			if tc.id != "journal-not_found" {
				if err := os.Mkdir(realDir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(realDir, "journal.ndjson"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.id == "journal-unsafe_path" {
				if err := os.Symlink(realDir, journalDir); err != nil {
					t.Fatal(err)
				}
			}
			assertOutput := func(want *netfilterDigest) {
				t.Helper()
				stateBefore, err := json.Marshal(s.State)
				if err != nil {
					t.Fatal(err)
				}
				legacyBefore, err := json.Marshal(s.Split(since, asOf))
				if err != nil {
					t.Fatal(err)
				}
				got, err := s.SplitWithNetfilter(since, asOf)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got.Netfilter, want) {
					t.Fatalf("whole literal section: got %+v want %+v", got.Netfilter, want)
				}
				got.Netfilter = nil
				legacyAfter, err := json.Marshal(got)
				if err != nil || !bytes.Equal(legacyBefore, legacyAfter) {
					t.Fatal("legacy projection changed", err)
				}
				stateAfter, err := json.Marshal(s.State)
				if err != nil || !bytes.Equal(stateBefore, stateAfter) {
					t.Fatal("producer changed retained source state", err)
				}
			}
			before := snapshotNetfilterLiteralJournal(t, journalDir, realDir)
			blocked := false
			restore := func() {
				if blocked {
					if err := os.Chmod(blockedParent, 0700); err != nil {
						t.Error(err)
						return
					}
					blocked = false
				}
			}
			t.Cleanup(restore)
			if blockedParent != "" {
				if err := os.Chmod(blockedParent, 0000); err != nil {
					t.Fatal(err)
				}
				blocked = true
				if _, err := os.Stat(journalDir); !errors.Is(err, os.ErrPermission) {
					t.Fatalf("unprivileged unreadable control requires permission denial, got %v", err)
				}
			}
			assertOutput(section(t, tc.id))
			restore()
			after := snapshotNetfilterLiteralJournal(t, journalDir, realDir)
			assertNetfilterLiteralJournalUnchanged(t, before, after)
			if tc.id == "netfilter-stall-alf-covered" && (len(s.Split(since, asOf).Window.CoverageGaps) != 0 || s.Split(since, asOf).Window.Truncated) {
				t.Fatal("netfilter stall altered covered ALF window")
			}
			if len(tc.id) >= len("journal-") && tc.id[:len("journal-")] == "journal-" {
				if tc.id == "journal-not_found" {
					if err := os.Mkdir(realDir, 0700); err != nil {
						t.Fatal(err)
					}
				}
				if tc.id == "journal-unsafe_path" {
					s.Config.NetfilterJournalDir = realDir
					journalDir = realDir
				}
				positive := "available-empty"
				data = []byte{}
				if tc.id == "journal-chain_invalid" {
					positive = "journal-verified-one-alarm"
					data = []byte(validJournal.Raw)
				}
				if err := os.WriteFile(filepath.Join(realDir, "journal.ndjson"), data, 0600); err != nil {
					t.Fatal(err)
				}
				before = snapshotNetfilterLiteralJournal(t, journalDir, realDir)
				assertOutput(section(t, positive))
				after = snapshotNetfilterLiteralJournal(t, journalDir, realDir)
				assertNetfilterLiteralJournalUnchanged(t, before, after)
			}
		})
	}
}

type netfilterLiteralJournalSnapshot struct {
	parentNames []string
	pathInfo    os.FileInfo
	dirInfo     os.FileInfo
	fileInfo    os.FileInfo
	linkTarget  string
	data        []byte
}

func snapshotNetfilterLiteralJournal(t *testing.T, dir, realDir string) netfilterLiteralJournalSnapshot {
	t.Helper()
	var out netfilterLiteralJournalSnapshot
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		out.parentNames = append(out.parentNames, entry.Name())
	}
	info := func(path string) os.FileInfo {
		t.Helper()
		st, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return st
	}
	out.pathInfo, out.dirInfo = info(dir), info(realDir)
	if out.pathInfo != nil && out.pathInfo.Mode()&os.ModeSymlink != 0 {
		out.linkTarget, err = os.Readlink(dir)
		if err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(realDir, "journal.ndjson")
	out.fileInfo = info(file)
	if out.fileInfo != nil {
		out.data, err = os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

// Snapshot comparisons cover fixture membership, identity, modes, size, mtime
// and bytes around the production call; they are bounded readback evidence.
func assertNetfilterLiteralJournalUnchanged(t *testing.T, before, after netfilterLiteralJournalSnapshot) {
	t.Helper()
	if !reflect.DeepEqual(before.parentNames, after.parentNames) || before.linkTarget != after.linkTarget || !bytes.Equal(before.data, after.data) {
		t.Fatal("producer changed journal fixture membership, link or bytes")
	}
	for _, pair := range [][2]os.FileInfo{{before.pathInfo, after.pathInfo}, {before.dirInfo, after.dirInfo}, {before.fileInfo, after.fileInfo}} {
		if pair[0] == nil || pair[1] == nil {
			if pair[0] != nil || pair[1] != nil {
				t.Fatal("producer created or removed journal fixture path")
			}
			continue
		}
		if !os.SameFile(pair[0], pair[1]) || pair[0].Mode() != pair[1].Mode() || pair[0].Size() != pair[1].Size() || !pair[0].ModTime().Equal(pair[1].ModTime()) {
			t.Fatal("producer changed journal fixture identity, metadata or permissions")
		}
	}
}
