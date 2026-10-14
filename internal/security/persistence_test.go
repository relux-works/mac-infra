package security

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A visible file change, addition and deletion are distinguished; denied current
// coverage suppresses false deletion and explicitly marks the source unknown.
func TestPersistenceDriftAndLostCoverage(t *testing.T) {
	dir := fixtureDir(t)
	p := filepath.Join(dir, "test.plist")
	os.WriteFile(p, []byte("one"), 0600)
	old := snapshotFiles(context.Background(), []source{{"fixture", dir}})
	os.WriteFile(p, []byte("two"), 0600)
	os.WriteFile(filepath.Join(dir, "added"), []byte("data"), 0600)
	current := snapshotFiles(context.Background(), []source{{"fixture", dir}})
	d, err := Compare(old, current)
	if err != nil || len(d.Changed) != 1 || len(d.Added) != 1 || len(d.Removed) != 0 {
		t.Fatalf("drift: %+v %v", d, err)
	}
	os.Remove(p)
	current = snapshotFiles(context.Background(), []source{{"fixture", dir}})
	d, _ = Compare(old, current)
	if len(d.Removed) != 1 {
		t.Fatal(d)
	}
	current.Coverage[0].Status = "unavailable"
	d, _ = Compare(old, current)
	if len(d.Removed) != 0 || len(d.Unknown) != 1 {
		t.Fatal(d)
	}
}

// Baselines round-trip privately and refuse overwriting an existing file or a
// symlink. Raw file contents never enter the baseline document.
func TestBaselinePrivateNoOverwriteAndValidation(t *testing.T) {
	dir := fixtureDir(t)
	os.WriteFile(filepath.Join(dir, "input"), []byte("secret-test-marker"), 0600)
	s := snapshotFiles(context.Background(), []source{{"fixture", dir}})
	path := filepath.Join(dir, "baseline.json")
	if err := SaveBaseline(path, s); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "secret-test-marker") {
		t.Fatal("source content leaked")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	loaded, err := LoadBaseline(path)
	if err != nil || len(loaded.Entries) != 1 {
		t.Fatal(err)
	}
	if SaveBaseline(path, s) == nil {
		t.Fatal("overwrote baseline")
	}
	after, _ := os.ReadFile(path)
	if string(data) != string(after) {
		t.Fatal("existing changed")
	}
	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	if SaveBaseline(link, s) == nil {
		t.Fatal("followed destination symlink")
	}
	if _, err := LoadBaseline(link); err == nil {
		t.Fatal("read symlink")
	}
	for _, bad := range []string{`{"schema":2,"entries":[],"coverage":[]}`, `{"schema":1,"entries":[],"coverage":[]} {}`, `{"schema":1,"entries":[],"coverage":[],"extra":true}`} {
		os.WriteFile(filepath.Join(dir, "bad"), []byte(bad), 0600)
		if _, err := LoadBaseline(filepath.Join(dir, "bad")); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	invalid := s
	invalid.Entries = append(append([]Entry{}, s.Entries...), s.Entries[0])
	if _, err := Compare(invalid, s); err == nil {
		t.Fatal("duplicate entry accepted")
	}
}

// A planted symlink cannot cause persistence collection to read another file;
// the scan remains explicitly partial, alongside a valid ordinary-file control.
func TestPersistenceSymlinkAndCancellation(t *testing.T) {
	dir := fixtureDir(t)
	os.WriteFile(filepath.Join(dir, "plain"), []byte("visible"), 0600)
	os.Symlink(filepath.Join(dir, "plain"), filepath.Join(dir, "link"))
	s := snapshotFiles(context.Background(), []source{{"fixture", dir}})
	if len(s.Entries) != 1 || s.Coverage[0].Status != "partial" {
		t.Fatal(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s = snapshotFiles(ctx, []source{{"fixture", dir}})
	if s.Coverage[0].Status == "ok" {
		t.Fatal("cancelled scan claims complete")
	}
}

// Duplicate names, including escaped aliases, and missing/null mode must not
// make ambiguous baseline evidence look like an ordinary zero-mode entry.
func TestBaselineRejectsAmbiguousMembers(t *testing.T) {
	dir := fixtureDir(t)
	p := filepath.Join(dir, "bad.json")
	hash := strings.Repeat("a", 64)
	for _, bad := range []string{
		`{"schema":1,"schema":1,"entries":[],"coverage":[]}`,
		`{"schema":1,"sc\u0068ema":1,"entries":[],"coverage":[]}`,
		`{"schema":1,"entries":[{"source":"x","path":"p","sha256":"` + hash + `"}],"coverage":[{"source":"x","status":"ok"}]}`,
		`{"schema":1,"entries":[{"source":"x","path":"p","sha256":"` + hash + `","mode":null}],"coverage":[{"source":"x","status":"ok"}]}`,
	} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, err := LoadBaseline(p); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// An absent source below a symlink is unknown, not a trustworthy empty source;
// a legitimate absent source beside it remains an ordinary empty control.
func TestMissingSourceUnsafeAncestor(t *testing.T) {
	dir := fixtureDir(t)
	target := fixtureDir(t)
	os.Symlink(target, filepath.Join(dir, "link"))
	unsafe := snapshotFiles(context.Background(), []source{{"x", filepath.Join(dir, "link/missing")}})
	safe := snapshotFiles(context.Background(), []source{{"x", filepath.Join(dir, "missing")}})
	if unsafe.Coverage[0].Status == "ok" || safe.Coverage[0].Status != "ok" {
		t.Fatalf("unsafe %v safe %v", unsafe, safe)
	}
	s := Snapshot{Schema: 1, Entries: []Entry{}, Coverage: []Coverage{{"x", "ok", ""}}}
	p := filepath.Join(target, "baseline.json")
	SaveBaseline(p, s)
	if _, err := LoadBaseline(filepath.Join(dir, "link/baseline.json")); err == nil {
		t.Fatal("baseline read through symlink parent")
	}
}

// Oversized directories stop at the scan entry bound and report partial rather
// than silently dropping records while claiming a complete inventory.
func TestPersistenceEntryBound(t *testing.T) {
	if testing.Short() {
		t.Skip("bounded directory fixture")
	}
	dir := fixtureDir(t)
	for i := 0; i < maxEntries+2; i++ {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%05d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	s := snapshotFiles(context.Background(), []source{{"x", dir}})
	if len(s.Entries) > maxEntries || s.Coverage[0].Status != "partial" {
		t.Fatal(len(s.Entries), s.Coverage)
	}
}

// Case aliases cannot override the exact closed schema or turn partial coverage
// into complete coverage; a correctly spelled adjacent snapshot round-trips.
func TestBaselineRejectsCaseAliases(t *testing.T) {
	dir := fixtureDir(t)
	p := filepath.Join(dir, "baseline.json")
	for _, bad := range []string{`{"schema":2,"SCHEMA":1,"entries":[],"coverage":[]}`, `{"schema":1,"entries":[],"coverage":[{"source":"x","status":"partial","STATUS":"ok"}]}`} {
		os.WriteFile(p, []byte(bad), 0600)
		if _, err := LoadBaseline(p); err == nil {
			t.Fatal("case alias accepted")
		}
	}
	os.WriteFile(p, []byte(`{"schema":1,"entries":[],"coverage":[{"source":"x","status":"ok"}]}`), 0600)
	if _, err := LoadBaseline(p); err != nil {
		t.Fatal(err)
	}
}
