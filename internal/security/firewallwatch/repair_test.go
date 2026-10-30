package firewallwatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// brokenStateDir builds a state directory as a backward wall-clock step on
// main d055484 left it: state.json with a coverage span ending before it
// starts, and a journal whose first record has an entry with last_seen
// before first_seen. Its second record is untouched. The normal reader
// refuses the directory.
func brokenStateDir(t *testing.T) (Config, []byte) {
	t.Helper()
	s, c := journalStore(t)
	at := time.Now().Round(0)
	s.BeginCoverage(at)
	observeFlush(t, s, newKey(1), at)
	if e := s.Save(at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	observeFlush(t, s, newKey(2), at.Add(2*time.Second))
	observeFlush(t, s, newKey(3), at.Add(3*time.Second))
	statePath, journalPath := filepath.Join(c.StateDir, "state.json"), filepath.Join(c.StateDir, journalFile)
	var st State
	b, _ := os.ReadFile(statePath)
	if e := json.Unmarshal(b, &st); e != nil || len(st.Coverage) == 0 {
		t.Fatalf("fixture state: %v", e)
	}
	st.Coverage[0].End = st.Coverage[0].Start.Add(-time.Second)
	b, _ = json.Marshal(st)
	if e := os.WriteFile(statePath, b, 0600); e != nil {
		t.Fatal(e)
	}
	raw, _ := os.ReadFile(journalPath)
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("fixture journal has %d records; want 2", len(lines))
	}
	var r journalRecord
	if e := json.Unmarshal(lines[0], &r); e != nil {
		t.Fatal(e)
	}
	for _, e := range r.Entries {
		e.LastSeen = e.FirstSeen.Add(-2 * time.Second)
	}
	lines[0], _ = json.Marshal(r)
	if e := os.WriteFile(journalPath, append(bytes.Join(lines, []byte("\n")), '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := OpenStore(c); e == nil {
		t.Fatal("fixture: the broken directory still opens")
	}
	// A watcher run created the lock file; the repair opens it to refuse
	// while a watcher runs.
	unlock, e := (&Store{Config: c}).Lock()
	if e != nil {
		t.Fatal(e)
	}
	unlock()
	return c, lines[1]
}

// Recovery, with a negative control: the broken directory fails to open
// before the repair; the repaired copy opens with the normal reader; the
// originals are copied byte for byte with their SHA-256; the state directory
// is not changed; the untouched journal record keeps its bytes; and every
// change is reported, an entry by key hash only.
func TestRepairMakesABrokenStateReadable(t *testing.T) {
	c, untouched := brokenStateDir(t)
	before := dirHashes(t, c.StateDir)
	brokenState, _ := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
	brokenJournal, _ := os.ReadFile(filepath.Join(c.StateDir, journalFile))
	out := filepath.Join(t.TempDir(), "repair")
	report, e := Repair(c, out)
	if e != nil {
		t.Fatal(e)
	}
	if report.BeforeOpen == "" || !report.Opens || report.OpenError != "" {
		t.Fatalf("report %+v; want a failing original and an opening repair", report)
	}
	if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
		t.Fatal("the repair changed the state directory")
	}
	for name, want := range map[string][]byte{"state.json": brokenState, journalFile: brokenJournal} {
		got, _ := os.ReadFile(filepath.Join(out, "original", name))
		sum := sha256.Sum256(want)
		if !bytes.Equal(got, want) || report.Originals[name] != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s: original copy or its hash differs", name)
		}
	}
	sums, _ := os.ReadFile(filepath.Join(out, "original", "SHA256SUMS"))
	if !strings.Contains(string(sums), report.Originals["state.json"]+"  state.json") {
		t.Fatalf("SHA256SUMS: %s", sums)
	}
	repaired := c
	repaired.StateDir = filepath.Join(out, "repaired")
	if _, e := OpenStore(repaired); e != nil {
		t.Fatalf("repaired directory: %v", e)
	}
	journal, _ := os.ReadFile(filepath.Join(repaired.StateDir, journalFile))
	if !bytes.Contains(journal, append(append([]byte("\n"), untouched...), '\n')) {
		t.Fatal("an untouched journal record lost its bytes")
	}
	checks := map[string]bool{}
	for _, ch := range report.Changes {
		checks[ch.File+" "+ch.Check] = true
		if strings.Contains(ch.Item, "app") {
			t.Fatalf("change %+v names a key", ch)
		}
	}
	if !checks["state.json "+checkSpanOrder] || !checks[journalFile+" "+checkEntryOrder] {
		t.Fatalf("changes %+v; want the span and the entry", report.Changes)
	}
}

// The repair refuses, before writing anything repaired, when the output
// exists, when it is inside the state directory, while a watcher holds the
// lock, and when a journal line in the middle is not a record (mid-file
// corruption stays refused); a refused journal leaves no repaired file.
func TestRepairRefusals(t *testing.T) {
	c, _ := brokenStateDir(t)
	exists := t.TempDir()
	if _, e := Repair(c, exists); e == nil || !strings.Contains(e.Error(), "exists") {
		t.Fatalf("existing output: %v", e)
	}
	if _, e := Repair(c, filepath.Join(c.StateDir, "repair")); e == nil || !strings.Contains(e.Error(), "outside") {
		t.Fatalf("output inside the state directory: %v", e)
	}
	unlock, e := (&Store{Config: c}).Lock()
	if e != nil {
		t.Fatal(e)
	}
	out := filepath.Join(t.TempDir(), "repair")
	if _, e := Repair(c, out); e == nil || !strings.Contains(e.Error(), "stopped") {
		t.Fatalf("watcher running: %v", e)
	}
	unlock()
	if _, e := os.Lstat(out); !os.IsNotExist(e) {
		t.Fatal("a refused repair created its output")
	}
	journalPath := filepath.Join(c.StateDir, journalFile)
	raw, _ := os.ReadFile(journalPath)
	if e := os.WriteFile(journalPath, append([]byte("garbage\n"), raw...), 0600); e != nil {
		t.Fatal(e)
	}
	out = filepath.Join(t.TempDir(), "repair")
	if _, e := Repair(c, out); e == nil || !strings.Contains(e.Error(), "not repairable") {
		t.Fatalf("mid-file garbage: %v", e)
	}
	if left, _ := os.ReadDir(filepath.Join(out, "repaired")); len(left) != 0 {
		t.Fatalf("a refused journal left %d repaired files", len(left))
	}
}

// The output is checked against the state directory as the kernel resolves
// it. Through a symlink to the state directory, through a symlink to a
// directory inside it, and (on a case-insensitive volume) through a case
// variant of its name, the repair refuses and creates nothing there. Positive
// control: a symlinked parent that resolves outside the state directory is
// accepted and the repair opens.
func TestRepairOutputCheckedAsResolved(t *testing.T) {
	c, _ := brokenStateDir(t)
	before := dirHashes(t, c.StateDir)
	sub := filepath.Join(c.StateDir, "sub")
	if e := os.Mkdir(sub, 0700); e != nil {
		t.Fatal(e)
	}
	links := t.TempDir()
	toState, toSub := filepath.Join(links, "state"), filepath.Join(links, "sub")
	for link, target := range map[string]string{toState: c.StateDir, toSub: sub} {
		if e := os.Symlink(target, link); e != nil {
			t.Fatal(e)
		}
	}
	outs := []string{filepath.Join(toState, "repair"), filepath.Join(toSub, "repair")}
	variant := filepath.Join(filepath.Dir(c.StateDir), strings.ToUpper(filepath.Base(c.StateDir)))
	a, e := os.Stat(variant)
	b, _ := os.Stat(c.StateDir)
	if e == nil && os.SameFile(a, b) {
		outs = append(outs, filepath.Join(variant, "repair"))
	} else {
		t.Log("case-sensitive volume: the case variant is not exercised")
	}
	for _, out := range outs {
		if _, e := Repair(c, out); e == nil || !strings.Contains(e.Error(), "outside") {
			t.Fatalf("%s: %v", out, e)
		}
	}
	for _, dir := range []string{c.StateDir, sub} {
		if _, e := os.Lstat(filepath.Join(dir, "repair")); !os.IsNotExist(e) {
			t.Fatalf("a refused repair created %s/repair", dir)
		}
	}
	if e := os.Remove(sub); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
		t.Fatal("a refused repair changed the state directory")
	}
	elsewhere := filepath.Join(links, "elsewhere")
	if e := os.Symlink(t.TempDir(), elsewhere); e != nil {
		t.Fatal(e)
	}
	if r, e := Repair(c, filepath.Join(elsewhere, "repair")); e != nil || !r.Opens {
		t.Fatalf("outside through a symlink: %+v %v", r, e)
	}
}

// The report lists entry changes in key order, so two repairs of the same
// state give the same report (map iteration order would otherwise vary).
func TestRepairEntriesReportInKeyOrder(t *testing.T) {
	at := time.Now().Round(0)
	broken := func() map[string]*Entry {
		m := map[string]*Entry{}
		for i := range 12 {
			m[fmt.Sprintf("key-%02d", i)] = &Entry{FirstSeen: at, WindowStart: at, LastSeen: at.Add(-time.Second), Count: 1}
		}
		return m
	}
	first := repairEntries(broken(), journalFile, 1)
	if len(first) != 12 {
		t.Fatalf("%d changes; want 12", len(first))
	}
	for range 5 {
		if again := repairEntries(broken(), journalFile, 1); !reflect.DeepEqual(first, again) {
			t.Fatalf("report order changed between runs")
		}
	}
}
