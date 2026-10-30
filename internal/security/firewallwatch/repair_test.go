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
// is not changed; the untouched journal record keeps its bytes; exactly the
// broken span and entry are reported, and no key appears in the report.
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
	// The fixture broke exactly one span in state.json and one entry in the
	// first journal record.
	var got []string
	for _, ch := range report.Changes {
		got = append(got, fmt.Sprintf("%s %d %s %s", ch.File, ch.Seq, ch.Check, ch.Field))
	}
	var first journalRecord
	if e := json.Unmarshal(bytes.SplitN(brokenJournal, []byte("\n"), 2)[0], &first); e != nil || len(first.Entries) != 1 {
		t.Fatalf("fixture record: %v", e)
	}
	want := []string{"state.json 0 " + checkSpanOrder + " end", fmt.Sprintf("%s %d %s last_seen", journalFile, first.Seq, checkEntryOrder)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changes %q; want %q", got, want)
	}
	reportJSON, _ := json.Marshal(report)
	var st State
	if e := json.Unmarshal(brokenState, &st); e != nil {
		t.Fatal(e)
	}
	for k := range first.Entries {
		st.Entries[k] = nil
	}
	for k := range st.Entries {
		// Keys hold characters JSON escapes: look for the encoded form.
		encoded, _ := json.Marshal(k)
		if bytes.Contains(reportJSON, encoded[1:len(encoded)-1]) {
			t.Fatalf("the report names key %q", k)
		}
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

// The repair applies the reader's tail rule (replayJournal). A final segment
// without a newline is ignored whatever it holds, even a decodable record or
// valid JSON that is not one; with none, a last complete line that is not
// valid JSON is a torn write. Each is kept byte for byte, reported as a torn
// tail, not counted as a record, and the repaired directory opens. Negative
// control: a last complete line that is valid JSON but not a record is
// corruption to the reader, so the repair refuses it.
func TestRepairJournalTailMatchesReader(t *testing.T) {
	cases := []struct {
		name, tail string
		refused    bool
	}{
		{"incomplete record", `{"seq":3,"type":"delta"}`, false},
		{"incomplete record with reversed times", `{"seq":3,"type":"delta","entries":{"k":{"first_seen":"2026-10-30T06:00:00Z","last_seen":"2026-10-30T05:00:00Z","count":1,"window_start":"2026-10-30T06:00:00Z","denies":0,"spike_emitted":false}}}`, false},
		{"incomplete non-record JSON", `{"seq":"x"}`, false},
		{"incomplete array", `[]`, false},
		{"incomplete garbage", `{"seq":3,"ty`, false},
		{"complete garbage", "garbage\n", false},
		{"complete blank line", "\n", false},
		{"complete non-record JSON", `{"seq":"x"}` + "\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := brokenStateDir(t)
			journalPath := filepath.Join(c.StateDir, journalFile)
			appendRaw(t, journalPath, tc.tail)
			out := filepath.Join(t.TempDir(), "repair")
			report, e := Repair(c, out)
			if tc.refused {
				if e == nil || !strings.Contains(e.Error(), "not repairable") {
					t.Fatalf("want a refusal, got %v", e)
				}
				return
			}
			if e != nil || !report.Opens || !report.TornTail || report.Records != 2 {
				t.Fatalf("report %+v, %v", report, e)
			}
			for _, ch := range report.Changes {
				if ch.Seq == 3 {
					t.Fatalf("a change in the ignored tail: %+v", ch)
				}
			}
			got, _ := os.ReadFile(filepath.Join(out, "repaired", journalFile))
			if !bytes.HasSuffix(got, []byte(tc.tail)) {
				t.Fatalf("tail not kept: %q", got[max(0, len(got)-40):])
			}
		})
	}
}

// Decoding is not enough to be a record: a line the reader refuses as not a
// record of this journal (null, another type, a seq out of order) is refused
// before anything repaired is written. The plain broken directory repairs
// (TestRepairMakesABrokenStateReadable) is the positive control.
func TestRepairRefusesNonRecords(t *testing.T) {
	for name, edit := range map[string]func(lines [][]byte) [][]byte{
		"null first":   func(l [][]byte) [][]byte { return append([][]byte{[]byte("null")}, l...) },
		"null between": func(l [][]byte) [][]byte { return [][]byte{l[0], []byte("null"), l[1]} },
		"other type": func(l [][]byte) [][]byte {
			return [][]byte{l[0], bytes.Replace(l[1], []byte(`"type":"delta"`), []byte(`"type":"other"`), 1)}
		},
		"seq gap": func(l [][]byte) [][]byte { return [][]byte{l[1], l[0]} },
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := brokenStateDir(t)
			path := filepath.Join(c.StateDir, journalFile)
			raw, _ := os.ReadFile(path)
			lines := edit(bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n")))
			if e := os.WriteFile(path, append(bytes.Join(lines, []byte("\n")), '\n'), 0600); e != nil {
				t.Fatal(e)
			}
			out := filepath.Join(t.TempDir(), "repair")
			if _, e := Repair(c, out); e == nil || !strings.Contains(e.Error(), "not repairable") {
				t.Fatalf("want a refusal, got %v", e)
			}
			if left, _ := os.ReadDir(filepath.Join(out, "repaired")); len(left) != 0 {
				t.Fatalf("%d repaired files written", len(left))
			}
		})
	}
}

// A watcher start on the installed repair records the refusal marker the
// install leaves in place and saves; the repair checks that start on a
// disposable copy that includes the marker. With a max_state_bytes the
// repaired files fit but the startup save (the journal folded in, the refusal
// added) does not, the copy opens but does not start, and the report says so
// with the error. The marker is kept among the
// originals with its hash, the check's copy is removed and the state
// directory is unchanged. Positive control: with room for the startup save,
// the same state starts.
func TestRepairChecksStartWithMarker(t *testing.T) {
	for _, tight := range []bool{true, false} {
		c, _ := brokenStateDir(t)
		marker, _ := json.Marshal(refusalMarkerFile{At: time.Now().Round(0), Field: checkEntryOrder, Kind: refusalKindJournal})
		if e := os.WriteFile(filepath.Join(c.StateDir, refusalMarker), marker, 0600); e != nil {
			t.Fatal(e)
		}
		if tight {
			st, _ := os.Stat(filepath.Join(c.StateDir, "state.json"))
			j, _ := os.Stat(filepath.Join(c.StateDir, journalFile))
			c.MaxStateBytes = max(st.Size(), j.Size()) + 64
		}
		before := dirHashes(t, c.StateDir)
		out := filepath.Join(t.TempDir(), "repair")
		report, e := Repair(c, out)
		if e != nil || !report.Opens {
			t.Fatalf("tight=%t: %+v %v", tight, report, e)
		}
		if tight && (report.Starts || !strings.Contains(report.StartError, "max_state_bytes")) {
			t.Fatalf("tight: %+v", report)
		}
		if !tight && (!report.Starts || report.StartError != "") {
			t.Fatalf("control: %+v", report)
		}
		got, _ := os.ReadFile(filepath.Join(out, "original", refusalMarker))
		sum := sha256.Sum256(marker)
		if !bytes.Equal(got, marker) || report.Originals[refusalMarker] != hex.EncodeToString(sum[:]) {
			t.Fatalf("tight=%t: marker not kept among the originals", tight)
		}
		if _, e := os.Lstat(filepath.Join(out, "startup-check")); !os.IsNotExist(e) {
			t.Fatalf("tight=%t: the start check's copy is left: %v", tight, e)
		}
		if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
			t.Fatalf("tight=%t: the state directory changed", tight)
		}
	}
}

// Repaired spans never count as covered a time that a recorded stall marked
// unavailable, and keep their start. For a stall beginning before the span,
// at its start, inside it, at its end and after it: the repaired span passes
// the reader's stall check, its end is no later than the original end nor
// than the stall's start (or the span's start if the stall began earlier),
// and the stall keeps its end.
func TestRepairSpansKeepStallsUnavailable(t *testing.T) {
	at := time.Date(2026, 10, 30, 6, 0, 0, 0, time.UTC)
	for _, from := range []time.Duration{-time.Second, 0, time.Second, 2 * time.Second, 3 * time.Second} {
		sp := CoverageSpan{Start: at, End: at.Add(2 * time.Second), StallAfter: &CoverageStall{From: at.Add(from), To: at.Add(4 * time.Second)}}
		orig := sp
		origStall := *sp.StallAfter
		spans := []CoverageSpan{sp}
		repairSpans(spans, "state.json", 0, nil)
		got := spans[0]
		limit := origStall.From
		if limit.Before(orig.Start) {
			limit = orig.Start
		}
		if !got.Start.Equal(orig.Start) || got.End.After(orig.End) || (origStall.From.Before(orig.End) && got.End.After(limit)) {
			t.Fatalf("stall from %v: span %v-%v", from, got.Start, got.End)
		}
		if !got.StallAfter.From.Equal(got.End) || !got.StallAfter.To.Equal(origStall.To) {
			t.Fatalf("stall from %v: stall %v-%v, span end %v", from, got.StallAfter.From, got.StallAfter.To, got.End)
		}
	}
}

// A journal whose records are contiguous but whose first record after the
// snapshot does not follow the snapshot's journal_seq (or 1, without a
// snapshot) is refused before anything repaired is written, as the reader
// refuses it.
func TestRepairRefusesSeqNotFollowingSnapshot(t *testing.T) {
	for _, withSnapshot := range []bool{true, false} {
		c, _ := brokenStateDir(t)
		path := filepath.Join(c.StateDir, journalFile)
		raw, _ := os.ReadFile(path)
		var out [][]byte
		for _, line := range bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n")) {
			var r journalRecord
			if e := json.Unmarshal(line, &r); e != nil {
				t.Fatal(e)
			}
			r.Seq += 10
			b, _ := json.Marshal(r)
			out = append(out, b)
		}
		if e := os.WriteFile(path, append(bytes.Join(out, []byte("\n")), '\n'), 0600); e != nil {
			t.Fatal(e)
		}
		if !withSnapshot {
			if e := os.Remove(filepath.Join(c.StateDir, "state.json")); e != nil {
				t.Fatal(e)
			}
		}
		dir := filepath.Join(t.TempDir(), "repair")
		if _, e := Repair(c, dir); e == nil || !strings.Contains(e.Error(), "does not follow the snapshot") {
			t.Fatalf("snapshot=%t: want a refusal, got %v", withSnapshot, e)
		}
		if left, _ := os.ReadDir(filepath.Join(dir, "repaired")); len(left) != 0 {
			t.Fatalf("snapshot=%t: %d repaired files written", withSnapshot, len(left))
		}
	}
}

// A failure to prepare the start check's copy is reported as the check's
// failure, not as a start refusal: the start was not tried. A failure to
// remove the copy after a start is reported with its path, never as an
// unqualified success. Faults are fixture permissions set from the reader
// hook: the output made read-only before the copy is made (the repaired
// files' own check, the second open), or after the copy's start began (the
// third open).
func TestRepairStartCheckFaults(t *testing.T) {
	for _, faultAt := range []int{2, 3} {
		c, _ := brokenStateDir(t)
		out := filepath.Join(t.TempDir(), "repair")
		opens := 0
		afterJournalOpen = func() {
			if opens++; opens == faultAt {
				if e := os.Chmod(out, 0500); e != nil {
					t.Error(e)
				}
			}
		}
		report, e := Repair(c, out)
		afterJournalOpen = nil
		os.Chmod(out, 0700)
		if e != nil || !report.Opens {
			t.Fatalf("fault at open %d: %+v %v", faultAt, report, e)
		}
		switch faultAt {
		case 2:
			if report.Starts || report.StartError != "" || !strings.Contains(report.StartCheckError, "was not tried") {
				t.Fatalf("preparation fault: %+v", report)
			}
		case 3:
			if !report.Starts || report.StartError != "" || !strings.Contains(report.StartCheckError, "was not removed") || !strings.Contains(report.StartCheckError, "startup-check") {
				t.Fatalf("cleanup fault: %+v", report)
			}
		}
	}
}

// The install keeps the new-events flag and the daily event files, which the
// startup save rewrites or removes after the same file check as every state
// artifact. The repair checks them in place and names each one a start would
// refuse: a flag or an obsolete day file with mode 0644, a day file that is a
// symlink, a flag with a second hard link. Each prediction is checked against
// a real start after the documented install (repaired state.json and journal
// copied in, the rest left): it refuses exactly when the report names a file.
// Positive control: private files are not named and the start succeeds. The
// state directory's names, bytes and modes are unchanged by the repair.
func TestRepairReportsUnsafeRetainedFiles(t *testing.T) {
	plant := map[string]func(t *testing.T, dir string){
		"flag mode 0644": func(t *testing.T, dir string) {
			writeMode(t, filepath.Join(dir, "new-events.flag"), "x\n", 0644)
		},
		"obsolete day mode 0644": func(t *testing.T, dir string) {
			writeMode(t, filepath.Join(dir, "events-1900-01-01.jsonl"), "{}\n", 0644)
		},
		"day symlink": func(t *testing.T, dir string) {
			target := filepath.Join(t.TempDir(), "day")
			writeMode(t, target, "{}\n", 0600)
			if e := os.Symlink(target, filepath.Join(dir, "events-1900-01-01.jsonl")); e != nil {
				t.Fatal(e)
			}
		},
		"flag hard link": func(t *testing.T, dir string) {
			path := filepath.Join(dir, "new-events.flag")
			writeMode(t, path, "x\n", 0600)
			if e := os.Link(path, filepath.Join(t.TempDir(), "flag")); e != nil {
				t.Fatal(e)
			}
		},
		"private control": func(t *testing.T, dir string) {
			writeMode(t, filepath.Join(dir, "new-events.flag"), "x\n", 0600)
			writeMode(t, filepath.Join(dir, "events-1900-01-01.jsonl"), "{}\n", 0600)
		},
	}
	for name, setup := range plant {
		c, _ := brokenStateDir(t)
		setup(t, c.StateDir)
		before, modes := dirHashes(t, c.StateDir), dirModes(t, c.StateDir)
		out := filepath.Join(t.TempDir(), "repair")
		report, e := Repair(c, out)
		if e != nil || !report.Opens || !report.Starts {
			t.Fatalf("%s: %+v %v", name, report, e)
		}
		if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) || !reflect.DeepEqual(modes, dirModes(t, c.StateDir)) {
			t.Fatalf("%s: the state directory changed", name)
		}
		control := name == "private control"
		if control != (len(report.RetainedUnsafe) == 0) {
			t.Fatalf("%s: retained_unsafe %q", name, report.RetainedUnsafe)
		}
		if !control && (len(report.RetainedUnsafe) != 1 || !strings.Contains(report.RetainedUnsafe[0], "private regular files")) {
			t.Fatalf("%s: retained_unsafe %q", name, report.RetainedUnsafe)
		}
		for _, f := range []string{"state.json", journalFile} {
			b, e := os.ReadFile(filepath.Join(out, "repaired", f))
			if e != nil {
				t.Fatal(e)
			}
			writeMode(t, filepath.Join(c.StateDir, f), string(b), 0600)
		}
		if _, e := openRun(c, time.Now); control != (e == nil) {
			t.Fatalf("%s: start after install: %v", name, e)
		}
	}
}

// A state directory is checked as the entry it names, whatever its spelling.
// A symlink to it is refused by checkDir, safeDir and the repair with or
// without trailing separators, and a spelling ending in "." or ".." is
// refused; the repair creates no output. Positive control: the directory
// itself, with or without a trailing separator, is accepted and repairs.
func TestStateDirSpellingsCheckTheEntry(t *testing.T) {
	c, _ := brokenStateDir(t)
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(c.StateDir, link); e != nil {
		t.Fatal(e)
	}
	for _, dir := range []string{link, link + "/", link + "//", link + "/.", c.StateDir + "/.", c.StateDir + "/sub/.."} {
		if checkDir(dir) == nil || safeDir(dir) == nil {
			t.Fatalf("%s: accepted", dir)
		}
		rc := c
		rc.StateDir = dir
		out := filepath.Join(t.TempDir(), "repair")
		if _, e := Repair(rc, out); e == nil {
			t.Fatalf("%s: repaired", dir)
		}
		if _, e := os.Lstat(out); !os.IsNotExist(e) {
			t.Fatalf("%s: output created: %v", dir, e)
		}
	}
	for _, dir := range []string{c.StateDir, c.StateDir + "/"} {
		if e := checkDir(dir); e != nil {
			t.Fatalf("%s: %v", dir, e)
		}
		if e := safeDir(dir); e != nil {
			t.Fatalf("%s: %v", dir, e)
		}
		rc := c
		rc.StateDir = dir
		if report, e := Repair(rc, filepath.Join(t.TempDir(), "repair")); e != nil || !report.Opens || !report.Starts {
			t.Fatalf("%s: %+v %v", dir, report, e)
		}
	}
}

func writeMode(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if e := os.WriteFile(path, []byte(data), mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}

func dirModes(t *testing.T, dir string) map[string]os.FileMode {
	t.Helper()
	files, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	modes := map[string]os.FileMode{}
	for _, f := range files {
		info, e := f.Info()
		if e != nil {
			t.Fatal(e)
		}
		modes[f.Name()] = info.Mode()
	}
	return modes
}
