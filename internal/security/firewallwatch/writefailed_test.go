package firewallwatch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A run that a failed flag write ends leaves the marker with kind
// write_failed and the file's name only; the next start records it, removes
// the marker, and the digest labels the gap write_failed naming the file,
// not an ordinary not_running restart. The flag is made to fail by the
// private-file check (mode 0644).
func TestFlagWriteFailureLabelsTheRestartGap(t *testing.T) {
	c := testConfig(t)
	at := time.Now().Round(0)
	s, e := openRun(c, fixedClock(at))
	if e != nil {
		t.Fatal(e)
	}
	s.BeginCoverage(at)
	if e := s.Save(at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	s.clock = fixedClock(at.Add(2 * time.Second))
	flag := filepath.Join(c.StateDir, "new-events.flag")
	writeMode(t, flag, "old\n", 0644)
	s.State.LastEvent = at
	if e := s.writeFlag(); e != nil {
		t.Fatalf("post: %v", e)
	}
	select {
	case <-s.flags.failure():
	case <-time.After(5 * time.Second):
		t.Fatal("the flag write did not fail")
	}
	err := s.finishRun(s.flags.error(), s.now())
	var failed *fileWriteError
	if !errors.As(err, &failed) || failed.file != "new-events.flag" {
		t.Fatalf("run error %v; want the failed flag write named", err)
	}
	raw, e := os.ReadFile(filepath.Join(c.StateDir, refusalMarker))
	if e != nil {
		t.Fatalf("marker: %v", e)
	}
	var fields map[string]any
	if e := json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	if len(fields) != 3 || fields["kind"] != refusalKindWriteFailed || fields["field"] != "new-events.flag" || fields["at"] == nil {
		t.Fatalf("marker %s; want only at, field new-events.flag and kind write_failed", raw)
	}

	if e := os.Chmod(flag, 0600); e != nil {
		t.Fatal(e)
	}
	restart := at.Add(70 * time.Second)
	r, e := openRun(c, fixedClock(restart))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(c.StateDir, refusalMarker)); !os.IsNotExist(e) {
		t.Fatalf("marker still present after the start: %v", e)
	}
	if n := len(r.State.WriteRefusals); n != 1 || r.State.WriteRefusals[0].Kind != refusalKindWriteFailed || r.State.WriteRefusals[0].Check != "new-events.flag" {
		t.Fatalf("records %+v", r.State.WriteRefusals)
	}
	r.BeginCoverage(restart)
	if e := r.finishRun(nil, restart.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	gaps := reopen(t, c).Split(at, restart.Add(time.Second)).Window.CoverageGaps
	found := false
	for _, g := range gaps {
		if g.Kind == GapNotRunning || g.Kind == GapWriteRefused {
			t.Fatalf("gap %+v; want write_failed", g)
		}
		if g.Kind == GapWriteFailed && g.Detail == "write_failed new-events.flag" {
			found = true
		}
	}
	if !found {
		t.Fatalf("gaps %+v; want one write_failed naming the flag", gaps)
	}
}

// Only a refused or failed state write leaves the marker. An error that names
// no state file (a collector ending) or a file outside the state files (the
// lock) leaves none; a failed state.json write leaves write_failed; a refusal
// joined with a failed write is recorded as the refusal.
func TestOnlyRefusedOrFailedStateWritesLeaveAMarker(t *testing.T) {
	cases := []struct {
		name  string
		err   error
		kind  string
		field string
	}{
		{"collector ended", errors.New("log stream ended"), "", ""},
		{"lock file", writeFailed("/x/watch.lock", errors.New("eio")), "", ""},
		{"state.json", writeFailed("/x/state.json", errors.New("no space")), refusalKindWriteFailed, "state.json"},
		{"journal", writeFailed("/x/"+journalFile, errors.New("eio")), refusalKindWriteFailed, journalFile},
		{"day file", writeFailed("/x/events-2026-10-30.jsonl", errors.New("eio")), refusalKindWriteFailed, "events-2026-10-30.jsonl"},
		{"refusal and failure", errors.Join(writeFailed("/x/new-events.flag", errors.New("eio")), errors.Join(errRefusedRecord, shapeError{check: checkStallOrder})), refusalKindJournal, checkStallOrder},
	}
	for _, tc := range cases {
		c := testConfig(t)
		s, e := OpenStore(c)
		if e != nil {
			t.Fatal(e)
		}
		if e := safeDir(c.StateDir); e != nil {
			t.Fatal(e)
		}
		s.clock = fixedClock(time.Now())
		if e := s.markWriteRefusal(tc.err); e != nil {
			t.Fatalf("%s: %v", tc.name, e)
		}
		raw, e := os.ReadFile(filepath.Join(c.StateDir, refusalMarker))
		if tc.kind == "" {
			if !os.IsNotExist(e) {
				t.Fatalf("%s: marker %s left", tc.name, raw)
			}
			continue
		}
		var m refusalMarkerFile
		if e != nil || json.Unmarshal(raw, &m) != nil || m.Kind != tc.kind || m.Field != tc.field {
			t.Fatalf("%s: marker %s (%v); want kind %q field %q", tc.name, raw, e, tc.kind, tc.field)
		}
	}
}

// The marker is read back as data, so a write_failed record is admitted only
// with a state file's name; anything else is recorded as unknown, as a
// malformed marker is. Refusal kinds keep their rule (a short check name).
func TestWriteFailedMarkerAdmitsOnlyStateFileNames(t *testing.T) {
	valid := []string{"state.json", journalFile, "new-events.flag", "events-2026-10-30.jsonl"}
	invalid := []string{"", "../state.json", "/tmp/state.json", "watch.lock", refusalMarker, "events-2026-10-30.jsonl.bak", "events-../../x.jsonl", "events-" + strings.Repeat("9", 40) + ".jsonl", "/Applications/Secret.app"}
	c := testConfig(t)
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	if e := safeDir(c.StateDir); e != nil {
		t.Fatal(e)
	}
	at := time.Now().Round(0)
	s.clock = fixedClock(at)
	for i, field := range append(append([]string{}, valid...), invalid...) {
		b, _ := json.Marshal(refusalMarkerFile{At: at.Add(time.Duration(i) * time.Second), Field: field, Kind: refusalKindWriteFailed})
		if e := os.WriteFile(filepath.Join(c.StateDir, refusalMarker), b, 0600); e != nil {
			t.Fatal(e)
		}
		if ok, e := s.takeWriteRefusal(); !ok || e != nil {
			t.Fatalf("%q: take %t %v", field, ok, e)
		}
		r := s.State.WriteRefusals[len(s.State.WriteRefusals)-1]
		admitted := i < len(valid)
		if admitted != (r.Kind == refusalKindWriteFailed && r.Check == field) || !admitted && (r.Kind != "unknown" || r.Check != "unknown") {
			t.Fatalf("%q: recorded %+v; admitted %t", field, r, admitted)
		}
	}
}

// A gap holding only failed writes is write_failed, naming each file and any
// repeat; a gap that also holds a refusal stays write_refused and names both.
func TestWriteFailedGapLabels(t *testing.T) {
	at := time.Now().Round(0)
	gap := func(s *Store) SplitGap {
		return s.labelRefusals([]SplitGap{{Kind: GapNotRunning, From: at.Add(-time.Minute), To: at.Add(time.Minute)}})[0]
	}
	s := &Store{}
	s.State.WriteRefusals = []WriteRefusal{{At: at, Check: "new-events.flag", Kind: refusalKindWriteFailed, Repeats: 1}}
	if g := gap(s); g.Kind != GapWriteFailed || g.Detail != "write_failed new-events.flag (repeated: 1 earlier failure(s) of this file in the last 3)" {
		t.Fatalf("failure only: %+v", g)
	}
	s.State.WriteRefusals = append(s.State.WriteRefusals, WriteRefusal{At: at.Add(time.Second), Check: checkStallOrder, Kind: refusalKindJournal})
	if g := gap(s); g.Kind != GapWriteRefused || !strings.Contains(g.Detail, "write_failed new-events.flag") || !strings.Contains(g.Detail, refusalKindJournal+" "+checkStallOrder) {
		t.Fatalf("failure and refusal: %+v", g)
	}
}

// A failed state write names its file: a snapshot whose state.json write
// fails, and a journal append whose write fails. The error still wraps the
// cause (errors.Is).
func TestFailedWritesNameTheirFile(t *testing.T) {
	cause := errors.New("injected")
	s, _ := journalStore(t)
	s.atomicWrite = func(string, []byte) error { return cause }
	var failed *fileWriteError
	if e := s.Save(time.Now()); !errors.As(e, &failed) || failed.file != "state.json" || !errors.Is(e, cause) {
		t.Fatalf("save: %v", e)
	}
	s, _ = journalStore(t)
	s.journalWrite = func(*os.File, []byte) error { return cause }
	observeAt := time.Now().Round(0)
	s.Observe(newKey(1), observeAt, ruleClassify)
	if e := s.appendJournal(observeAt, true); !errors.As(e, &failed) || failed.file != journalFile || !errors.Is(e, cause) {
		t.Fatalf("append: %v", e)
	}
}

// A flag write that fails only during the shutdown drain is named too: the
// marker comes after the drain. The writer's write is held until after
// finishRun has saved and posted, so its failure surfaces only at the stop.
// Positive control: the same shutdown with a write that succeeds leaves no
// marker.
func TestDrainFailureLeavesTheMarker(t *testing.T) {
	for _, fail := range []bool{true, false} {
		c := testConfig(t)
		at := time.Now().Round(0)
		s, e := openRun(c, fixedClock(at))
		if e != nil {
			t.Fatal(e)
		}
		if e := s.stopFlags(); e != nil {
			t.Fatal(e)
		}
		release := make(chan struct{})
		flag := filepath.Join(c.StateDir, "new-events.flag")
		s.flags = startFlagWriter(func([]byte) error {
			<-release
			if fail {
				return writeFailed(flag, errors.New("injected"))
			}
			return nil
		})
		s.State.LastEvent = at
		go func() {
			time.Sleep(50 * time.Millisecond)
			close(release)
		}()
		err := s.finishRun(nil, at.Add(time.Second))
		_, statErr := os.Stat(filepath.Join(c.StateDir, refusalMarker))
		if fail != (err != nil) || fail != (statErr == nil) {
			t.Fatalf("fail=%t: run error %v, marker %v", fail, err, statErr)
		}
	}
}
