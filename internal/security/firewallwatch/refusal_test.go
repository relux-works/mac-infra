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

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t.Round(0) } }

// refuseAndEnd makes the run's next heartbeat refused, as a stall whose times
// run backward by wall time would be, and ends the run the way Run does: the
// final save, then the marker. It returns the run's error.
func refuseAndEnd(t *testing.T, s *Store, at time.Time) error {
	t.Helper()
	back := sameWallLaterMono(t, at.Add(-time.Second), 2*time.Second)
	s.StallCoverage(back)
	s.ResumeCoverage(sameWallLaterMono(t, at.Add(-time.Second), 3*time.Second))
	err := s.Checkpoint(back)
	if !errors.Is(err, errInvalidState) {
		t.Fatalf("fixture: heartbeat %v; want a refusal", err)
	}
	err = errors.Join(err, s.Save(back))
	return errors.Join(err, s.markWriteRefusal(err))
}

// A refused write leaves a marker holding only {at, field, kind}; the next
// start records it in the state, removes the marker, and the digest labels the
// gap between the last durable coverage and the restart write_refused with the
// refused check, instead of an ordinary not_running restart. Negative control:
// a start that ignores the marker leaves the gap not_running and the marker
// in place.
func TestWriteRefusalLabelsTheRestartGap(t *testing.T) {
	c := testConfig(t)
	at := time.Now()
	s, e := openRun(c, fixedClock(at))
	if e != nil {
		t.Fatal(e)
	}
	s.BeginCoverage(at)
	if e := s.Save(at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	s.clock = fixedClock(at.Add(2 * time.Second))
	if err := refuseAndEnd(t, s, at); !errors.Is(err, errInvalidState) {
		t.Fatalf("run error %v; want the refusal", err)
	}
	raw, e := os.ReadFile(filepath.Join(c.StateDir, refusalMarker))
	if e != nil {
		t.Fatalf("marker: %v", e)
	}
	var fields map[string]any
	if e := json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	keys := []string{}
	for k := range fields {
		keys = append(keys, k)
	}
	if len(keys) != 3 || fields["field"] != checkStallOrder || fields["kind"] != refusalKindJournal || fields["at"] == nil {
		t.Fatalf("marker %s; want only at, field %q and kind %q", raw, checkStallOrder, refusalKindJournal)
	}

	restart := at.Add(70 * time.Second)
	r, e := openRun(c, fixedClock(restart))
	if e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(c.StateDir, refusalMarker)); !os.IsNotExist(e) {
		t.Fatalf("marker still present after the start: %v", e)
	}
	if len(r.State.WriteRefusals) != 1 || r.State.WriteRefusals[0].Check != checkStallOrder {
		t.Fatalf("refusals %+v", r.State.WriteRefusals)
	}
	r.BeginCoverage(restart)
	if e := r.Save(restart.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	again := reopen(t, c)
	gaps := again.Split(at, restart.Add(time.Second)).Window.CoverageGaps
	found := false
	for _, g := range gaps {
		if g.Kind == GapNotRunning {
			t.Fatalf("gap %+v left as an ordinary restart", g)
		}
		if g.Kind == GapWriteRefused && strings.Contains(g.Detail, checkStallOrder) && strings.Contains(g.Detail, refusalKindJournal) {
			found = true
		}
	}
	if !found {
		t.Fatalf("gaps %+v; want one write_refused naming the check", gaps)
	}
}

// Loop guard: a refusal of a check already refused within the last three
// recorded refusals carries the repeat count, and the gap says "repeated";
// a refusal of another check does not. The record list stays bounded.
func TestWriteRefusalRepeatsAreReported(t *testing.T) {
	c := testConfig(t)
	at := time.Now().Round(0)
	s, e := openRun(c, fixedClock(at))
	if e != nil {
		t.Fatal(e)
	}
	s.State.WriteRefusals = []WriteRefusal{{At: at.Add(-3 * time.Minute), Check: checkStallOrder, Kind: refusalKindJournal}, {At: at.Add(-2 * time.Minute), Check: checkStallOrder, Kind: refusalKindJournal}}
	marks := 0
	mark := func(check string) WriteRefusal {
		t.Helper()
		marks++ // each refusal its own time: the same marker is recorded once
		b, _ := json.Marshal(refusalMarkerFile{At: at.Add(time.Duration(marks) * time.Millisecond), Field: check, Kind: refusalKindSnapshot})
		if e := os.WriteFile(filepath.Join(c.StateDir, refusalMarker), b, 0600); e != nil {
			t.Fatal(e)
		}
		if ok, e := s.takeWriteRefusal(); !ok || e != nil {
			t.Fatalf("take: %t %v", ok, e)
		}
		return s.State.WriteRefusals[len(s.State.WriteRefusals)-1]
	}
	if r := mark(checkStallOrder); r.Repeats != 2 {
		t.Fatalf("repeats %d; want 2", r.Repeats)
	}
	if r := mark(checkEntryOrder); r.Repeats != 0 {
		t.Fatalf("another check counted as a repeat: %d", r.Repeats)
	}
	for i := 0; i < refusalLimit+5; i++ {
		mark(checkShape)
	}
	if len(s.State.WriteRefusals) != refusalLimit {
		t.Fatalf("%d refusals kept; want %d", len(s.State.WriteRefusals), refusalLimit)
	}
	if e := s.Save(at); e != nil {
		t.Fatalf("a full record list must still save: %v", e)
	}
	stalls := []WriteRefusal{{At: at, Check: checkStallOrder, Repeats: 2}}
	s.State.WriteRefusals = stalls
	gap := s.labelRefusals([]SplitGap{{Kind: GapNotRunning, From: at.Add(-time.Second), To: at.Add(time.Second)}})
	if gap[0].Kind != GapWriteRefused || !strings.Contains(gap[0].Detail, "repeated") {
		t.Fatalf("gap %+v; want write_refused with the repeat reported", gap[0])
	}
	s.State.WriteRefusals = []WriteRefusal{{At: at, Check: checkEntryOrder}}
	gap = s.labelRefusals([]SplitGap{{Kind: GapNotRunning, From: at.Add(-time.Second), To: at.Add(time.Second)}})
	if gap[0].Kind != GapWriteRefused || strings.Contains(gap[0].Detail, "repeated") {
		t.Fatalf("gap %+v; a first refusal is not a repeat", gap[0])
	}
	if other := s.labelRefusals([]SplitGap{{Kind: GapStall, From: at.Add(-time.Second), To: at.Add(time.Second)}}); other[0].Kind != GapStall {
		t.Fatal("only not_running gaps are relabelled")
	}
}

// A marker that cannot be written does not keep the run alive or hide the
// refusal: the run's error still is the refusal, plus the marker failure.
func TestWriteRefusalMarkerFailureStillEndsTheRun(t *testing.T) {
	c := testConfig(t)
	at := time.Now()
	s, e := openRun(c, fixedClock(at))
	if e != nil {
		t.Fatal(e)
	}
	s.BeginCoverage(at)
	if e := s.Save(at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(c.StateDir, refusalMarker), 0700); e != nil {
		t.Fatal(e)
	}
	err := refuseAndEnd(t, s, at)
	if !errors.Is(err, errInvalidState) || !errors.Is(err, errRefusedRecord) {
		t.Fatalf("run error %v; want the refusal kept", err)
	}
}

func writeMarker(t *testing.T, c Config, raw []byte) {
	t.Helper()
	if e := os.WriteFile(filepath.Join(c.StateDir, refusalMarker), raw, 0600); e != nil {
		t.Fatal(e)
	}
}

// Review r2: recording a refusal is idempotent across failed or interrupted
// starts. Two starts fail after their snapshot already holds the record (the
// day projection cannot be written), the marker survives them, and the next
// good start leaves exactly one record with no repeat. The same holds for a
// malformed marker, recorded with its file's time. Negative control: an
// import that appends unconditionally records three refusals, two of them
// false repeats.
func TestRefusalImportIsIdempotent(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		c := testConfig(t)
		at := time.Now().Round(0)
		s, e := openRun(c, fixedClock(at))
		if e != nil {
			t.Fatal(e)
		}
		observeFlush(t, s, newKey(1), at)
		if e := s.Save(at); e != nil {
			t.Fatal(e)
		}
		if malformed {
			writeMarker(t, c, []byte("broken"))
		} else {
			b, _ := json.Marshal(refusalMarkerFile{At: at.Add(time.Second), Field: checkEntryOrder, Kind: refusalKindJournal})
			writeMarker(t, c, b)
		}
		day := filepath.Join(c.StateDir, "events-"+at.UTC().Format("2006-01-02")+".jsonl")
		if e := os.Remove(day); e != nil {
			t.Fatal(e)
		}
		if e := os.Mkdir(day, 0700); e != nil {
			t.Fatal(e)
		}
		for attempt := 1; attempt <= 2; attempt++ {
			if _, e := openRun(c, fixedClock(at.Add(time.Duration(attempt+1)*time.Second))); e == nil {
				t.Fatal("fixture: the start must fail at the day projection")
			}
			if _, e := os.Stat(filepath.Join(c.StateDir, refusalMarker)); e != nil {
				t.Fatalf("malformed=%v: the marker was lost by a failed start: %v", malformed, e)
			}
		}
		if e := os.Remove(day); e != nil {
			t.Fatal(e)
		}
		r, e := openRun(c, fixedClock(at.Add(4*time.Second)))
		if e != nil {
			t.Fatal(e)
		}
		if len(r.State.WriteRefusals) != 1 || r.State.WriteRefusals[0].Repeats != 0 {
			t.Fatalf("malformed=%v: one refusal recorded as %+v", malformed, r.State.WriteRefusals)
		}
		if _, e := os.Stat(filepath.Join(c.StateDir, refusalMarker)); !os.IsNotExist(e) {
			t.Fatalf("malformed=%v: marker left after the good start", malformed)
		}
	}
}

// Review r2: several runs can fail before any new coverage is durable, so one
// not_running gap can hold several refusals; the label names each and keeps
// the repeat of an earlier one when a later, first-time check follows.
// Negative control: keeping only the last refusal's detail drops the repeat.
func TestSeveralRefusalsInOneGap(t *testing.T) {
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
	for i, check := range []string{checkStallOrder, checkStallOrder, checkEntryOrder} {
		b, _ := json.Marshal(refusalMarkerFile{At: at.Add(time.Duration(i+2) * time.Second), Field: check, Kind: refusalKindJournal})
		writeMarker(t, c, b)
		if s, e = openRun(c, fixedClock(at.Add(time.Duration(i+3)*time.Second))); e != nil {
			t.Fatal(e)
		}
	}
	s.BeginCoverage(at.Add(70 * time.Second))
	if e := s.Save(at.Add(71 * time.Second)); e != nil {
		t.Fatal(e)
	}
	gaps := s.Split(at, at.Add(71*time.Second)).Window.CoverageGaps
	if len(gaps) != 1 || gaps[0].Kind != GapWriteRefused || !strings.Contains(gaps[0].Detail, "repeated") || !strings.Contains(gaps[0].Detail, checkStallOrder) || !strings.Contains(gaps[0].Detail, checkEntryOrder) {
		t.Fatalf("gaps %+v; want one write_refused naming both checks and the repeat", gaps)
	}
}

// Review r3: a shape-check refusal of a journal record is returned as such,
// also when a snapshot could succeed instead (at cap 1 the snapshot's prune
// drops the refused span), so the run ends with the named error and its
// marker; the last durable state stays readable. Control: an ordinary
// append I/O failure still recovers through a snapshot, keeping the entry.
// Negative control: falling back to the snapshot on a refusal returns nil.
func TestRefusalIsNotSwallowedBySnapshotFallback(t *testing.T) {
	for _, cap := range []int{1, 20} {
		s, c := journalStore(t)
		s.Config.MaxEntries, c.MaxEntries = cap, cap
		at := time.Now()
		s.BeginCoverage(at)
		if e := s.Save(at.Add(time.Second)); e != nil {
			t.Fatal(e)
		}
		back := sameWallLaterMono(t, at.Add(-time.Second), 2*time.Second)
		s.StallCoverage(back)
		s.ResumeCoverage(sameWallLaterMono(t, at.Add(-time.Second), 3*time.Second))
		err := s.Checkpoint(back)
		if !errors.Is(err, errRefusedRecord) || !errors.Is(err, errInvalidState) {
			t.Fatalf("cap %d: checkpoint %v; want the named refusal", cap, err)
		}
		if _, e := OpenStore(c); e != nil {
			t.Fatalf("cap %d: last durable state unreadable: %v", cap, e)
		}
	}

	s, c := journalStore(t)
	at := time.Now()
	s.Observe(newKey(1), at, ruleClassify)
	s.journalWrite = func(*os.File, []byte) error { return errors.New("injected append I/O failure") }
	if e := s.Flush(at, true, false); e != nil {
		t.Fatalf("ordinary append failure: %v; want recovery through a snapshot", e)
	}
	r, e := OpenStore(c)
	if e != nil || r.State.Entries[key(newKey(1))] == nil {
		t.Fatalf("snapshot fallback lost the entry: %v", e)
	}
}
