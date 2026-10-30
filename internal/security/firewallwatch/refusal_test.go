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
	mark := func(check string) WriteRefusal {
		t.Helper()
		b, _ := json.Marshal(refusalMarkerFile{At: at, Field: check, Kind: refusalKindSnapshot})
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
