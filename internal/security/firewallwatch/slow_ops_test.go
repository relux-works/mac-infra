package firewallwatch

import (
	"encoding/json"
	"reflect"
	"sort"
	"testing"
	"time"
)

// The record keeps operations of at least the threshold and nothing shorter,
// holds at most SlowOpLimit, drops the oldest first and reports the latest
// dropped completion time. A record is metadata only: exactly kind, at,
// duration_ns and an optional items count.
func TestRecordSlowThresholdAndBound(t *testing.T) {
	var h RunHealth
	start := time.Date(2026, 10, 29, 18, 0, 0, 0, time.UTC)
	h.recordSlow(SlowSave, SlowOpThreshold-1, start, 0)
	if len(h.SlowOps) != 0 {
		t.Fatalf("below threshold recorded: %+v", h.SlowOps)
	}
	h.recordSlow(SlowSave, SlowOpThreshold, start, 0)
	if len(h.SlowOps) != 1 || h.SlowOpsDroppedThrough != nil {
		t.Fatalf("threshold op: %+v", h)
	}
	for i := 1; i < SlowOpLimit+3; i++ {
		h.recordSlow(SlowNettopSample, SlowOpThreshold, start.Add(time.Duration(i)*time.Second), i)
	}
	if len(h.SlowOps) != SlowOpLimit || !h.SlowOps[0].At.Equal(start.Add(3*time.Second)) {
		t.Fatalf("len %d first %v; want %d from +3s", len(h.SlowOps), h.SlowOps[0].At, SlowOpLimit)
	}
	if h.SlowOpsDroppedThrough == nil || !h.SlowOpsDroppedThrough.Equal(start.Add(2*time.Second)) {
		t.Fatalf("dropped through %v; want +2s", h.SlowOpsDroppedThrough)
	}
	for _, c := range []struct {
		op   SlowOp
		keys []string
	}{
		{SlowOp{Kind: SlowSave, At: start, NS: 1}, []string{"at", "duration_ns", "kind"}},
		{SlowOp{Kind: SlowNettopSample, At: start, NS: 1, Items: 4}, []string{"at", "duration_ns", "items", "kind"}},
	} {
		raw, err := json.Marshal(c.op)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err = json.Unmarshal(raw, &fields); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(fields))
		for k := range fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if !reflect.DeepEqual(keys, c.keys) {
			t.Fatalf("record fields %v; want %v", keys, c.keys)
		}
	}
}

// Saves and classifications add records through their timing hooks, and the
// record survives a save and reopen. Limit: the nettop sample and maintenance
// hooks live in Run, which no unit test drives; they call the same recordSlow.
func TestSlowOpsRecordedAndPersisted(t *testing.T) {
	saved := slowOpThreshold
	slowOpThreshold = 0
	t.Cleanup(func() { slowOpThreshold = saved })
	s := pruneFixture(t, 20)
	s.classify(Item{App: "a"}, func(Item) Decision { return Decision{Label: "noise"} })
	if e := s.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	if e := s.Save(time.Now()); e != nil { // persists the first save's record
		t.Fatal(e)
	}
	reopened, e := OpenStore(s.Config)
	if e != nil {
		t.Fatal(e)
	}
	kinds := map[string]int{}
	for _, op := range reopened.State.Health.SlowOps {
		kinds[op.Kind]++
	}
	if kinds[SlowClassification] != 1 || kinds[SlowSave] < 1 {
		t.Fatalf("persisted kinds %v; want one classification and a save", kinds)
	}
}

// A digest window holds exactly the records that completed in [since, as_of],
// both ends included, with each kind's count and maximum there; an empty window
// has empty, non-null records and kinds. dropped_through appears only when the
// bound dropped records completed at or after since.
func TestWindowSlowOps(t *testing.T) {
	t0 := time.Date(2026, 10, 29, 18, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	h := RunHealth{SlowOps: []SlowOp{
		{Kind: SlowSave, At: at(0), NS: 9e9},
		{Kind: SlowSave, At: at(10), NS: 3e9},
		{Kind: SlowNettopSample, At: at(15), NS: 50e9, Items: 14},
		{Kind: SlowSave, At: at(20), NS: 4e9},
		{Kind: SlowMaintenance, At: at(30), NS: 7e9},
	}}
	w := windowSlowOps(h, at(10), at(20))
	if len(w.Records) != 3 || w.DroppedThrough != nil {
		t.Fatalf("records %+v dropped %v", w.Records, w.DroppedThrough)
	}
	want := map[string]WindowSlowKind{
		SlowSave:         {Count: 2, MaxNS: 4e9, MaxAt: at(20)},
		SlowNettopSample: {Count: 1, MaxNS: 50e9, MaxAt: at(15)},
	}
	if !reflect.DeepEqual(w.Kinds, want) {
		t.Fatalf("kinds %+v; want %+v", w.Kinds, want)
	}
	raw, err := json.Marshal(windowSlowOps(h, at(40), at(50)))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"records":[],"kinds":{},"dropped_through":null}` {
		t.Fatalf("empty window: %s", raw)
	}
	before, inside := at(5), at(10)
	h.SlowOpsDroppedThrough = &before
	if w = windowSlowOps(h, at(10), at(20)); w.DroppedThrough != nil {
		t.Fatal("drops before the window reported")
	}
	h.SlowOpsDroppedThrough = &inside
	if w = windowSlowOps(h, at(10), at(20)); w.DroppedThrough == nil || !w.DroppedThrough.Equal(inside) {
		t.Fatalf("drop at since not reported: %v", w.DroppedThrough)
	}
}

// Split carries the window's slow operations from state.
func TestSplitIncludesSlowOps(t *testing.T) {
	s := pruneFixture(t, 20)
	now := time.Now().UTC()
	s.State.Health.SlowOps = []SlowOp{{Kind: SlowMaintenance, At: now.Add(-time.Minute), NS: 3e9}}
	split := s.Split(now.Add(-time.Hour), now)
	if k := split.Window.SlowOps.Kinds[SlowMaintenance]; k.Count != 1 || k.MaxNS != 3e9 {
		t.Fatalf("split slow ops %+v", split.Window.SlowOps)
	}
}
