package firewallwatch

import (
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"testing"
	"time"
	"unsafe"
)

// referencePrune is the entry and event part of prune before BUG-261029-do8v1i:
// it always sorts and copies. The scan path must keep its results.
func referencePrune(s *Store, now time.Time) {
	cutoff := now.Add(-time.Duration(s.Config.RetentionDays) * 24 * time.Hour)
	for k, v := range s.State.Entries {
		if v.LastSeen.Before(cutoff) {
			delete(s.State.Entries, k)
		}
	}
	if len(s.State.Entries) > s.Config.MaxEntries {
		keys := make([]string, 0, len(s.State.Entries))
		for k := range s.State.Entries {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := s.State.Entries[keys[i]], s.State.Entries[keys[j]]
			if a.LastSeen.Equal(b.LastSeen) {
				return keys[i] < keys[j]
			}
			return a.LastSeen.Before(b.LastSeen)
		})
		for _, k := range keys[:len(keys)-s.Config.MaxEntries] {
			delete(s.State.Entries, k)
		}
	}
	evicted := func(e Event) {
		if e.TS.After(s.State.EvictedThrough) {
			s.State.EvictedThrough = e.TS
		}
	}
	events := s.State.Events[:0]
	for _, e := range s.State.Events {
		if !e.TS.Before(cutoff) {
			events = append(events, e)
		} else {
			evicted(e)
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	if len(events) > s.Config.MaxEntries {
		for _, e := range events[:len(events)-s.Config.MaxEntries] {
			evicted(e)
		}
		events = events[len(events)-s.Config.MaxEntries:]
	}
	s.State.Events = append([]Event(nil), events...)
}

func pruneFixture(t *testing.T, max int) *Store {
	t.Helper()
	c := testConfig(t)
	c.MaxEntries = max
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

// For random stores (stale and tied entries, 0 to 3 entries over the cap,
// time-ordered and shuffled events with stale ones and equal timestamps), prune
// keeps the same entries, events in the same order, the same EvictedThrough and
// the same nil-ness of Events as the pre-fix sorting prune.
func TestPruneMatchesSortingPrune(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-8 * 24 * time.Hour) // testConfig retains 7 days
	rng := rand.New(rand.NewSource(261029))
	for round := 0; round < 2000; round++ {
		max := 1 + rng.Intn(5)
		at := func() time.Time {
			if rng.Intn(4) == 0 {
				return stale.Add(-time.Duration(rng.Intn(3)) * time.Minute)
			}
			return now.Add(-time.Duration(rng.Intn(4)) * time.Minute) // few values: ties
		}
		entries := map[string]*Entry{}
		for i, n := 0, rng.Intn(max+4); i < n; i++ {
			seen := at()
			entries[fmt.Sprintf("k%02d", rng.Intn(20))] = &Entry{FirstSeen: seen, LastSeen: seen, WindowStart: seen, Count: 1}
		}
		var events []Event
		for i, n := 0, rng.Intn(max+4); i < n; i++ {
			events = append(events, Event{TS: at(), App: fmt.Sprintf("e%d", i)})
		}
		if rng.Intn(2) == 0 {
			sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
		}
		got, want := pruneFixture(t, max), pruneFixture(t, max)
		for _, s := range []*Store{got, want} {
			s.State.Entries = map[string]*Entry{}
			for k, v := range entries {
				s.State.Entries[k] = v
			}
			s.State.Events = slices.Clone(events)
			s.State.EvictedThrough = time.Time{}
		}
		got.prune(now)
		referencePrune(want, now)
		keys := func(s *Store) []string {
			k := make([]string, 0, len(s.State.Entries))
			for key := range s.State.Entries {
				k = append(k, key)
			}
			sort.Strings(k)
			return k
		}
		if !reflect.DeepEqual(keys(got), keys(want)) {
			t.Fatalf("round %d entries: got %v want %v", round, keys(got), keys(want))
		}
		if !reflect.DeepEqual(got.State.Events, want.State.Events) || (got.State.Events == nil) != (want.State.Events == nil) {
			t.Fatalf("round %d events: got %v want %v", round, got.State.Events, want.State.Events)
		}
		if !got.State.EvictedThrough.Equal(want.State.EvictedThrough) {
			t.Fatalf("round %d evicted_through: got %v want %v", round, got.State.EvictedThrough, want.State.EvictedThrough)
		}
	}
}

// The scan path follows the eviction contract directly, not only the reference:
// one entry over the cap evicts the oldest, the smaller key on a tie, and never a
// fresh entry; expired and surplus time-ordered events leave from the front and
// advance EvictedThrough to the newest event removed.
func TestPruneScanPathContract(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	s := pruneFixture(t, 2)
	old := now.Add(-time.Hour)
	s.State.Entries = map[string]*Entry{
		"b":     {FirstSeen: old, LastSeen: old, WindowStart: old, Count: 1},
		"a":     {FirstSeen: old, LastSeen: old, WindowStart: old, Count: 1},
		"fresh": {FirstSeen: now, LastSeen: now, WindowStart: now, Count: 1},
	}
	expired := now.Add(-8 * 24 * time.Hour)
	s.State.Events = []Event{{TS: expired, App: "expired"}, {TS: old, App: "surplus"}, {TS: old.Add(time.Minute), App: "kept1"}, {TS: now, App: "kept2"}}
	s.State.EvictedThrough = time.Time{}
	s.prune(now)
	if _, ok := s.State.Entries["a"]; ok || len(s.State.Entries) != 2 || s.State.Entries["b"] == nil || s.State.Entries["fresh"] == nil {
		t.Fatalf("entry eviction: %v", s.State.Entries)
	}
	if len(s.State.Events) != 2 || s.State.Events[0].App != "kept1" || s.State.Events[1].App != "kept2" {
		t.Fatalf("event trim: %v", s.State.Events)
	}
	if !s.State.EvictedThrough.Equal(old) {
		t.Fatalf("evicted_through %v, want %v", s.State.EvictedThrough, old)
	}
	// Removing every event leaves nil, as the sorting path did (JSON null).
	s.State.Events = []Event{{TS: expired}}
	s.prune(now)
	if s.State.Events != nil {
		t.Fatal("empty events not nil")
	}
}

// BUG-261029-do8v1i regression witness: at a 10000-entry, 10000-event,
// 10000-span cap with ordered wall-clock state (as loaded or observed), prune
// allocates nothing, and a repeat observation allocates no copy of events or
// coverage. The pre-fix prune copied every event on each call. Allocation counts
// and bytes, not timing, keep this deterministic; Observe still makes small
// allocations for the item key, far below one copy.
func TestPruneAtCapDoesNotCopyState(t *testing.T) {
	const max = 10000
	s := pruneFixture(t, max)
	now := time.Now().Round(0) // persisted state carries wall-clock times only
	start := now.Add(-time.Hour)
	for i := 0; i < max; i++ {
		seen := start.Add(time.Duration(i) * time.Millisecond)
		s.State.Entries[fmt.Sprintf("app%05d|nettop|observed|lan", i)] = &Entry{FirstSeen: seen, LastSeen: seen, WindowStart: seen, Count: 1}
		s.State.Events = append(s.State.Events, Event{TS: seen, Source: "nettop", App: fmt.Sprintf("app%05d", i), Label: "noise", Reason: "x", Mode: "shadow", Counts: 1})
		s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: seen, End: seen.Add(time.Microsecond)})
	}
	if allocs := testing.AllocsPerRun(20, func() { s.prune(now) }); allocs != 0 {
		t.Fatalf("prune at cap allocated %.0f times per call", allocs)
	}
	it := Item{App: "app09999", Source: "nettop", Verdict: "observed", Remote: "lan"}
	s.Observe(it, now, ruleClassify)
	// The pre-fix prune copied events and coverage spans twice per observation.
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const runs = 20
	for i := 0; i < runs; i++ {
		s.Observe(it, now, ruleClassify)
	}
	runtime.ReadMemStats(&after)
	copyBytes := uint64(max) * uint64(min(unsafe.Sizeof(Event{}), unsafe.Sizeof(CoverageSpan{})))
	if perCall := (after.TotalAlloc - before.TotalAlloc) / runs; perCall >= copyBytes/16 {
		t.Fatalf("repeat observation at cap allocated %d bytes per call; one state copy is %d", perCall, copyBytes)
	}
	if len(s.State.Entries) != max || len(s.State.Events) != max || len(s.State.Coverage) != max {
		t.Fatalf("cap not held: entries %d events %d coverage %d", len(s.State.Entries), len(s.State.Events), len(s.State.Coverage))
	}
}

// A nettop sample whose new keys all emit writes state once, at the tick's save
// after the sample, instead of once per emitted row (the pre-fix behaviour wrote
// five times here), and reports that it emitted. A sample still classifying after save_interval saves its
// rows emitted so far mid-sample, and a failed save stops the sample with its
// error. Every emitted row is in the reopened state afterwards.
func TestCollectSampleSavesOncePerSample(t *testing.T) {
	setup := func(t *testing.T) (*Store, map[string]int, *time.Time) {
		t.Helper()
		s := pruneFixture(t, 20)
		writes := map[string]int{}
		s.atomicWrite = func(path string, b []byte) error { writes[filepath.Base(path)]++; return atomicWrite(path, b) }
		clock := time.Now()
		if e := s.Save(clock); e != nil {
			t.Fatal(e)
		}
		clear(writes)
		return s, writes, &clock
	}
	items := make([]Item, 5)
	for i := range items {
		items[i] = Item{App: fmt.Sprintf("app%d", i), Source: "nettop", Verdict: "observed", Remote: "lan"}
	}
	t.Run("short sample", func(t *testing.T) {
		s, writes, clock := setup(t)
		collect := func(it Item) bool { return len(s.Observe(it, *clock, ruleClassify)) > 0 }
		flush := func(emitted bool) error { return s.Flush(*clock, emitted, false) }
		if emitted, e := collectSample(items, collect, flush); e != nil || !emitted {
			t.Fatal(emitted, e)
		}
		if writes["state.json"] != 0 {
			t.Fatalf("state written %d times during the sample", writes["state.json"])
		}
		if e := s.Save(*clock); e != nil { // the tick's save
			t.Fatal(e)
		}
		reopened, e := OpenStore(s.Config)
		if e != nil {
			t.Fatal(e)
		}
		if writes["state.json"] != 1 || len(reopened.State.Events) != len(items) {
			t.Fatalf("writes %d, persisted events %d", writes["state.json"], len(reopened.State.Events))
		}
	})
	t.Run("long sample", func(t *testing.T) {
		s, writes, clock := setup(t)
		n := 0
		collect := func(it Item) bool {
			if n++; n == 3 {
				*clock = clock.Add(11 * time.Second) // slow classification passes save_interval
			}
			return len(s.Observe(it, *clock, ruleClassify)) > 0
		}
		flush := func(emitted bool) error { return s.Flush(*clock, emitted, false) }
		if _, e := collectSample(items, collect, flush); e != nil {
			t.Fatal(e)
		}
		reopened, e := OpenStore(s.Config)
		if e != nil {
			t.Fatal(e)
		}
		if writes["state.json"] != 1 || len(reopened.State.Events) != 3 {
			t.Fatalf("writes %d, persisted events %d; want 1 and 3", writes["state.json"], len(reopened.State.Events))
		}
	})
	t.Run("failed save", func(t *testing.T) {
		s := pruneFixture(t, 20)
		collected, failed := 0, errors.New("disk full")
		collect := func(it Item) bool { collected++; return len(s.Observe(it, time.Now(), ruleClassify)) > 0 }
		flush := func(bool) error {
			if collected == 2 {
				return failed
			}
			return nil
		}
		if _, e := collectSample(items, collect, flush); !errors.Is(e, failed) || collected != 2 {
			t.Fatalf("error %v after %d items; want disk full after 2", e, collected)
		}
	})
}

// PR65 review r1: observations store wall-clock times, so in-memory state is
// the state a reload yields. An observation made with a monotonic clock
// reading leaves none in its event or entry, and a Save/OpenStore round trip
// returns equal events.
func TestObservationsUseWallClock(t *testing.T) {
	s := pruneFixture(t, 20)
	now := time.Now()
	if wallClock(now) {
		t.Fatal("fixture needs a monotonic reading")
	}
	s.Observe(Item{App: "wall", Source: "nettop", Verdict: "observed", Remote: "lan"}, now, ruleClassify)
	if len(s.State.Events) != 1 || !wallClock(s.State.Events[0].TS) || !s.State.Events[0].TS.Equal(now) {
		t.Fatalf("event time %v", s.State.Events)
	}
	for _, e := range s.State.Entries {
		if !wallClock(e.FirstSeen) || !wallClock(e.LastSeen) || !wallClock(e.WindowStart) {
			t.Fatalf("entry times keep a monotonic reading: %+v", e)
		}
	}
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(s.Config)
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(reopened.State.Events[0].TS, s.State.Events[0].TS) {
		t.Fatal("reloaded event time differs from the in-memory one")
	}
}

// The fast paths' guards refuse every state where they would not be exact:
// a monotonic reading anywhere, out-of-order times, an expired span, spans over
// the bound, or empty coverage (the sorting path turns it into nil). Ordered
// wall-clock state within the bound is accepted, so the fast path is reachable.
func TestPruneFastPathGuards(t *testing.T) {
	mono := time.Now()
	wall := mono.Round(0)
	if !wallClock(wall) || wallClock(mono) {
		t.Fatal("wallClock does not detect the monotonic reading")
	}
	later := wall.Add(time.Minute)
	if !eventsWallOrdered([]Event{{TS: wall}, {TS: wall}, {TS: later}}) || !eventsWallOrdered(nil) {
		t.Fatal("ordered wall-clock events refused")
	}
	for name, events := range map[string][]Event{
		"monotonic":    {{TS: wall}, {TS: mono.Add(time.Hour)}},
		"out of order": {{TS: later}, {TS: wall}},
	} {
		if eventsWallOrdered(events) {
			t.Errorf("events %s accepted", name)
		}
	}
	cutoff := wall.Add(-time.Hour)
	span := func(start time.Time) CoverageSpan { return CoverageSpan{Start: start, End: start.Add(time.Second)} }
	if !coverageSettled([]CoverageSpan{span(wall), span(later)}, 2, cutoff) {
		t.Fatal("settled coverage refused")
	}
	stalled := span(wall)
	stalled.StallAfter = &CoverageStall{From: stalled.End, To: mono.Add(time.Hour)}
	for name, spans := range map[string][]CoverageSpan{
		"empty":           {},
		"over the bound":  {span(wall), span(later), span(later)},
		"monotonic start": {span(mono)},
		"monotonic stall": {stalled},
		"out of order":    {span(later), span(wall)},
		"expired":         {span(cutoff.Add(-time.Hour)), span(wall)},
	} {
		if coverageSettled(spans, 2, cutoff) {
			t.Errorf("coverage %s accepted", name)
		}
	}
}

// PR65 review r1, finding 2: coverage expiry stays irreversible at observation
// time. An observation past a span's retention removes it and advances the
// watermark; a later Save with an earlier clock reading neither restores the
// span nor clears the watermark, in memory, in Split or in state.json.
func TestCoverageExpiresAtObservation(t *testing.T) {
	s := pruneFixture(t, 20)
	now := time.Now().Round(0)
	end := now.Add(-time.Duration(s.Config.RetentionDays) * 24 * time.Hour)
	s.BeginCoverage(end.Add(-time.Hour))
	s.EndCoverage(end)
	if e := s.Save(end); e != nil {
		t.Fatal(e)
	}
	if len(s.State.Coverage) != 1 {
		t.Fatalf("fixture coverage %v", s.State.Coverage)
	}
	s.Observe(Item{App: "clock", Source: "nettop", Verdict: "observed", Remote: "lan"}, now.Add(time.Second), ruleClassify)
	if len(s.State.Coverage) != 0 || !s.State.CoverageEvictedThrough.Equal(end) || !s.Split(end.Add(-time.Minute), end).Window.Truncated {
		t.Fatalf("observation kept expired coverage: %v watermark %v", s.State.Coverage, s.State.CoverageEvictedThrough)
	}
	if e := s.Save(now.Add(-time.Second)); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(s.Config)
	if e != nil {
		t.Fatal(e)
	}
	if len(reopened.State.Coverage) != 0 || !reopened.State.CoverageEvictedThrough.Equal(end) {
		t.Fatalf("saved coverage %v watermark %v", reopened.State.Coverage, reopened.State.CoverageEvictedThrough)
	}
}

// PR65 review r1, finding 3: a tick saves a sample that emitted before backend
// maintenance, which can block for the backend timeout, then saves once more.
// A failed first save returns its error without maintenance; a sample that
// emitted nothing skips the early save; a sample error stops the tick.
func TestSampleTickSavesBeforeMaintenance(t *testing.T) {
	run := func(emitted bool, sampleErr, saveErr error) ([]string, error) {
		var calls []string
		e := sampleTick(func() (bool, error) { calls = append(calls, "sample"); return emitted, sampleErr },
			func() error { calls = append(calls, "save"); return saveErr },
			func() { calls = append(calls, "maintain") })
		return calls, e
	}
	if calls, e := run(true, nil, nil); e != nil || !reflect.DeepEqual(calls, []string{"sample", "save", "maintain", "save"}) {
		t.Fatalf("emitted: %v %v", calls, e)
	}
	if calls, e := run(false, nil, nil); e != nil || !reflect.DeepEqual(calls, []string{"sample", "maintain", "save"}) {
		t.Fatalf("silent: %v %v", calls, e)
	}
	failed := errors.New("disk full")
	if calls, e := run(true, nil, failed); !errors.Is(e, failed) || !reflect.DeepEqual(calls, []string{"sample", "save"}) {
		t.Fatalf("failed save: %v %v", calls, e)
	}
	if calls, e := run(true, failed, nil); !errors.Is(e, failed) || !reflect.DeepEqual(calls, []string{"sample"}) {
		t.Fatalf("failed sample: %v %v", calls, e)
	}
}
