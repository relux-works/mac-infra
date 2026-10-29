package firewallwatch

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"
)

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

// atCap fills a store to max entries, events and coverage spans with times
// taken from the running clock, as a live watcher holds them.
func atCap(t *testing.T, max int) (*Store, time.Time) {
	t.Helper()
	s := pruneFixture(t, max)
	now := time.Now()
	start := now.Add(-time.Hour)
	for i := 0; i < max; i++ {
		seen := start.Add(time.Duration(i) * time.Millisecond)
		s.State.Entries[fmt.Sprintf("app%05d|nettop|observed|lan", i)] = &Entry{FirstSeen: seen, LastSeen: seen, WindowStart: seen, Count: 1}
		s.State.Events = append(s.State.Events, Event{TS: seen, Source: "nettop", App: fmt.Sprintf("app%05d", i), Label: "noise", Reason: "x", Mode: "shadow", Counts: 1})
		s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: seen, End: seen.Add(time.Microsecond)})
	}
	return s, now
}

// BUG-261029-do8v1i regression witness: at a 10000-entry, 10000-event,
// 10000-span cap, a repeat observation allocates far less than one copy of
// the events or spans; the pre-fix full prune per observation copied both
// twice. A new key at the cap still holds every bound at once. Bytes, not
// timing, keep this deterministic.
func TestObserveAtCapDoesNotPrune(t *testing.T) {
	const max = 10000
	s, now := atCap(t, max)
	it := Item{App: "app09999", Source: "nettop", Verdict: "observed", Remote: "lan"}
	s.Observe(it, now, ruleClassify)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const runs = 20
	for i := 0; i < runs; i++ {
		s.Observe(it, now, ruleClassify)
	}
	runtime.ReadMemStats(&after)
	copyBytes := uint64(max) * uint64(min(unsafe.Sizeof(Event{}), unsafe.Sizeof(CoverageSpan{})))
	if perCall := (after.TotalAlloc - before.TotalAlloc) / runs; perCall >= copyBytes/16 {
		t.Fatalf("repeat observation at cap allocated %d bytes per call; one copy is %d", perCall, copyBytes)
	}
	s.Observe(Item{App: "brand-new", Source: "nettop", Verdict: "observed", Remote: "lan"}, now, ruleClassify)
	if len(s.State.Entries) != max || len(s.State.Events) != max || len(s.State.Coverage) != max {
		t.Fatalf("bounds after a new key: entries %d events %d coverage %d", len(s.State.Entries), len(s.State.Events), len(s.State.Coverage))
	}
}

// An observation still decides its own key's expiry exactly: an entry last
// seen before the retention cutoff is new again (count 1, a fresh first-seen,
// a new event), while the same entry inside retention is a silent repeat.
func TestObserveExpiresOwnKey(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name    string
		age     time.Duration
		newKey  bool
		wantCnt uint64
	}{
		{"expired", 8 * 24 * time.Hour, true, 1}, // testConfig retains 7 days
		{"retained", 6 * 24 * time.Hour, false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := pruneFixture(t, 20)
			it := Item{App: "own", Source: "nettop", Verdict: "observed", Remote: "lan"}
			old := now.Add(-tc.age)
			s.State.Entries[key(cleanItem(it))] = &Entry{FirstSeen: old, LastSeen: old, WindowStart: old, Count: 1}
			events := s.Observe(it, now, ruleClassify)
			e := s.State.Entries[key(cleanItem(it))]
			if (len(events) > 0) != tc.newKey || e.Count != tc.wantCnt || e.FirstSeen.Equal(now) != tc.newKey {
				t.Fatalf("events %d count %d first_seen %v", len(events), e.Count, e.FirstSeen)
			}
		})
	}
}

// Expiry of items nobody observes waits for the next Save, as it did
// whenever nothing was observed: after an observation of another key the
// expired entry, event and coverage span are still in memory; the next Save
// removes all three, advances both watermarks, and the reload agrees.
func TestUnobservedExpiryAtSave(t *testing.T) {
	s := pruneFixture(t, 20)
	now := time.Now()
	old := now.Add(-8 * 24 * time.Hour)
	s.State.Entries["stale|nettop|observed|lan"] = &Entry{FirstSeen: old, LastSeen: old, WindowStart: old, Count: 1}
	s.State.Events = []Event{{TS: old, Source: "nettop", App: "stale", Verdict: "observed", Label: "noise", Reason: "x", Mode: "shadow", Counts: 1}}
	s.State.Coverage = []CoverageSpan{{Start: old.Add(-time.Hour), End: old}}
	s.Observe(Item{App: "other", Source: "nettop", Verdict: "observed", Remote: "lan"}, now, ruleClassify)
	if s.State.Entries["stale|nettop|observed|lan"] == nil || len(s.State.Events) != 2 || len(s.State.Coverage) != 1 {
		t.Fatalf("observation expired unobserved state early: entries %d events %d coverage %d", len(s.State.Entries), len(s.State.Events), len(s.State.Coverage))
	}
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenStore(s.Config)
	if e != nil {
		t.Fatal(e)
	}
	for _, st := range []*Store{s, reopened} {
		if st.State.Entries["stale|nettop|observed|lan"] != nil || len(st.State.Events) != 1 || st.State.Events[0].App != "other" || len(st.State.Coverage) != 0 {
			t.Fatalf("save kept expired state: entries %d events %v coverage %d", len(st.State.Entries), st.State.Events, len(st.State.Coverage))
		}
		if !st.State.EvictedThrough.Equal(old) || !st.State.CoverageEvictedThrough.Equal(old) {
			t.Fatalf("watermarks %v %v, want %v", st.State.EvictedThrough, st.State.CoverageEvictedThrough, old)
		}
	}
}

// PR66 review r1: a backward wall-clock correction does not undo expiry an
// earlier, later-reading observation decided. A key whose entry expired at
// that observation is new again when seen after the correction (count 1, a
// fresh first-seen, a row at the corrected time that the Save persists), and
// a span that expired then is gone after a Save at the corrected time, with
// its watermark, in memory, in Split and after reload. A rollback beyond
// retention does not let the earlier clock expire later entries. Times
// without a monotonic reading model loaded state and a stepped wall clock.
func TestClockCorrectionKeepsExpiry(t *testing.T) {
	base := time.Now().Round(0)
	old := base.Add(-7*24*time.Hour - time.Second) // testConfig retains 7 days
	rolled := base.Add(-2 * time.Second)
	t.Run("observed key", func(t *testing.T) {
		s := pruneFixture(t, 20)
		it := Item{App: "old", Source: "nettop", Verdict: "observed", Remote: "lan"}
		s.Observe(it, old, ruleClassify)
		s.Observe(Item{App: "other", Source: "nettop", Verdict: "observed", Remote: "lan"}, base, ruleClassify)
		events := s.Observe(it, rolled, ruleClassify)
		e := s.State.Entries[key(cleanItem(it))]
		if len(events) != 1 || e.Count != 1 || !e.FirstSeen.Equal(rolled) {
			t.Fatalf("expired key resurrected: events %d count %d first_seen %v", len(events), e.Count, e.FirstSeen)
		}
		if err := s.Save(rolled); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(s.Config)
		if err != nil {
			t.Fatal(err)
		}
		rows := 0
		for _, ev := range reopened.State.Events {
			if ev.App == it.App && ev.TS.Equal(rolled) {
				rows++
			}
		}
		if rows != 1 {
			t.Fatalf("new-key rows at the corrected time: %d", rows)
		}
	})
	t.Run("saved coverage", func(t *testing.T) {
		s := pruneFixture(t, 20)
		s.State.Coverage = []CoverageSpan{{Start: old.Add(-time.Hour), End: old}}
		s.Observe(Item{App: "other", Source: "nettop", Verdict: "observed", Remote: "lan"}, base, ruleClassify)
		if err := s.Save(rolled); err != nil {
			t.Fatal(err)
		}
		reopened, err := OpenStore(s.Config)
		if err != nil {
			t.Fatal(err)
		}
		for _, st := range []*Store{s, reopened} {
			if len(st.State.Coverage) != 0 || !st.State.CoverageEvictedThrough.Equal(old) {
				t.Fatalf("expired span resurrected: spans %d watermark %v", len(st.State.Coverage), st.State.CoverageEvictedThrough)
			}
		}
		if !s.Split(old.Add(-time.Minute), old).Window.Truncated {
			t.Fatal("split of the expired minute not truncated")
		}
	})
	// A rollback longer than retention: a key first seen after it is judged
	// by cutoffs from then on, as before, so its next sighting is a repeat.
	t.Run("rollback beyond retention", func(t *testing.T) {
		s := pruneFixture(t, 20)
		s.Observe(Item{App: "other", Source: "nettop", Verdict: "observed", Remote: "lan"}, base, ruleClassify)
		back := base.Add(-8 * 24 * time.Hour)
		it := Item{App: "during", Source: "nettop", Verdict: "observed", Remote: "lan"}
		s.Observe(it, back, ruleClassify)
		events := s.Observe(it, back.Add(time.Second), ruleClassify)
		if e := s.State.Entries[key(cleanItem(it))]; len(events) != 0 || e == nil || e.Count != 2 {
			t.Fatalf("entry from after the rollback expired by the older clock: events %d entry %+v", len(events), e)
		}
	})
	// Control: without the later observation, a Save at the corrected time
	// keeps a span that has not expired by its own clock.
	t.Run("no later observation", func(t *testing.T) {
		s := pruneFixture(t, 20)
		end := rolled.Add(-7*24*time.Hour + time.Second)
		s.State.Coverage = []CoverageSpan{{Start: end.Add(-time.Hour), End: end}}
		if err := s.Save(rolled); err != nil {
			t.Fatal(err)
		}
		if len(s.State.Coverage) != 1 || !s.State.CoverageEvictedThrough.IsZero() {
			t.Fatalf("unexpired span removed: %v", s.State.Coverage)
		}
	})
}

// sameWallLaterMono returns base with its monotonic reading advanced by d and
// its wall reading unchanged, as after a wall correction that nets to zero.
// The time API cannot build this, so it uses the time.Time layout (wall with
// the monotonic flag in its top bit, ext holding the monotonic reading); the
// checks fail the test if a Go release changes that layout.
func sameWallLaterMono(t *testing.T, base time.Time, d time.Duration) time.Time {
	t.Helper()
	v := base
	raw := (*struct {
		wall uint64
		ext  int64
		loc  *time.Location
	})(unsafe.Pointer(&v))
	if raw.wall>>63 != 1 {
		t.Fatal("base needs a monotonic reading")
	}
	raw.ext += int64(d)
	if !v.Round(0).Equal(base.Round(0)) || v.Sub(base) != d || !base.Before(v) {
		t.Fatal("unexpected time.Time layout")
	}
	return v
}

// PR66 review r2: a later observation with the same wall reading but a later
// monotonic reading expires in-run state, and a Save handed the earlier time
// still applies that decision. The old entry, its event and its span are gone
// from state.json with both watermarks set, as before PR66. With increasing
// wall readings the same holds (control).
func TestEqualWallLaterMonotonicExpiry(t *testing.T) {
	const retention = 7 * 24 * time.Hour // testConfig retains 7 days
	for _, tie := range []bool{true, false} {
		t.Run(fmt.Sprintf("wall tie %v", tie), func(t *testing.T) {
			s := pruneFixture(t, 20)
			base := time.Now()
			oldT := base.Add(3 * time.Second)
			a := base.Add(retention + 2*time.Second) // oldT is retained at a
			b := a.Add(2 * time.Second)              // and expired at b
			if tie {
				b = sameWallLaterMono(t, a, 2*time.Second)
			}
			old := Item{App: "old", Source: "nettop", Verdict: "observed", Remote: "lan"}
			s.Observe(old, oldT, ruleClassify)
			s.State.Coverage = []CoverageSpan{{Start: oldT.Add(-time.Hour), End: oldT}}
			other := Item{App: "other", Source: "nettop", Verdict: "observed", Remote: "lan"}
			s.Observe(other, a, ruleClassify)
			s.Observe(other, b, ruleClassify)
			if err := s.Save(a); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(s.Config.StateDir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			var persisted State
			if err := json.Unmarshal(raw, &persisted); err != nil {
				t.Fatal(err)
			}
			if persisted.Entries[key(cleanItem(old))] != nil || len(persisted.Events) != 1 || persisted.Events[0].App != "other" || len(persisted.Coverage) != 0 {
				t.Fatalf("expired state persisted: entries %d events %v coverage %d", len(persisted.Entries), persisted.Events, len(persisted.Coverage))
			}
			if !persisted.EvictedThrough.Equal(oldT) || !persisted.CoverageEvictedThrough.Equal(oldT) {
				t.Fatalf("watermarks %v %v, want %v", persisted.EvictedThrough, persisted.CoverageEvictedThrough, oldT)
			}
		})
	}
}

// A backward wall step costs one full prune: the first observation after it
// applies the earlier decisions, later ones at the corrected clock allocate
// far less than one copy of the state again.
func TestClockCorrectionPrunesOnce(t *testing.T) {
	const max = 10000
	s, now := atCap(t, max)
	it := Item{App: "app09999", Source: "nettop", Verdict: "observed", Remote: "lan"}
	s.Observe(it, now.Round(0), ruleClassify)
	rolled := now.Round(0).Add(-2 * time.Second)
	s.Observe(it, rolled, ruleClassify)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const runs = 20
	for i := 0; i < runs; i++ {
		s.Observe(it, rolled, ruleClassify)
	}
	runtime.ReadMemStats(&after)
	copyBytes := uint64(max) * uint64(min(unsafe.Sizeof(Event{}), unsafe.Sizeof(CoverageSpan{})))
	if perCall := (after.TotalAlloc - before.TotalAlloc) / runs; perCall >= copyBytes/16 {
		t.Fatalf("observation after the step allocated %d bytes per call; one copy is %d", perCall, copyBytes)
	}
}

// When an observation pushes a bound over max_entries it runs the full
// prune at once: expired entries go first, so a new key at the cap with one
// expired entry present evicts that entry and keeps every retained one.
func TestObserveOverCapRunsFullPrune(t *testing.T) {
	s := pruneFixture(t, 2)
	now := time.Now()
	old, recent := now.Add(-8*24*time.Hour), now.Add(-time.Minute)
	s.State.Entries["expired|nettop|observed|lan"] = &Entry{FirstSeen: old, LastSeen: old, WindowStart: old, Count: 1}
	s.State.Entries["recent|nettop|observed|lan"] = &Entry{FirstSeen: recent, LastSeen: recent, WindowStart: recent, Count: 1}
	it := Item{App: "new", Source: "nettop", Verdict: "observed", Remote: "lan"}
	s.Observe(it, now, ruleClassify)
	if len(s.State.Entries) != 2 || s.State.Entries["recent|nettop|observed|lan"] == nil || s.State.Entries[key(cleanItem(it))] == nil {
		t.Fatalf("entries after over-cap observation: %v", s.State.Entries)
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
		if emitted, e := collectSample(items, collect, flush, noDrain); e != nil || !emitted {
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
		if _, e := collectSample(items, collect, flush, noDrain); e != nil {
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
		if _, e := collectSample(items, collect, flush, noDrain); !errors.Is(e, failed) || collected != 2 {
			t.Fatalf("error %v after %d items; want disk full after 2", e, collected)
		}
	})
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
