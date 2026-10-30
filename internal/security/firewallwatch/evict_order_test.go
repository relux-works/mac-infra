package firewallwatch

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
	"time"
)

// referencePruneItems is pruneItems as it was before the linear eviction pass
// (main d055484), kept verbatim as the differential oracle: it sorts every key
// and every event on each prune.
func referencePruneItems(s *Store, refs expiryRefs) {
	expired := func(t time.Time) bool { return s.expired(t, refs) }
	for k, v := range s.State.Entries {
		if expired(v.LastSeen) {
			delete(s.State.Entries, k)
			s.entryRemoved(k)
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
			s.entryRemoved(k)
		}
	}
	evicted := func(e Event) {
		if e.TS.After(s.State.EvictedThrough) {
			s.State.EvictedThrough = e.TS
		}
		s.eventRemoved(e)
	}
	events := s.State.Events[:0]
	for _, e := range s.State.Events {
		if !expired(e.TS) {
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
	if len(s.State.Signers) > s.Config.MaxEntries {
		keys := make([]string, 0, len(s.State.Signers))
		for k := range s.State.Signers {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := s.State.Signers[keys[i]], s.State.Signers[keys[j]]
			if a.LastSeen.Equal(b.LastSeen) {
				return keys[i] < keys[j]
			}
			return a.LastSeen.Before(b.LastSeen)
		})
		for _, k := range keys[:len(keys)-s.Config.MaxEntries] {
			delete(s.State.Signers, k)
			s.signerRemoved(k)
		}
	}
}

// pruneCase builds one random over-cap state. Times come from a small pool,
// so equal last-seen times (ties broken by key) are common; the pool mixes
// readings with and without a monotonic clock and times old enough to expire.
// It has no backward wall-clock correction, so time.Before is consistent on
// it and the previous full-sort prune is well defined.
func pruneCase(rng *rand.Rand, c Config, base time.Time) (*Store, expiryRefs) {
	retention := time.Duration(c.RetentionDays) * 24 * time.Hour
	var pool []time.Time
	for i := 0; i < 6; i++ {
		// Whole hours plus a random fraction of a second, so wall times
		// within one second differ too.
		d := time.Duration(rng.Intn(int(2*retention/time.Hour)))*time.Hour + time.Duration(rng.Int63n(int64(time.Second)))
		t := base.Add(-d)
		switch rng.Intn(3) {
		case 0:
			pool = append(pool, t) // monotonic reading
		case 1:
			pool = append(pool, t.Round(0)) // wall only
		default:
			// An earlier monotonic reading. Time.Add moves wall and
			// monotonic readings together, so these states have no
			// backward wall-clock correction (see the corrections test).
			pool = append(pool, t.Add(-time.Duration(rng.Intn(48))*time.Hour))
		}
	}
	at := func() time.Time { return pool[rng.Intn(len(pool))] }
	n := c.MaxEntries + rng.Intn(4) - 1 // under, at, and one to two over the cap
	s := &Store{Config: c}
	s.State.Entries = map[string]*Entry{}
	s.State.Signers = map[string]SignerEntry{}
	for i := 0; i < n; i++ {
		s.State.Entries[fmt.Sprintf("k%03d", rng.Intn(3*n+1))] = &Entry{LastSeen: at(), Count: uint64(i)}
		s.State.Signers[fmt.Sprintf("s%03d", rng.Intn(3*n+1))] = SignerEntry{Value: "v", LastSeen: at()}
	}
	for i := 0; i < n; i++ {
		s.State.Events = append(s.State.Events, Event{TS: at(), App: fmt.Sprintf("a%d", i)})
	}
	if rng.Intn(2) == 0 {
		// Usually the run loop appends events in time order.
		sort.SliceStable(s.State.Events, func(i, j int) bool { return s.State.Events[i].TS.Before(s.State.Events[j].TS) })
	}
	var refs expiryRefs
	for i := rng.Intn(3); i >= 0; i-- {
		refs.add(at().Add(retention))
	}
	return s, refs
}

func cloneForPrune(s *Store) *Store {
	c := &Store{Config: s.Config}
	c.State.EvictedThrough = s.State.EvictedThrough
	c.State.Entries = map[string]*Entry{}
	for k, v := range s.State.Entries {
		e := *v
		c.State.Entries[k] = &e
	}
	c.State.Signers = map[string]SignerEntry{}
	for k, v := range s.State.Signers {
		c.State.Signers[k] = v
	}
	c.State.Events = append([]Event(nil), s.State.Events...)
	return c
}

// Differential oracle for the linear eviction pass: on random states without
// a backward wall-clock correction, with ties, expired items, events out of
// time order, monotonic and wall-only readings, under the cap and one or more
// over it, at caps 1, 3 and 260,
// pruneItems leaves exactly the entries, events, signers and evicted-through
// time of the old full-sort prune, and records exactly the same removals for
// the journal. The verdict comes from the old algorithm itself, not from the
// new one. Negative controls: dropping the key tiebreak, picking the maximum
// and an unsorted multi-key overflow each fail it. States with a correction
// are covered by TestEvictionOrderWithClockCorrections.
func TestPruneItemsMatchesFullSortPrune(t *testing.T) {
	base := time.Now()
	rng := rand.New(rand.NewSource(261030))
	cases := 0
	covered := map[string]int{}
	for _, cap := range []int{1, 3, 260} {
		c := testConfig(t)
		c.MaxEntries = cap
		rounds := 3000
		if cap == 260 {
			rounds = 300
		}
		for round := 0; round < rounds; round++ {
			got, refs := pruneCase(rng, c, base)
			want := cloneForPrune(got)
			live, expiredEntries := 0, false
			for _, v := range got.State.Entries {
				if got.expired(v.LastSeen, refs) {
					expiredEntries = true
				} else {
					live++
				}
			}
			switch over := live - cap; {
			case over == 1:
				covered["entries one over"]++
			case over > 1:
				covered["entries several over"]++
			}
			if expiredEntries {
				covered["expired entries"]++
			}
			if live > cap {
				// Several live entries share the oldest time: the key decides.
				var oldest time.Time
				ties := 0
				for _, v := range got.State.Entries {
					if got.expired(v.LastSeen, refs) {
						continue
					}
					switch {
					case ties == 0 || v.LastSeen.Before(oldest):
						oldest, ties = v.LastSeen, 1
					case v.LastSeen.Equal(oldest):
						ties++
					}
				}
				if ties > 1 {
					covered["tie at the victim"]++
				}
			}
			if !sort.SliceIsSorted(got.State.Events, func(i, j int) bool { return got.State.Events[i].TS.Before(got.State.Events[j].TS) }) {
				covered["events out of order"]++
			}
			if len(got.State.Signers) > cap {
				covered["signers over"]++
			}
			got.pruneItems(refs)
			referencePruneItems(want, refs)
			if !reflect.DeepEqual(got.State.Entries, want.State.Entries) ||
				!reflect.DeepEqual(got.State.Events, want.State.Events) ||
				!reflect.DeepEqual(got.State.Signers, want.State.Signers) ||
				!got.State.EvictedThrough.Equal(want.State.EvictedThrough) {
				t.Fatalf("cap %d round %d: retained state differs from the full-sort prune", cap, round)
			}
			if !reflect.DeepEqual(got.delta.removedEntries, want.delta.removedEntries) ||
				!reflect.DeepEqual(got.delta.removedSigners, want.delta.removedSigners) ||
				!reflect.DeepEqual(got.delta.removedEvents, want.delta.removedEvents) {
				t.Fatalf("cap %d round %d: recorded removals differ from the full-sort prune", cap, round)
			}
			cases++
		}
	}
	t.Logf("%d states compared; paths: %v", cases, covered)
	// The oracle is only as good as the paths it reaches.
	for _, path := range []string{"entries one over", "entries several over", "expired entries", "events out of order", "signers over", "tie at the victim"} {
		if covered[path] < 100 {
			t.Fatalf("path %q reached only %d times", path, covered[path])
		}
	}
}

// oldestKeys returns the keys first in (last seen, key) order: the minimum by
// one pass for n == 1, the sorted prefix otherwise, and nothing for an empty
// map. Ties at one instant are broken by key, so map iteration order never
// decides. Positive controls: a single key, and n larger than the map.
func TestOldestKeysOrder(t *testing.T) {
	at := time.Now()
	m := map[string]time.Time{"b": at, "a": at, "c": at.Add(-time.Second), "d": at.Add(time.Second)}
	seen := func(t time.Time) time.Time { return t }
	for i := 0; i < 50; i++ { // map iteration order varies between runs
		if got := oldestKeys(m, seen, 1); !reflect.DeepEqual(got, []string{"c"}) {
			t.Fatalf("n=1: %v", got)
		}
		if got := oldestKeys(m, seen, 3); !reflect.DeepEqual(got, []string{"c", "a", "b"}) {
			t.Fatalf("n=3: %v", got)
		}
	}
	delete(m, "c")
	if got := oldestKeys(m, seen, 1); !reflect.DeepEqual(got, []string{"a"}) {
		t.Fatalf("tie at the minimum: %v", got)
	}
	if got := oldestKeys(map[string]time.Time{}, seen, 1); got != nil {
		t.Fatalf("empty map: %v", got)
	}
	if got := oldestKeys(map[string]time.Time{"x": at}, seen, 5); !reflect.DeepEqual(got, []string{"x"}) {
		t.Fatalf("n beyond the map: %v", got)
	}
}

// A wall correction between monotonic readings, with events loaded from
// state.json (wall-only), makes Before non-transitive: adjacent pairs can look
// ordered while the stable sort still moves an event. The prune must keep the
// stable sort's result, so retained events, the removed-event identities and
// the eviction watermark equal the previous prune's, at caps 20 and 10000.
// The state is reached through Observe and a JSON round trip; the host clock
// is not changed. Regression witness from an independent review; a sorted-check
// shortcut fails it.
func TestEventEvictionAfterClockCorrection(t *testing.T) {
	for _, cap := range []int{20, 10000} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			c := testConfig(t)
			c.MaxEntries = cap
			s := &Store{Config: c}
			s.State.Entries = map[string]*Entry{}
			s.State.Signers = map[string]SignerEntry{}
			at := time.Now()
			wall := at.Add(-time.Second).Round(0)
			for i := 0; i < cap-1; i++ {
				s.Observe(newKey(i), wall, ruleClassify)
			}
			raw, e := json.Marshal(s.State)
			if e != nil {
				t.Fatal(e)
			}
			s = &Store{Config: c}
			if e = json.Unmarshal(raw, &s.State); e != nil {
				t.Fatal(e)
			}
			if e = s.validateState(); e != nil {
				t.Fatal(e)
			}
			s.Observe(newKey(cap-1), at, ruleClassify)
			back := sameWallLaterMono(t, at.Add(-2*time.Second), 3*time.Second)
			want := cloneForPrune(s)
			referencePruneItems(want, s.refs.with(back))
			emitted := s.Observe(newKey(cap), back, ruleClassify)
			if len(emitted) != 1 {
				t.Fatalf("emissions=%d", len(emitted))
			}
			want.State.Events = append(want.State.Events, emitted...)
			referencePruneItems(want, s.refs)
			if !(wall.Before(at) && at.Before(back) && back.Before(wall)) {
				t.Fatal("fixture does not form the comparison cycle")
			}
			if !reflect.DeepEqual(s.State.Events, want.State.Events) ||
				!reflect.DeepEqual(s.delta.removedEvents, want.delta.removedEvents) ||
				!s.State.EvictedThrough.Equal(want.State.EvictedThrough) {
				t.Fatal("retained events, removed-event identities or the watermark differ from the previous prune")
			}
		})
	}
}

// orderViolation checks that less is a strict total order over the items
// 0..n-1 (all distinct): irreflexive, exactly one direction for every pair,
// and transitive over every triple. It returns the first violation found.
func orderViolation(n int, less func(i, j int) bool) string {
	for i := 0; i < n; i++ {
		if less(i, i) {
			return fmt.Sprintf("not irreflexive at %d", i)
		}
		for j := 0; j < n; j++ {
			if i != j && less(i, j) == less(j, i) {
				return fmt.Sprintf("pair %d,%d not ordered exactly one way", i, j)
			}
			for k := 0; k < n; k++ {
				if less(i, j) && less(j, k) && !less(i, k) {
					return fmt.Sprintf("not transitive: %d<%d<%d", i, j, k)
				}
			}
		}
	}
	return ""
}

// orderSample is a set of distinct keyed times: monotonic readings, the same
// instants without one (as loaded from state.json), readings taken after the
// wall clock was set back (same wall time or earlier, later monotonic time),
// repeated wall times, and the comparison cycle an independent review found.
func orderSample(t *testing.T, rng *rand.Rand) ([]string, []time.Time) {
	t.Helper()
	a := time.Now()
	keys := []string{"a", "b", "c"}
	times := []time.Time{a, a.Add(-time.Second).Round(0), sameWallLaterMono(t, a.Add(-2*time.Second), 3*time.Second)}
	for i := 0; len(keys) < 24; i++ {
		base := a.Add(-time.Duration(rng.Intn(5))*time.Second - time.Duration(rng.Intn(1000))*time.Millisecond)
		var at time.Time
		switch rng.Intn(4) {
		case 0:
			at = base
		case 1:
			at = base.Round(0)
		case 2:
			at = sameWallLaterMono(t, base, time.Duration(1+rng.Intn(5))*time.Second)
		default:
			at = sameWallLaterMono(t, base.Add(-time.Duration(rng.Intn(3))*time.Second), time.Duration(1+rng.Intn(5))*time.Second)
		}
		keys = append(keys, fmt.Sprintf("k%02d", i))
		times = append(times, at)
	}
	return keys, times
}

// The eviction order is a strict total order over mixed wall-only and
// monotonic times, wall-clock corrections and the review's cycle included, on
// 200 random samples. Negative control: the previous comparison (time.Before,
// with the key only for equal instants) fails the same check on the cycle.
func TestEvictionOrderIsStrictTotal(t *testing.T) {
	rng := rand.New(rand.NewSource(30))
	for round := 0; round < 200; round++ {
		keys, times := orderSample(t, rng)
		if v := orderViolation(len(keys), func(i, j int) bool { return evictFirst(keys[i], times[i], keys[j], times[j]) }); v != "" {
			t.Fatalf("round %d: eviction order %s", round, v)
		}
	}
	keys, times := orderSample(t, rng)
	previous := func(i, j int) bool {
		if times[i].Equal(times[j]) {
			return keys[i] < keys[j]
		}
		return times[i].Before(times[j])
	}
	if v := orderViolation(3, previous); v == "" {
		t.Fatal("control: the previous comparison should not be a total order on the cycle")
	}
}

// On the review's cycle (a: wall T with a monotonic reading; b: wall T-1s,
// loaded; c: wall T-2s read after the clock was set back) the victim is c,
// the earliest wall time, for every map iteration order, and the sorted prefix
// is c, b, a. Monotonic readings within one wall-clock tick are ordered by
// key, the documented difference from the previous comparison.
func TestEvictionOrderCycleAndSameTick(t *testing.T) {
	a := time.Now()
	times := map[string]time.Time{"a": a, "b": a.Add(-time.Second).Round(0), "c": sameWallLaterMono(t, a.Add(-2*time.Second), 3*time.Second)}
	seen := func(v time.Time) time.Time { return v }
	for i := 0; i < 50; i++ {
		if got := oldestKeys(times, seen, 1); !reflect.DeepEqual(got, []string{"c"}) {
			t.Fatalf("cycle victim %v; want c", got)
		}
		if got := oldestKeys(times, seen, 3); !reflect.DeepEqual(got, []string{"c", "b", "a"}) {
			t.Fatalf("cycle order %v; want c b a", got)
		}
	}
	tick := map[string]time.Time{"a": sameWallLaterMono(t, a, time.Second), "b": a}
	for i := 0; i < 50; i++ {
		if got := oldestKeys(tick, seen, 1); !reflect.DeepEqual(got, []string{"a"}) {
			t.Fatalf("same wall tick victim %v; want a (by key)", got)
		}
	}
}

// With backward wall-clock corrections (readings with the same or an earlier
// wall time but a later monotonic time) mixed with loaded wall-only times, at
// caps 1, 3 and 260, the prune evicts exactly the live entries and signers
// that come first by (wall time, key), computed independently from Unix
// nanoseconds, and two runs on copies of one state give the same result. It
// asserts that the generated states contain comparison cycles of the previous
// order, where that order had no defined victim.
func TestEvictionOrderWithClockCorrections(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	cyclic := 0
	for _, cap := range []int{1, 3, 260} {
		c := testConfig(t)
		c.MaxEntries = cap
		for round := 0; round < 300; round++ {
			keys, times := orderSample(t, rng)
			for len(keys) < cap+3 {
				keys = append(keys, fmt.Sprintf("x%04d", len(keys)))
				times = append(times, times[rng.Intn(len(times))])
			}
			s := &Store{Config: c}
			s.State.Entries = map[string]*Entry{}
			s.State.Signers = map[string]SignerEntry{}
			n := cap + 1 + rng.Intn(2)
			for i := 0; i < n && i < len(keys); i++ {
				s.State.Entries[keys[i]] = &Entry{LastSeen: times[i], Count: 1}
				s.State.Signers[keys[i]] = SignerEntry{Value: "v", LastSeen: times[i]}
			}
			// Does the inserted set (its first 24 items) contain a cycle of
			// the previous order?
			m := min(n, len(keys), 24)
			if orderViolation(m, func(i, j int) bool {
				if times[i].Equal(times[j]) {
					return keys[i] < keys[j]
				}
				return times[i].Before(times[j])
			}) != "" {
				cyclic++
			}
			type kt struct {
				key  string
				wall int64
			}
			var want []kt
			for k, e := range s.State.Entries {
				want = append(want, kt{k, e.LastSeen.UnixNano()})
			}
			sort.Slice(want, func(i, j int) bool {
				if want[i].wall != want[j].wall {
					return want[i].wall < want[j].wall
				}
				return want[i].key < want[j].key
			})
			kept := map[string]bool{}
			for _, w := range want[len(want)-cap:] {
				kept[w.key] = true
			}
			other := cloneForPrune(s)
			s.pruneItems(expiryRefs{})
			other.pruneItems(expiryRefs{})
			for _, got := range []map[string]bool{keysOf(s.State.Entries), keysOf(s.State.Signers)} {
				if !reflect.DeepEqual(got, kept) {
					t.Fatalf("cap %d round %d: kept %v; want %v", cap, round, got, kept)
				}
			}
			if !reflect.DeepEqual(s.State.Entries, other.State.Entries) || !reflect.DeepEqual(s.State.Signers, other.State.Signers) {
				t.Fatalf("cap %d round %d: two runs on one state differ", cap, round)
			}
		}
	}
	if cyclic < 100 {
		t.Fatalf("only %d states contained a cycle of the previous order", cyclic)
	}
	t.Logf("%d states with a cycle of the previous order", cyclic)
}

func keysOf[T any](m map[string]T) map[string]bool {
	out := map[string]bool{}
	for k := range m {
		out[k] = true
	}
	return out
}

func previousFirst(a string, at time.Time, b string, bt time.Time) bool {
	if at.Equal(bt) {
		return a < b
	}
	return at.Before(bt)
}

// Exact pairwise boundary of the order change: the new order agrees with the
// previous comparison for monotonic pairs whose monotonic and wall orders
// agree (forward steps included), mixed pairs, wall-only pairs and equal
// instants, and differs only for two in-run readings whose monotonic order
// differs from their wall order (equal wall with later monotonic, equal
// monotonic with later wall, wall set back). Keys oppose the time order so a
// tie decision is visible.
func TestEvictionOrderBoundary(t *testing.T) {
	a := time.Now()
	cases := []struct {
		name    string
		b       time.Time
		changed bool
	}{
		{"monotonic", a.Add(time.Second), false},
		{"mixed", a.Add(time.Second).Round(0), false},
		{"same instant mixed", a.Round(0), false},
		{"same instant", a, false},
		{"forward step, later monotonic", monoFrom(t, a.Add(time.Second), a.Add(time.Nanosecond)), false},
		{"same wall, later monotonic", sameWallLaterMono(t, a, time.Second), true},
		{"later wall, same monotonic", monoFrom(t, a.Add(time.Second), a), true},
		{"wall set back, later monotonic", sameWallLaterMono(t, a.Add(-2*time.Second), 3*time.Second), true},
	}
	for _, tc := range cases {
		previous, now := previousFirst("z", a, "a", tc.b), evictFirst("z", a, "a", tc.b)
		if (previous != now) != tc.changed {
			t.Fatalf("%s: previous=%v new=%v; changed should be %v", tc.name, previous, now, tc.changed)
		}
	}
	// A set with no cycle can still change: two in-run readings across a
	// backward step had a defined previous victim (a), the new one is c.
	c := sameWallLaterMono(t, a.Add(-2*time.Second), 3*time.Second)
	times := map[string]time.Time{"a": a, "c": c}
	if !previousFirst("a", a, "c", c) || previousFirst("c", c, "a", a) {
		t.Fatal("fixture: the previous order should evict a")
	}
	if got := oldestKeys(times, func(v time.Time) time.Time { return v }, 1); !reflect.DeepEqual(got, []string{"c"}) {
		t.Fatalf("victim %v; want c, the earlier wall time", got)
	}
}

// Times within one second are ordered by their full wall time, on both the
// one-pass and sorted paths, for entries and signers, with and without a
// monotonic reading; equal times fall back to key bytes. Negative control:
// truncating times to the second makes these a key tie and evicts the wrong
// one (the integer-second generators alone did not catch that).
func TestEvictionOrderSubsecond(t *testing.T) {
	at := time.Now()
	early := at.Add(-time.Duration(at.Nanosecond()) + 100*time.Millisecond)
	late := early.Add(100 * time.Millisecond)
	for _, wallOnly := range []bool{false, true} {
		a, b := early, late
		if wallOnly {
			a, b = a.Round(0), b.Round(0)
		}
		times := map[string]time.Time{"z": a, "a": b}
		for _, n := range []int{1, 2} {
			if got := oldestKeys(times, func(v time.Time) time.Time { return v }, n); !reflect.DeepEqual(got, []string{"z", "a"}[:n]) {
				t.Fatalf("wall-only=%v n=%d: %v", wallOnly, n, got)
			}
		}
		s := &Store{Config: Config{MaxEntries: 1, RetentionDays: 7}}
		s.State.Entries = map[string]*Entry{"z": {LastSeen: a}, "a": {LastSeen: b}}
		s.State.Signers = map[string]SignerEntry{"z": {LastSeen: a}, "a": {LastSeen: b}}
		s.pruneItems(expiryRefs{})
		want := map[string]bool{"a": true}
		if !reflect.DeepEqual(keysOf(s.State.Entries), want) || !reflect.DeepEqual(keysOf(s.State.Signers), want) {
			t.Fatalf("wall-only=%v: kept %v and %v", wallOnly, keysOf(s.State.Entries), keysOf(s.State.Signers))
		}
	}
	for _, pair := range [][2]string{{"Z", "a"}, {"a", "á"}, {"a\x00", "a\xff"}} {
		if !evictFirst(pair[0], at, pair[1], at) {
			t.Fatalf("tie not ordered by key bytes: %q", pair)
		}
	}
}

// The documented re-emit exposure stays with the key whose own refresh was
// lost. A refresh of A with a wall time before its recorded last_seen (after
// a wall clock correction) keeps that last_seen, so it cannot change which
// entry the cap evicts next and needs no append: a crash right after it gives
// the same eviction as the run, and fully durable B re-emits no more often
// after a crash than without one. With an explicit checkpoint after the
// refresh the same holds (control). Regression witness from an independent
// review; a refresh that moves last_seen back without being appended makes B
// re-emit only in the crashed run.
func TestBackwardRefreshKeepsEvictionOrderAcrossCrash(t *testing.T) {
	for _, beat := range []bool{false, true} {
		run := func(crash bool) int {
			s := pruneFixture(t, 3)
			base := time.Now()
			observeFlush(t, s, newKey(2), base.Add(-20*time.Second)) // A, first seen
			observeFlush(t, s, newKey(1), base)                      // B, durable, never refreshed
			observeFlush(t, s, newKey(2), base.Add(time.Second))     // A, durable refresh after B
			observeFlush(t, s, newKey(3), base.Add(2*time.Second))   // C
			if e := s.Save(base.Add(3 * time.Second)); e != nil {
				t.Fatal(e)
			}
			seq := s.seq
			back := sameWallLaterMono(t, base.Add(-10*time.Second), 14*time.Second)
			if es := observeFlush(t, s, newKey(2), back); len(es) != 0 {
				t.Fatal("backward refresh emitted")
			}
			if s.seq != seq || !s.State.Entries[key(newKey(2))].LastSeen.Equal(base.Add(time.Second)) {
				t.Fatalf("seq %d -> %d, last_seen %v; want the recorded last_seen kept and nothing appended", seq, s.seq, s.State.Entries[key(newKey(2))].LastSeen)
			}
			if beat {
				if e := s.Checkpoint(back); e != nil {
					t.Fatal(e)
				}
			}
			if crash {
				s = reopen(t, s.Config)
			}
			observeFlush(t, s, newKey(4), base.Add(5*time.Second))
			return len(observeFlush(t, s, newKey(1), base.Add(6*time.Second)))
		}
		if live, crashed := run(false), run(true); crashed > live {
			t.Fatalf("checkpoint=%v: durable B re-emits only after a crash: run %d, crashed %d", beat, live, crashed)
		}
	}
}
