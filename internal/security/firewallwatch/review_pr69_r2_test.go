package firewallwatch

// Regression witnesses from the independent PR69 review r2 (Codex,
// review-pr69-r2.md), kept as written by the reviewer except where noted.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// Losing a silent refresh inside save_interval must not add cap-pressure
// re-emission beyond the operator's sole accepted early-retention path.
// An explicit heartbeat is the durable positive control.
//
// Keeper's adaptation after the sysadmin amendment j_P52e7w (2026-10-29): a
// key whose latest refresh was not yet appended may re-emit once after a
// crash, through count-pressure eviction choice too. This pins that bound for
// the A/B/C/D sequence: after D, observing the refreshed key A re-emits
// exactly once after a crash, and nothing uninterrupted or with a heartbeat.
func TestR2UnappendedCapRefresh(t *testing.T) {
	for _, beat := range []bool{false, true} {
		t.Run(fmt.Sprint(beat), func(t *testing.T) {
			run := func(crash bool) []Event {
				s := pruneFixture(t, 3)
				now := time.Now().Round(0)
				observeFlush(t, s, newKey(1), now.Add(-2*time.Minute))
				observeFlush(t, s, newKey(2), now.Add(-time.Minute))
				observeFlush(t, s, newKey(3), now.Add(-30*time.Second))
				if e := s.Save(now.Add(-time.Second)); e != nil {
					t.Fatal(e)
				}
				seq := s.seq
				observeFlush(t, s, newKey(1), now)
				if s.seq != seq {
					t.Fatal("fixture: refresh unexpectedly appended")
				}
				if beat {
					if e := s.Checkpoint(now); e != nil {
						t.Fatal(e)
					}
				}
				if crash {
					s = reopen(t, s.Config)
				}
				observeFlush(t, s, newKey(4), now.Add(time.Second))
				return s.Observe(newKey(1), now.Add(2*time.Second), ruleClassify)
			}
			uninterrupted, crashed := run(false), run(true)
			want := 0
			if !beat {
				want = 1
			}
			if len(uninterrupted) != 0 || len(crashed) != want {
				t.Fatalf("heartbeat=%t: uninterrupted re-emits %v, after crash %v; want none, and after a crash without heartbeat app1 once", beat, eventApps(uninterrupted), eventApps(crashed))
			}
		})
	}
}

// A complete window after the latest short stall remains complete in digest
// immediately after a heartbeat, just as after a full snapshot. Reader
// compaction must not absorb the running source's clean open span.
func TestR2CoverageCleanTail(t *testing.T) {
	s := pruneFixture(t, 3)
	base := time.Now().Add(-time.Hour).Round(0)
	s.BeginCoverage(base)
	alf := s.Coverage("")
	alf.StallCoverage(base.Add(time.Second))
	alf.ResumeCoverage(base.Add(1100 * time.Millisecond))
	if e := s.Save(base.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	alf.StallCoverage(base.Add(3 * time.Second))
	alf.ResumeCoverage(base.Add(3100 * time.Millisecond))
	alf.StallCoverage(base.Add(4 * time.Second))
	alf.ResumeCoverage(base.Add(4100 * time.Millisecond))
	if e := s.Checkpoint(base.Add(6 * time.Second)); e != nil {
		t.Fatal(e)
	}
	start, end := base.Add(4200*time.Millisecond), base.Add(5800*time.Millisecond)
	want := s.Split(start, end).Window
	got := reopen(t, s.Config).Split(start, end).Window
	if want.Truncated {
		t.Fatal("fixture: runtime clean tail truncated")
	}
	if e := s.Save(base.Add(6 * time.Second)); e != nil {
		t.Fatal(e)
	}
	control := reopen(t, s.Config).Split(start, end).Window
	if control.Truncated {
		t.Fatal("snapshot control truncated")
	}
	if got.Truncated != want.Truncated {
		t.Fatalf("clean tail: runtime truncated=%t gaps=%v; heartbeat reader truncated=%t gaps=%v coalesced=%+v; snapshot reader truncated=%t", want.Truncated, want.CoverageGaps, got.Truncated, got.CoverageGaps, got.CoalescedShortStalls, control.Truncated)
	}
}

// PR66's independent wall/monotonic readings can prune an event that is not
// the wall-time oldest. Delta replay must reproduce the actual event removal
// rather than infer it from events_len. Snapshot is the positive control.
func TestR2EventRemovalAcrossWallCorrection(t *testing.T) {
	s := pruneFixture(t, 2)
	base := time.Now()
	// A came from an earlier snapshot made under a forward wall reading.
	futureA := base.Add(12 * time.Hour).Round(0)
	s.Observe(newKey(1), futureA, ruleClassify)
	start := sameWallLaterMono(t, base, 16*24*time.Hour)
	if e := s.Save(start); e != nil {
		t.Fatal(e)
	}
	s = reopen(t, s.Config) // snapshot times have no monotonic reading
	if e := s.Save(start); e != nil {
		t.Fatal(e)
	} // Run's mandatory startup snapshot
	// Only one second of monotonic time elapses between B and C, but the
	// wall advances eight days. Loaded A expires by wall; in-run B does not.
	later := sameWallLaterMono(t, base.Add(8*24*time.Hour), 8*24*time.Hour+time.Second)
	observeFlush(t, s, newKey(2), start)
	observeFlush(t, s, newKey(3), later)
	if s.journalRecords != 2 {
		t.Fatalf("fixture: expected 2 journal appends, got %d (unexpected snapshot)", s.journalRecords)
	}
	want := eventApps(s.State.Events)
	if !reflect.DeepEqual(want, []string{"app2", "app3"}) {
		t.Fatal("fixture runtime", want)
	}
	// The wall corrects back before the reader opens, while monotonic time
	// has advanced only seconds. Reopen must not resurrect the removed A.
	got := eventApps(reopen(t, s.Config).State.Events)
	if e := s.Save(start.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	control := eventApps(reopen(t, s.Config).State.Events)
	if !reflect.DeepEqual(control, want) {
		t.Fatal("snapshot control", control, want)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime events=%v; journal reader=%v; snapshot control=%v", want, got, control)
	}
}

// Every acknowledged append stays within the reader limit, including every
// intermediate crossing; at least one real fallback snapshot must occur.
func TestR2ByteBoundEveryAppend(t *testing.T) {
	s, c := journalStore(t)
	c.MaxStateBytes = 4096
	s.Config = c
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	snapshots := 0
	s.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "state.json" {
			snapshots++
		}
		return atomicWrite(path, b)
	}
	it := Item{Source: "alf", App: "deny", Verdict: "deny", Remote: "lan"}
	for i := 0; i < 40; i++ {
		observeFlush(t, s, it, now.Add(time.Duration(i)*time.Millisecond))
		if raw, e := os.ReadFile(s.journalPath()); e == nil && int64(len(raw)) > c.MaxStateBytes {
			t.Fatalf("step %d oversized journal %d", i, len(raw))
		}
		got := reopen(t, c)
		a, _ := json.Marshal(s.State.Entries)
		b, _ := json.Marshal(got.State.Entries)
		if string(a) != string(b) || len(got.State.Events) != len(s.State.Events) {
			t.Fatalf("step %d replay differs", i)
		}
	}
	if snapshots == 0 {
		t.Fatal("fixture: no actual threshold crossing")
	}
}

// A coverage tail with an open source evicted at snapshot is restored by
// heartbeat, then the reader's canonical prune retains equivalent coverage.
func TestR2EvictedSourceAndPendingCoalescing(t *testing.T) {
	for _, cap := range []int{1, 3} {
		t.Run(fmt.Sprint(cap), func(t *testing.T) {
			s := pruneFixture(t, cap)
			base := time.Now().Add(-time.Hour).Round(0)
			s.BeginCoverage(base)
			s.BeginSourceCoverage(SourceNetfilter, base.Add(time.Second))
			if e := s.Save(base.Add(2 * time.Second)); e != nil {
				t.Fatal(e)
			}
			alf := s.Coverage("")
			for i := 0; i < 10; i++ {
				at := base.Add(time.Duration(i+3) * time.Second)
				alf.StallCoverage(at)
				alf.ResumeCoverage(at.Add(100 * time.Millisecond))
			}
			if e := s.Checkpoint(base.Add(14 * time.Second)); e != nil {
				t.Fatal(e)
			}
			got := reopen(t, s.Config)
			same := &Store{Config: s.Config, State: State{Entries: map[string]*Entry{}, Signers: map[string]SignerEntry{}}}
			raw, _ := json.Marshal(s.State.Coverage)
			json.Unmarshal(raw, &same.State.Coverage)
			same.prune(time.Now())
			a, _ := json.Marshal(same.State.Coverage)
			b, _ := json.Marshal(got.State.Coverage)
			if string(a) != string(b) {
				t.Fatalf("cap=%d runtime-pruned=%s replay=%s", cap, a, b)
			}
			if _, e := os.Stat(filepath.Join(s.Config.StateDir, "state.json")); e != nil {
				t.Fatal(e)
			}
		})
	}
}

// A new/changed signer on a repeat nettop key must be durable before a
// following slow row can block. The first row emits no event; a checkpoint
// demonstrates that the record is serializable and otherwise restorable.
func TestR2SilentSampleSigner(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	path := filepath.Join(t.TempDir(), "executable")
	if e := os.WriteFile(path, []byte("old"), 0600); e != nil {
		t.Fatal(e)
	}
	text := fmt.Sprintf(",bytes_out\n%s.123,\n127.0.0.1:1000<->192.168.0.1:443,10\n", path)
	items, unknown := ParseNettop(text)
	if len(items) != 1 || unknown != 0 {
		t.Fatal("fixture parse", items, unknown)
	}
	it := items[0]
	result := "Developer ID: old"
	s.inspectSigner = func(context.Context, string) (string, error) { return result, nil }
	s.signer(context.Background(), path)
	observeFlush(t, s, it, now)
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("updated executable"), 0600); e != nil {
		t.Fatal(e)
	}
	result = "Developer ID: changed"
	calls := 0
	collect := func(it Item) bool { return s.collect(context.Background(), &Classifier{}, it) }
	flush := func(emitted bool) error { calls++; return s.Flush(time.Now(), emitted, false) }
	emitted, e := collectSample(items, collect, flush, noDrain)
	if e != nil || emitted {
		t.Fatal("fixture", emitted, e)
	}
	urgent := s.delta.urgent
	got := reopen(t, c)
	if e := s.Checkpoint(time.Now()); e != nil {
		t.Fatal(e)
	}
	control := reopen(t, c)
	var before, after string
	for _, v := range got.State.Signers {
		before = v.Value
	}
	for _, v := range control.State.Signers {
		after = v.Value
	}
	if after != result {
		t.Fatal("checkpoint control missing changed signer", after)
	}
	if before != result {
		t.Fatalf("parsed repeat nettop row invoked flush %d times, urgent=%t; crash restores %q before checkpoint, %q after it", calls, urgent, before, after)
	}
}
