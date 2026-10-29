package firewallwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func requireGap(t *testing.T, w SplitWindow, kind string, from, to time.Time) {
	t.Helper()
	if !w.Truncated || len(w.CoverageGaps) != 1 || w.CoverageGaps[0].Kind != kind || !w.CoverageGaps[0].From.Equal(from) || !w.CoverageGaps[0].To.Equal(to) {
		t.Fatalf("want %s [%s, %s], got %+v", kind, from, to, w)
	}
}

// A real ten-minute stop between saved runs remains exactly not_running after reload.
func TestCoverageRestartKind(t *testing.T) {
	c := testConfig(t)
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	stop, restart := start.Add(5*time.Minute), start.Add(15*time.Minute)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginCoverage(start)
	s.EndCoverage(stop)
	if err = s.Save(stop.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginCoverage(restart)
	end := restart.Add(time.Minute)
	if err = s.Save(end); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	requireGap(t, s.Split(start, end).Window, GapNotRunning, stop, restart)
}

// Exact stalls, including an open tail inside the grace, persist as stall rather than not_running.
func TestCoverageStallKindPersistence(t *testing.T) {
	c := testConfig(t)
	start := time.Now().Add(-time.Hour).Truncate(time.Second)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	s.BeginCoverage(start)
	stalled := start.Add(time.Minute)
	s.StallCoverage(stalled)
	if err = s.Save(stalled.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	requireGap(t, loaded.Split(start, stalled.Add(time.Second)).Window, GapStall, stalled, stalled.Add(time.Second))
	resumed := stalled.Add(2 * time.Minute)
	s.ResumeCoverage(resumed)
	if err = s.Save(resumed.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	requireGap(t, loaded.Split(start, resumed.Add(time.Minute)).Window, GapStall, stalled, resumed)
	// Stopping while stalled must close the stall at EOF, then report downtime.
	s.StallCoverage(resumed.Add(2 * time.Minute))
	s.EndCoverage(resumed.Add(3 * time.Minute))
	if err = s.Save(resumed.Add(10 * time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	gaps := loaded.Split(resumed.Add(time.Minute), resumed.Add(10*time.Minute)).Window.CoverageGaps
	if len(gaps) != 2 || gaps[0].Kind != GapStall || gaps[1].Kind != GapNotRunning || !gaps[0].To.Equal(gaps[1].From) || !gaps[1].From.Equal(resumed.Add(3*time.Minute)) {
		t.Fatal(gaps)
	}
}

// 10001 micro-stalls within 24h cannot evict the covered start, with or without intervening saves.
func TestCoverageMicroStallStorm(t *testing.T) {
	for _, batch := range []int{2000, 10001} {
		t.Run(map[int]string{2000: "periodic_saves", 10001: "one_save"}[batch], func(t *testing.T) {
			c := testConfig(t)
			c.MaxEntries = 10000
			s, err := OpenStore(c)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().Add(-24 * time.Hour).Truncate(time.Second)
			s.BeginCoverage(start)
			for i := 1; i <= 10001; i++ {
				at := start.Add(time.Duration(i) * 7 * time.Second)
				s.StallCoverage(at)
				s.ResumeCoverage(at.Add(20 * time.Millisecond))
				if len(s.Coverage("").stalls) > c.MaxEntries {
					t.Fatal("pending observations exceeded bound")
				}
				if i%batch == 0 {
					if err = s.Save(at.Add(time.Second)); err != nil {
						t.Fatal(err)
					}
					if len(s.State.Coverage) > c.MaxEntries {
						t.Fatal("state exceeded bound")
					}
				}
			}
			end := start.Add(23 * time.Hour)
			if err = s.Save(end); err != nil {
				t.Fatal(err)
			}
			s, err = OpenStore(c)
			if err != nil {
				t.Fatal(err)
			}
			w := s.Split(start, end).Window
			if w.CoverageEvictedThrough != nil {
				t.Fatalf("micro-stalls evicted history: %+v", w)
			}
			if !w.Truncated {
				t.Fatal("coalesced stalls hid possible incompleteness")
			}
			if batch == 10001 && (len(w.CoverageGaps) != 0 || w.CoalescedShortStalls.Count != 10001 || w.CoalescedShortStalls.StalledNS != 10001*int64(20*time.Millisecond)) {
				t.Fatalf("coalesced-only storm is invisible in the split: %+v", w)
			}
			count, ns := uint64(0), int64(0)
			for _, span := range s.State.Coverage {
				count += span.ShortStalls
				ns += span.ShortStalledNS
			}
			for _, g := range w.CoverageGaps {
				if g.Kind != GapStall || !g.From.After(start) {
					t.Fatalf("leading or non-stall gap over a running watcher: %+v", g)
				}
				count++
				ns += int64(g.To.Sub(g.From))
			}
			if count == 0 {
				t.Fatal("storm was not compacted")
			}
			if count != 10001 || ns != 10001*int64(20*time.Millisecond) {
				t.Fatalf("lost stall accounting: count=%d ns=%d", count, ns)
			}
			if len(s.State.Coverage) > c.MaxEntries || s.validateState() != nil {
				t.Fatal("unbounded or invalid state")
			}
			t.Logf("stalls=%d spans=%d pending_bound=%d exact_gaps=%d", count, len(s.State.Coverage), c.MaxEntries, len(w.CoverageGaps))
		})
	}
}

// Forced count or age eviction persists an unknown prefix and truncation, never a fabricated stop.
func TestCoverageEvictionKind(t *testing.T) {
	for _, mode := range []string{"count", "pending", "age"} {
		t.Run(mode, func(t *testing.T) {
			c := testConfig(t)
			c.MaxEntries = 2
			s, err := OpenStore(c)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now().Add(-time.Hour).Truncate(time.Second)
			s.BeginCoverage(start)
			if mode == "age" {
				start = time.Now().Add(-8 * 24 * time.Hour).Truncate(time.Second)
				s.State.Coverage[0] = CoverageSpan{Start: start, End: start.Add(time.Minute)}
				s.coverage = nil
			} else {
				for i := 1; i <= 4; i++ {
					at := start.Add(time.Duration(i) * time.Minute)
					s.StallCoverage(at)
					s.ResumeCoverage(at.Add(time.Second))
					if mode == "count" {
						if err = s.Save(at.Add(2 * time.Second)); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			end := time.Now().Truncate(time.Second)
			if err = s.Save(end); err != nil {
				t.Fatal(err)
			}
			s, err = OpenStore(c)
			if err != nil {
				t.Fatal(err)
			}
			w := s.Split(start, end).Window
			if w.CoverageEvictedThrough == nil || !w.Truncated || len(w.CoverageGaps) == 0 {
				t.Fatal(w)
			}
			g := w.CoverageGaps[0]
			if g.Kind != GapCoverageEvicted || !g.From.Equal(start) || !g.To.Equal(*w.CoverageEvictedThrough) {
				t.Fatal(w)
			}
			if len(s.State.Coverage) > c.MaxEntries {
				t.Fatal("span bound exceeded")
			}
			// Even overlapping retained coverage cannot turn evicted time into a known stop or coverage.
			s.State.Coverage = []CoverageSpan{{Start: start, End: end}}
			requireGap(t, s.Split(start, end).Window, GapCoverageEvicted, start, *w.CoverageEvictedThrough)
		})
	}
}

// An uninterrupted complete window remains untruncated with no coverage or eviction gaps.
func TestCoverageCompleteWindowControl(t *testing.T) {
	s, err := OpenStore(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour)
	end := start.Add(time.Hour)
	s.BeginCoverage(start)
	if err = s.Save(end); err != nil {
		t.Fatal(err)
	}
	w := s.Split(start, end).Window
	if w.Truncated || len(w.CoverageGaps) != 0 || w.CoverageEvictedThrough != nil || w.CoalescedShortStalls != (CoalescedShortStalls{}) {
		t.Fatal(w)
	}
}

// An actual pre-change JSON layout loads unchanged; untyped historical gaps gain the default not_running kind.
func TestCoverageOldFormatState(t *testing.T) {
	c := testConfig(t)
	c.RetentionDays = 3650
	if err := safeDir(c.StateDir); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/state-before-coverage-kinds.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(c.StateDir, "state.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC)
	requireGap(t, s.Split(start, start.Add(time.Hour)).Window, GapNotRunning, start.Add(10*time.Minute), start.Add(11*time.Minute))
	if s.State.Health != (RunHealth{}) || !s.State.CoverageEvictedThrough.IsZero() {
		t.Fatal("new fields did not default safely")
	}
	if err = s.Save(start.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// Real fake-fed queue pressure and classification/save work produce persisted, fixed-size status summaries.
func TestRunHealthInstrumentation(t *testing.T) {
	c := testConfig(t)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	s.BeginCoverage(start)
	s.BeginSourceCoverage(SourceNetfilter, start)
	for _, source := range []string{"", SourceNetfilter} {
		tracker := s.Coverage(source)
		lines := make(chan []byte, 64)
		done := make(chan error, 1)
		go func() {
			done <- feedLines(context.Background(), bytes.NewBufferString(strings.Repeat("line\n", 70)), lines, tracker)
		}()
		deadline := time.Now().Add(5 * time.Second)
		for {
			tracker.mu.Lock()
			stalled := !tracker.stalledAt.IsZero()
			tracker.mu.Unlock()
			if stalled {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("no queue stall")
			}
			time.Sleep(time.Millisecond)
		}
		for range lines {
		}
		if err = <-done; err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	classify := func(Item) Decision { calls++; return Decision{Label: "digest", Reason: "test"} }
	for i := 0; i < 3; i++ {
		s.Observe(Item{App: "sample", Source: "alf", Verdict: "allow"}, time.Now(), classify)
	}
	if calls != 1 || s.State.Health.Classification.Count != 1 {
		t.Fatal("classification summary counted repeats")
	}
	s.atomicWrite = func(path string, raw []byte) error { time.Sleep(2 * time.Millisecond); return atomicWrite(path, raw) }
	if err = s.Flush(time.Now(), true, false); err != nil {
		t.Fatal(err)
	}
	first := s.State.Health.Save
	if first.Count != 1 || first.LastNS < int64(2*time.Millisecond) {
		t.Fatal("save did not include I/O", first)
	}
	if err = s.Save(time.Now()); err != nil {
		t.Fatal(err)
	}
	loaded, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	health := loaded.State.Health
	if health.LineQueueHighWater.ALF != 64 || health.LineQueueHighWater.Netfilter != 64 || !reflect.DeepEqual(health.Save, first) || health.Classification.Count != 1 || health.LineQueueHighWater.MaxAt.ALF == nil || health.LineQueueHighWater.MaxAt.Netfilter == nil || health.Classification.MaxAt == nil {
		t.Fatalf("health not persisted: %+v", health)
	}
	raw, err := json.Marshal(loaded.Status())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"line_queue_high_water", "run_loop_timing", "classification", "save", "last_ns", "max_ns", "count", "max_at"} {
		if !bytes.Contains(raw, []byte(`"`+key+`"`)) {
			t.Fatalf("status missing %s: %s", key, raw)
		}
	}
	summary := TimingSummary{Count: math.MaxUint64, MaxNS: 10}
	for i := 0; i < 10001; i++ {
		summary.observe(5, start)
	}
	if summary.Count != math.MaxUint64 || summary.LastNS != 5 || summary.MaxNS != 10 {
		t.Fatal("unbounded timing", summary)
	}
	if addCount(math.MaxUint64, 1) != math.MaxUint64 || addNS(math.MaxInt64, 1) != math.MaxInt64 {
		t.Fatal("counter overflow")
	}
}

// Compaction never merges a real stop, a one-second stall, or another source into ALF coverage.
func TestCoverageCompactionBoundaries(t *testing.T) {
	start := time.Now().Add(-time.Hour)
	for _, tc := range []struct {
		name   string
		stall  *CoverageStall
		source string
		want   int
	}{
		{"micro", &CoverageStall{From: start.Add(time.Minute), To: start.Add(time.Minute + 20*time.Millisecond)}, "", 1},
		{"threshold", &CoverageStall{From: start.Add(time.Minute), To: start.Add(time.Minute + time.Second)}, "", 2},
		{"real_stop", nil, "", 2},
		{"other_source", &CoverageStall{From: start.Add(time.Minute), To: start.Add(time.Minute + 20*time.Millisecond)}, SourceNetfilter, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next := start.Add(time.Minute + 20*time.Millisecond)
			if tc.stall != nil {
				next = tc.stall.To
			}
			spans := []CoverageSpan{{Start: start, End: start.Add(time.Minute), StallAfter: tc.stall}, {Start: next, End: next.Add(time.Minute), Source: tc.source}}
			compacted := compactCoverage(spans, nil)
			if len(compacted) != tc.want {
				t.Fatal(compacted)
			}
			if tc.want == 1 && (compacted[0].ShortStalls != 1 || compacted[0].ShortStalledNS != int64(20*time.Millisecond)) {
				t.Fatal(compacted)
			}
		})
	}
}

// Malformed new fields are refused and existing state byte and span bounds still apply.
func TestCoverageHealthStateBounds(t *testing.T) {
	c := testConfig(t)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour)
	base := CoverageSpan{Start: start, End: start.Add(time.Minute)}
	for _, mutate := range []func(){
		func() { s.State.Health.LineQueueHighWater.ALF = 65 },
		func() { s.State.Health.Save.LastNS = -1 },
		func() { s.State.Health.Classification = TimingSummary{LastNS: 2, MaxNS: 1, Count: 1} },
		func() { s.State.Coverage[0].ShortStalledNS = -1 },
		func() { s.State.Coverage[0].StallAfter = &CoverageStall{From: start, To: start.Add(2 * time.Minute)} },
		func() { s.State.Coverage = make([]CoverageSpan, c.MaxEntries+1) },
	} {
		s.State.Health = RunHealth{}
		s.State.Coverage = []CoverageSpan{base}
		mutate()
		if s.validateState() == nil {
			t.Fatal("malformed state admitted")
		}
	}
	s.State.Health = RunHealth{}
	s.State.Coverage = []CoverageSpan{base}
	s.Config.MaxStateBytes = 1
	if err = s.Save(time.Now()); err == nil || !strings.Contains(err.Error(), "max_state_bytes") {
		t.Fatal("byte limit bypassed", err)
	}
	if _, err = os.Stat(filepath.Join(c.StateDir, "state.json")); !os.IsNotExist(err) {
		t.Fatal("oversize state was written", err)
	}
}

// A stall timestamp delivered after a save corrects its optimistic end and retains the exact cause.
func TestCoverageLateStallReport(t *testing.T) {
	for _, closed := range []bool{false, true} {
		c := testConfig(t)
		s, err := OpenStore(c)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now().Add(-time.Hour)
		saved := start.Add(time.Minute)
		stalled := saved.Add(-time.Millisecond)
		s.BeginCoverage(start)
		if err = s.Save(saved); err != nil {
			t.Fatal(err)
		}
		s.StallCoverage(stalled)
		end := saved.Add(time.Minute)
		if closed {
			s.ResumeCoverage(end)
		}
		if err = s.Save(end); err != nil {
			t.Fatal(err)
		}
		loaded, err := OpenStore(c)
		if err != nil {
			t.Fatal(err)
		}
		requireGap(t, loaded.Split(start, end).Window, GapStall, stalled, end)
	}
}
