package firewallwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Split puts each in-window event in at most one bucket with precedence
// real_deny > known_fp > needs_review. A non-nettop deny verdict (deny,
// denied, block, blocked, drop in any case) is real_deny whatever its label;
// a nettop row is never real_deny, and a verdict that merely contains a deny
// word is not one. Only decide rows enter known_fp or needs_review, and the three
// known-FP causes match only their exact source, verdict, reason, remote class
// and app. The reason is read from a string, a decoded map or a struct alike.
// The window counts only events in [since, asOf].
func TestSplitBuckets(t *testing.T) {
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	since := now.Add(-time.Hour)
	knnStruct := struct {
		Kind string `json:"kind"`
	}{Kind: "knn"}
	knnMap := map[string]any{"kind": "knn", "neighbours": []any{}}
	ev := func(min int, source, app, verdict, remote, label string, reason any) Event {
		return Event{TS: now.Add(time.Duration(min) * time.Minute), Source: source, App: app, Verdict: verdict, RemoteClass: remote, Label: label, Reason: reason}
	}
	s := &Store{State: State{Events: []Event{
		ev(-90, "alf", "old", "deny", "unknown", "decide", "hard_non_allow"),  // before since: excluded
		ev(-50, "alf", "a1", "deny", "unknown", "noise", "policy_apple_lan"),  // real_deny despite noise
		ev(-49, "alf", "a2", "block", "unknown", "decide", "hard_deny_spike"), // real_deny wins over known_fp
		ev(-48, "nettop", "Safari", "observed", "internet-raw-ip", "decide", "policy_raw_ip"),
		ev(-47, "nettop", "Safari", "observed", "internet-raw-ip", "digest", "policy_raw_ip"), // not decide: none
		ev(-46, "alf", "a3", "unknown", "unknown", "decide", "hard_non_allow"),
		ev(-45, "alf", "a4", "allow", "unknown", "decide", knnMap),
		ev(-44, "nettop", "/usr/bin/ssh", "observed", "loopback", "decide", knnStruct),
		ev(-43, "nettop", "limactl", "observed", "loopback", "decide", knnMap),
		ev(-42, "nettop", "curl", "observed", "loopback", "decide", knnMap),               // not ssh/limactl: review
		ev(-41, "nettop", "ssh", "observed", "internet", "decide", knnMap),                // not loopback: review
		ev(-40, "nettop", "ssh", "observed", "loopback", "decide", "policy_unusual_port"), // not knn: review
		ev(-39, "nettop", "x", "observed", "lan", "noise", "policy_apple_lan"),            // noise: none
		ev(-38, "alf", "a5", "DENIED", "unknown", "digest", "test"),                       // real_deny, case-folded
		ev(-37, "alf", "a6", "Blocked", "unknown", "", nil),                               // real_deny, empty label
		ev(-36, "alf", "a7", "drop", "unknown", "decide", "policy_raw_ip"),                // real_deny over known_fp
		ev(-35, "nettop", "n1", "deny", "internet", "decide", "policy_unusual_port"),      // nettop: review, not deny
		ev(-34, "alf", "a8", "verdict_code:2", "unknown", "decide", "hard_non_allow"),     // not a deny word: review
		ev(-33, "alf", "a9", "undeny", "unknown", "noise", "test"),                        // substring only: none
		ev(1, "alf", "future", "deny", "unknown", "decide", "test"),                       // after asOf: excluded
	}}}
	split := s.Split(since, now)
	var denied []string
	for _, row := range split.RealDeny {
		denied = append(denied, row.App)
	}
	if strings.Join(denied, ",") != "a1,a2,a5,a6,a7" {
		t.Fatalf("real_deny: %+v", split.RealDeny)
	}
	want := map[string]int{KnownFPNettopRawIP: 1, KnownFPALFUnknownOrAllow: 2, KnownFPLoopbackSSHKNN: 2}
	for group, count := range want {
		if g := split.KnownFP[group]; g.Count != count || len(g.Rows) != count {
			t.Errorf("%s: %+v, want %d", group, g, count)
		}
	}
	if len(split.NeedsReview) != 5 {
		t.Fatalf("needs_review: %+v", split.NeedsReview)
	}
	if split.Window.EventsInWindow != 18 || !split.Window.FirstTS.Equal(now.Add(-50*time.Minute)) || !split.Window.LastTS.Equal(now.Add(-33*time.Minute)) {
		t.Fatalf("window: %+v", split.Window)
	}
}

// truncated follows recorded watcher coverage, not event timestamps: an old
// retained event does not prove a stopped watcher covered the window. Each
// gap in [since, as_of] is reported: a stop, a restart, a late start, a tail
// beyond nettop_interval + save_interval (15s here), or no coverage at all
// (state written before coverage existed). The tail grace applies only after
// a span reached the window: a window shorter than or equal to the grace with
// no span, or with spans only before since, is one full gap. Unsorted
// overlapping spans merge.
func TestSplitCoverageTruncation(t *testing.T) {
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)
	at := func(d time.Duration) time.Time { return now.Add(d) }
	span := func(from, to time.Duration) CoverageSpan { return CoverageSpan{Start: at(from), End: at(to)} }
	gap := func(from, to time.Time) SplitGap { return SplitGap{From: from, To: to} }
	for _, tc := range []struct {
		name  string
		since time.Duration
		spans []CoverageSpan
		gaps  []SplitGap
	}{
		{name: "covered", spans: []CoverageSpan{span(-25*time.Hour, -10*time.Second)}, gaps: nil},
		{name: "tail at grace", spans: []CoverageSpan{span(-25*time.Hour, -15*time.Second)}, gaps: nil},
		{name: "merged overlap", spans: []CoverageSpan{span(-10*time.Hour, 0), span(-25*time.Hour, -9*time.Hour)}, gaps: nil},
		{name: "stopped watcher", spans: []CoverageSpan{span(-30*time.Hour, -12*time.Hour)}, gaps: []SplitGap{gap(at(-12*time.Hour), now)}},
		{name: "restart", spans: []CoverageSpan{span(-25*time.Hour, -6*time.Hour), span(-6*time.Hour+5*time.Second, 0)}, gaps: []SplitGap{gap(at(-6*time.Hour), at(-6*time.Hour+5*time.Second))}},
		{name: "late start", spans: []CoverageSpan{span(-20*time.Hour, 0)}, gaps: []SplitGap{gap(since, at(-20*time.Hour))}},
		{name: "tail past grace", spans: []CoverageSpan{span(-25*time.Hour, -16*time.Second)}, gaps: []SplitGap{gap(at(-16*time.Second), now)}},
		{name: "no coverage", spans: nil, gaps: []SplitGap{gap(since, now)}},
		{name: "short window covered", spans: []CoverageSpan{span(-time.Hour, -time.Second)}, gaps: nil, since: -10 * time.Second},
		{name: "short window no coverage", spans: nil, gaps: []SplitGap{gap(at(-10*time.Second), now)}, since: -10 * time.Second},
		{name: "grace-long window no coverage", spans: nil, gaps: []SplitGap{gap(at(-15*time.Second), now)}, since: -15 * time.Second},
		{name: "short window spans before since", spans: []CoverageSpan{span(-5*time.Hour, -4*time.Hour)}, gaps: []SplitGap{gap(at(-10*time.Second), now)}, since: -10 * time.Second},
	} {
		since := since
		if tc.since != 0 {
			since = at(tc.since)
		}
		s := &Store{Config: testConfig(t), State: State{Coverage: tc.spans, Events: []Event{{TS: at(-25 * time.Hour), Source: "nettop", Label: "noise"}}}}
		w := s.Split(since, now).Window
		if len(w.CoverageGaps) != len(tc.gaps) || w.Truncated != (len(tc.gaps) > 0) {
			t.Errorf("%s: %+v", tc.name, w)
			continue
		}
		for i := range tc.gaps {
			if w.CoverageGaps[i].Kind != GapNotRunning || !w.CoverageGaps[i].From.Equal(tc.gaps[i].From) || !w.CoverageGaps[i].To.Equal(tc.gaps[i].To) {
				t.Errorf("%s: gap %d = %+v, want %+v", tc.name, i, w.CoverageGaps[i], tc.gaps[i])
			}
		}
	}
}

// Count pruning that drops an event at or after since marks the window
// truncated even when coverage is complete and a retained event sits on the
// boundary (deny@T evicted, noise@T kept); an eviction strictly before since
// does not. Exercised through prune, save and reload.
func TestSplitEvictionTruncation(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 2
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	T := time.Now().Truncate(time.Second)
	s.BeginCoverage(T.Add(-time.Hour))
	ev := func(ts time.Time, verdict, label string) Event {
		return Event{TS: ts, Source: "alf", App: "a", Verdict: verdict, Counts: 1, Label: label, Reason: "test", Mode: "shadow"}
	}
	s.State.Events = []Event{ev(T, "deny", "decide"), ev(T, "allow", "noise"), ev(T.Add(time.Second), "allow", "noise")}
	if e = s.Save(T.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	loaded, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	asOf := T.Add(2 * time.Second)
	w := loaded.Split(T, asOf).Window
	if !w.Truncated || len(w.CoverageGaps) != 0 || w.EvictedThrough == nil || !w.EvictedThrough.Equal(T) || w.EventsInWindow != 2 {
		t.Fatalf("boundary eviction: %+v", w)
	}
	if w = loaded.Split(T.Add(time.Nanosecond), asOf).Window; w.Truncated {
		t.Fatalf("eviction before since: %+v", w)
	}
}

// An empty store has no coverage, so its window is one gap and truncated.
// Empty buckets and gaps are JSON arrays, not null.
func TestSplitEmptyJSON(t *testing.T) {
	now := time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)
	empty := (&Store{Config: testConfig(t)}).Split(now.Add(-time.Hour), now)
	if !empty.Window.Truncated || empty.Window.FirstTS != nil || len(empty.Window.CoverageGaps) != 1 || empty.Window.EvictedThrough != nil {
		t.Fatalf("empty store window: %+v", empty.Window)
	}
	data, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	_ = json.Unmarshal(data, &decoded)
	if _, ok := decoded["window"].(map[string]any)["coverage_gaps"].([]any); !ok {
		t.Fatalf("coverage_gaps is not an array: %s", data)
	}
	for _, key := range []string{"real_deny", "needs_review"} {
		if _, ok := decoded[key].([]any); !ok {
			t.Fatalf("%s is not an array: %s", key, data)
		}
	}
	fp := decoded["known_fp"].(map[string]any)
	for _, group := range []string{KnownFPNettopRawIP, KnownFPALFUnknownOrAllow, KnownFPLoopbackSSHKNN} {
		if rows, ok := fp[group].(map[string]any)["rows"].([]any); !ok || rows == nil {
			t.Fatalf("known_fp %s rows not an array: %s", group, data)
		}
	}
	if decoded["health"].(map[string]any)["mode"] != "shadow" {
		t.Fatalf("health mode missing: %s", data)
	}
}

// A watcher's span opens at BeginCoverage and ends at its last save; a
// restart opens a second span, leaving the downtime uncovered. A store that
// never began coverage (status/digest readers) extends no span when saved.
// Spans ending before the retention cutoff are pruned; an inverted or
// zero-start span is refused on save.
func TestCoverageSpans(t *testing.T) {
	c := testConfig(t)
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	run, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	run.BeginCoverage(at(0))
	for _, m := range []int{1, 2} {
		if e = run.Save(at(m)); e != nil {
			t.Fatal(e)
		}
	}
	restart, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	restart.BeginCoverage(at(5))
	if e = restart.Save(at(6)); e != nil {
		t.Fatal(e)
	}
	reader, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = reader.Save(at(9)); e != nil {
		t.Fatal(e)
	}
	loaded, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	want := []CoverageSpan{{Start: at(0), End: at(2)}, {Start: at(5), End: at(6)}}
	if len(loaded.State.Coverage) != 2 || !loaded.State.Coverage[0].Start.Equal(want[0].Start) || !loaded.State.Coverage[0].End.Equal(want[0].End) || !loaded.State.Coverage[1].Start.Equal(want[1].Start) || !loaded.State.Coverage[1].End.Equal(want[1].End) {
		t.Fatalf("coverage: %+v", loaded.State.Coverage)
	}
	if gaps := loaded.Split(at(1), at(6)).Window.CoverageGaps; len(gaps) != 1 || gaps[0].Kind != GapNotRunning || !gaps[0].From.Equal(at(2)) || !gaps[0].To.Equal(at(5)) {
		t.Fatalf("restart gap: %+v", gaps)
	}
	cutoff := at(10).Add(-time.Duration(c.RetentionDays) * 24 * time.Hour)
	loaded.State.Coverage = append([]CoverageSpan{{Start: cutoff.Add(-2 * time.Hour), End: cutoff.Add(-time.Hour)}}, loaded.State.Coverage...)
	if e = loaded.Save(at(10)); e != nil || len(loaded.State.Coverage) != 2 {
		t.Fatalf("retention prune: %v %+v", e, loaded.State.Coverage)
	}
	for _, bad := range []CoverageSpan{{Start: at(3), End: at(2)}, {Start: time.Time{}, End: at(2)}} {
		loaded.State.Coverage = []CoverageSpan{bad}
		if e = loaded.Save(at(11)); e == nil {
			t.Fatalf("invalid span saved: %+v", bad)
		}
	}
}

// EndCoverage caps the open span at the collector's end even when the run
// loop saves later (blocked classification); the first end wins, later saves
// never extend the span, and the capped span reloads with a gap after it.
func TestCoverageEndsAtCollectorEnd(t *testing.T) {
	c := testConfig(t)
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	s.BeginCoverage(at(0))
	if e = s.Save(at(1)); e != nil {
		t.Fatal(e)
	}
	s.EndCoverage(at(2))
	s.EndCoverage(at(3))
	for _, m := range []int{5, 9} {
		if e = s.Save(at(m)); e != nil {
			t.Fatal(e)
		}
		if end := s.State.Coverage[0].End; !end.Equal(at(2)) {
			t.Fatalf("save at %d extended coverage to %v", m, end)
		}
	}
	loaded, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	if w := loaded.Split(at(0), at(9)).Window; !w.Truncated || len(w.CoverageGaps) != 1 || !w.CoverageGaps[0].From.Equal(at(2)) {
		t.Fatalf("collector end: %+v", w)
	}
}

// feedLines reports the collector's end as soon as its stream ends, while
// queued lines are still unconsumed (the run loop is blocked) and before
// lines is closed, so the loop's final save sees the end; it does not report
// an end while the stream is open.
func TestFeedLinesReportsEndBeforeConsumption(t *testing.T) {
	r, w := io.Pipe()
	lines := make(chan []byte, 64)
	var ended atomic.Int64
	queued, closedFirst := 0, false
	done := make(chan error, 1)
	go func() {
		done <- feedLines(context.Background(), r, lines, observerFuncs{end: func(at time.Time) {
		drain:
			for {
				select {
				case _, ok := <-lines:
					if !ok {
						closedFirst = true
						break drain
					}
					queued++
				default:
					break drain
				}
			}
			ended.Store(at.UnixNano())
		}})
	}()
	if _, e := w.Write([]byte("{\"a\":1}\n")); e != nil {
		t.Fatal(e)
	}
	if _, e := w.Write([]byte("{\"b\":2}\n")); e != nil {
		t.Fatal(e)
	}
	if ended.Load() != 0 {
		t.Fatal("end reported while the stream is open")
	}
	w.Close()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if ended.Load() == 0 || queued != 2 || closedFirst {
		t.Fatalf("end not reported before consumption and close: ended=%d queued=%d closed=%t", ended.Load(), queued, closedFirst)
	}
	if _, ok := <-lines; ok {
		t.Fatal("lines not closed after the end")
	}
}

type observerFuncs struct{ stall, resume, end func(time.Time) }

func (o observerFuncs) StallCoverage(at time.Time) {
	if o.stall != nil {
		o.stall(at)
	}
}
func (o observerFuncs) ResumeCoverage(at time.Time) {
	if o.resume != nil {
		o.resume(at)
	}
}
func (o observerFuncs) EndCoverage(at time.Time) {
	if o.end != nil {
		o.end(at)
	}
}

// A stall (full line queue) is not coverage: a save during an open stall ends
// the span at the stall's start, the resume opens a new span, and the stall
// stays a gap after reload. Saves that see no stall extend the span (control).
func TestCoverageStallIsGap(t *testing.T) {
	c := testConfig(t)
	t0 := time.Now().Truncate(time.Second).Add(-time.Hour)
	at := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	s.BeginCoverage(at(0))
	if e = s.Save(at(1)); e != nil || !s.State.Coverage[0].End.Equal(at(1)) {
		t.Fatalf("live save: %v %+v", e, s.State.Coverage)
	}
	s.StallCoverage(at(2))
	s.StallCoverage(at(3))
	if e = s.Save(at(5)); e != nil || !s.State.Coverage[0].End.Equal(at(2)) {
		t.Fatalf("save during stall: %v %+v", e, s.State.Coverage)
	}
	s.ResumeCoverage(at(6))
	if e = s.Save(at(7)); e != nil {
		t.Fatal(e)
	}
	loaded, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	got := loaded.State.Coverage
	if len(got) != 2 || !got[0].End.Equal(at(2)) || !got[1].Start.Equal(at(6)) || !got[1].End.Equal(at(7)) {
		t.Fatalf("coverage: %+v", got)
	}
	if w := loaded.Split(at(0), at(7)).Window; !w.Truncated || len(w.CoverageGaps) != 1 || w.CoverageGaps[0].Kind != GapStall || !w.CoverageGaps[0].From.Equal(at(2)) || !w.CoverageGaps[0].To.Equal(at(6)) {
		t.Fatalf("stall gap: %+v", w)
	}
}

// Backpressure end to end: with more than 64 queued lines, consumption
// blocked longer than the grace, and the collector gone, the feeder reports a
// stall and only reaches EOF after the loop drains; delayed saves and reload
// keep the blocked period as a gap. An unblocked live stream adds no gap, and
// a live stream that stalls and catches up regains coverage.
func TestFeedLinesBackpressureGap(t *testing.T) {
	c := testConfig(t)
	c.NettopInterval, c.SaveInterval = "1ms", "1ms"
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	s.BeginCoverage(start)
	stalled := make(chan time.Time, 1)
	observer := observerFuncs{
		stall: func(at time.Time) {
			s.StallCoverage(at)
			select {
			case stalled <- at:
			default:
			}
		},
		resume: s.ResumeCoverage,
		end:    s.EndCoverage,
	}
	// A kernel pipe buffers all 100 lines, so the collector side closes while
	// the feeder is still stalled on the full queue.
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	lines := make(chan []byte, 64)
	done := make(chan error, 1)
	go func() { done <- feedLines(context.Background(), r, lines, observer) }()
	collectorGone := make(chan error, 1)
	go func() {
		for i := 0; i < 100; i++ {
			if _, e := fmt.Fprintf(w, "{\"n\":%d}\n", i); e != nil {
				collectorGone <- e
				return
			}
		}
		collectorGone <- w.Close()
	}()
	if e = <-collectorGone; e != nil {
		t.Fatal(e)
	}
	var stallAt time.Time
	select {
	case stallAt = <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("no stall reported while the queue is full")
	}
	alf := s.Coverage("")
	alf.mu.Lock()
	endSeen := !alf.endedAt.IsZero()
	alf.mu.Unlock()
	if endSeen {
		t.Fatal("feeder saw the collector's end through a full queue")
	}
	time.Sleep(20 * time.Millisecond)
	if e = s.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	for range lines {
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	asOf := time.Now()
	if e = s.Save(asOf); e != nil {
		t.Fatal(e)
	}
	loaded, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	w2 := loaded.Split(start, asOf).Window
	covered := false
	for _, g := range w2.CoverageGaps {
		if g.Kind == GapStall && !g.From.After(stallAt) && g.To.Sub(stallAt) >= 20*time.Millisecond {
			covered = true
		}
	}
	if !w2.Truncated || !covered {
		t.Fatalf("blocked period not a gap: stall=%v %+v coverage=%+v", stallAt, w2, loaded.State.Coverage)
	}

	live, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	live.State.Coverage = nil
	liveStart := time.Now()
	live.BeginCoverage(liveStart)
	lr, lw := io.Pipe()
	liveLines := make(chan []byte, 64)
	liveDone := make(chan error, 1)
	go func() { liveDone <- feedLines(context.Background(), lr, liveLines, live) }()
	for i := 0; i < 100; i++ {
		if _, e = fmt.Fprintf(lw, "{\"n\":%d}\n", i); e != nil {
			t.Fatal(e)
		}
		<-liveLines
	}
	liveAsOf := time.Now()
	if e = live.Save(liveAsOf); e != nil {
		t.Fatal(e)
	}
	if w := live.Split(liveStart, liveAsOf).Window; w.Truncated || len(live.State.Coverage) != 1 {
		t.Fatalf("live stream: %+v coverage=%+v", w, live.State.Coverage)
	}

	// A stall on a live stream resumes: once the loop catches up, saves extend
	// a new span to the save time again.
	resumeStalled := make(chan struct{}, 1)
	go func() {
		for i := 0; i < 70; i++ {
			fmt.Fprintf(lw, "{\"n\":%d}\n", i)
		}
	}()
	go func() {
		for len(liveLines) < cap(liveLines) {
			time.Sleep(time.Millisecond)
		}
		live.Coverage("").mu.Lock()
		stalled := !live.Coverage("").stalledAt.IsZero()
		live.Coverage("").mu.Unlock()
		for !stalled {
			time.Sleep(time.Millisecond)
			live.Coverage("").mu.Lock()
			stalled = !live.Coverage("").stalledAt.IsZero()
			live.Coverage("").mu.Unlock()
		}
		resumeStalled <- struct{}{}
	}()
	select {
	case <-resumeStalled:
	case <-time.After(10 * time.Second):
		t.Fatal("live stream did not stall")
	}
	for i := 0; i < 70; i++ {
		<-liveLines
	}
	if _, e = fmt.Fprintf(lw, "{\"n\":70}\n"); e != nil {
		t.Fatal(e)
	}
	<-liveLines
	resumedAt := time.Now()
	if e = live.Save(resumedAt); e != nil {
		t.Fatal(e)
	}
	if spans := live.State.Coverage; len(spans) < 2 || !spans[len(spans)-1].End.Equal(resumedAt) {
		t.Fatalf("coverage did not resume after the stall: %+v", spans)
	}
	lw.Close()
	<-liveDone
}
