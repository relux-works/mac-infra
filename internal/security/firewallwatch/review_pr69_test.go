package firewallwatch

// Regression witnesses from the independent PR69 review r1 (Codex,
// review-pr69-r1.md), kept as written by the reviewer except where noted.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// A durable new key at the cap must remain readable after a crash.
func TestReviewJournalAtCapRestart(t *testing.T) {
	s, now := atCap(t, 3)
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	observeFlush(t, s, newKey(99), now.Add(time.Second))
	if len(s.State.Entries) != 3 || len(s.State.Events) != 3 {
		t.Fatal("runtime cap lost")
	}
	got, e := OpenStore(s.Config)
	if e != nil {
		t.Fatalf("ordinary crash at cap refuses restart: %v", e)
	}
	if len(got.State.Events) != 3 {
		t.Fatal("wrong retained events")
	}
}

// A failed append with a complete prefix followed by a fallback snapshot
// rename must not replay already-snapshotted events twice.
func TestReviewFallbackRenameCrash(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	s.Observe(newKey(1), now, ruleClassify)
	s.Observe(newKey(2), now, ruleClassify)
	s.journalWrite = func(f *os.File, b []byte) error {
		n := bytes.IndexByte(b, '\n') + 1
		if _, e := f.Write(b[:n+10]); e != nil {
			return e
		}
		return errors.New("append sync/write failure")
	}
	s.atomicWrite = func(path string, b []byte) error {
		if strings.HasPrefix(filepath.Base(path), "events-") {
			return errors.New("crash after state rename before rotation")
		}
		return atomicWrite(path, b)
	}
	if e := s.Flush(now, true, false); e == nil {
		t.Fatal("injected crash missing")
	}
	got := reopen(t, c)
	if len(got.State.Events) != 2 {
		t.Fatalf("fallback rename restored %d events, want 2: journal prefix applied twice", len(got.State.Events))
	}
}

// The coverage tail must retain a compaction that absorbs the snapshot's
// anchor into a historical span starting before that anchor.
//
// Keeper's adaptation: observations no longer prune coverage (r1 finding 3),
// so between snapshots the runtime holds the four exact spans, over the cap
// of three. A reader's open prunes them the way the next snapshot would:
// count pressure coalesces the short stalls into counters. The replayed view
// must lose no stall (all three are counted), invent no not_running gap,
// stay conservative (truncated wherever the runtime is) and equal the
// runtime coverage after the same open-time prune.
func TestReviewHeartbeatCompaction(t *testing.T) {
	s := pruneFixture(t, 3)
	t0 := time.Now().Add(-time.Hour).Round(0)
	s.BeginCoverage(t0)
	alf := s.Coverage("")
	alf.StallCoverage(t0.Add(time.Second))
	alf.ResumeCoverage(t0.Add(1100 * time.Millisecond))
	if e := s.Save(t0.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	alf.StallCoverage(t0.Add(3 * time.Second))
	alf.ResumeCoverage(t0.Add(3100 * time.Millisecond))
	alf.StallCoverage(t0.Add(4 * time.Second))
	alf.ResumeCoverage(t0.Add(4100 * time.Millisecond))
	s.applyCollectors(t0.Add(5 * time.Second))
	s.pruneItems(s.refs.with(t0.Add(5 * time.Second))) // an over-cap observation's prune
	if e := s.Checkpoint(t0.Add(6 * time.Second)); e != nil {
		t.Fatal(e)
	}
	got := reopen(t, s.Config)
	end := t0.Add(6 * time.Second)
	for _, g := range got.coverageGaps(t0, end) {
		if g.Kind == GapNotRunning {
			t.Errorf("replay invented a not_running gap %+v", g)
		}
	}
	runtimeStalls := 0
	for _, g := range s.coverageGaps(t0, end) {
		if g.Kind == GapStall {
			runtimeStalls++
		}
	}
	w := got.Split(t0, end).Window
	exact := 0
	for _, g := range w.CoverageGaps {
		if g.Kind == GapStall {
			exact++
		}
	}
	if exact+int(w.CoalescedShortStalls.Count) != runtimeStalls {
		t.Errorf("replay holds %d exact + %d coalesced stalls; runtime had %d", exact, w.CoalescedShortStalls.Count, runtimeStalls)
	}
	for _, win := range [][2]time.Time{{t0.Add(100 * time.Millisecond), t0.Add(900 * time.Millisecond)}, {t0, end}} {
		if s.Split(win[0], win[1]).Window.Truncated && !got.Split(win[0], win[1]).Window.Truncated {
			t.Errorf("replay less conservative than runtime in %v", win)
		}
	}
	// The same open-time prune of the runtime's coverage gives the replay.
	same := &Store{Config: s.Config, State: State{Entries: map[string]*Entry{}, Signers: map[string]SignerEntry{}, Coverage: slices.Clone(s.State.Coverage)}}
	same.prune(time.Now())
	a, _ := json.Marshal(same.State.Coverage)
	b, _ := json.Marshal(got.State.Coverage)
	if string(a) != string(b) {
		t.Fatalf("replayed coverage %s, runtime after the same prune %s", b, a)
	}
}

// A valid small state-size limit must also bound successful journal writes,
// so the writer cannot acknowledge a journal its next reader refuses.
//
// Keeper's adaptation: the writer now keeps the journal within the reader's
// limit, so the fixture's precondition (a journal past max_state_bytes) is the
// defect itself; the witness asserts the bound and a reopen that equals the
// runtime instead.
func TestReviewJournalByteLimit(t *testing.T) {
	s, c := journalStore(t)
	c.MaxStateBytes = 4096
	s.Config = c
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	it := Item{Source: "alf", App: "deny", Verdict: "deny", Remote: "lan"}
	for i := 0; i < 40; i++ {
		observeFlush(t, s, it, now.Add(time.Duration(i)*time.Millisecond))
	}
	if raw, e := os.ReadFile(s.journalPath()); e == nil && int64(len(raw)) > c.MaxStateBytes {
		t.Fatalf("writer acknowledged %d journal bytes with max_state_bytes=%d", len(raw), c.MaxStateBytes)
	}
	got, e := OpenStore(c)
	if e != nil {
		t.Fatal("reopen refused:", e)
	}
	a, _ := json.Marshal(s.State.Entries)
	b, _ := json.Marshal(got.State.Entries)
	if string(a) != string(b) || len(got.State.Events) != len(s.State.Events) {
		t.Fatalf("reopened entries %s events %d; runtime %s %d", b, len(got.State.Events), a, len(s.State.Events))
	}
}

// A reader of a nonexistent state directory should leave it nonexistent.
func TestReviewReaderMissingDirectory(t *testing.T) {
	c := testConfig(t)
	c.StateDir = filepath.Join(t.TempDir(), "absent")
	if _, e := OpenStore(c); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(c.StateDir); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("read-only OpenStore created state_dir")
	}
}

// Complete observe records on either side of a heartbeat preserve the latest
// event and dedup entry, and coverage records collector termination exactly.
func TestReviewHeartbeatObserveAndEnd(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now().Add(-time.Minute).Round(0)
	s.BeginCoverage(now)
	s.BeginSourceCoverage(SourceNetfilter, now.Add(time.Second))
	if e := s.Save(now.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	observeFlush(t, s, newKey(1), now.Add(3*time.Second))
	s.Coverage(SourceNetfilter).EndCoverage(now.Add(4 * time.Second))
	s.EndCoverage(now.Add(5 * time.Second))
	s.State.Parser.Unrecognized = 7
	if e := s.Checkpoint(now.Add(6 * time.Second)); e != nil {
		t.Fatal(e)
	}
	got := reopen(t, c)
	if got.State.Parser.Unrecognized != 7 || len(got.State.Events) != 1 {
		t.Fatal("heartbeat lost preceding observe or parser")
	}
	for _, span := range got.State.Coverage {
		want := now.Add(5 * time.Second)
		if span.Source == SourceNetfilter {
			want = now.Add(4 * time.Second)
		}
		if !span.End.Equal(want) {
			t.Fatal("collector end not replayed", span)
		}
	}
	observeFlush(t, s, newKey(2), now.Add(7*time.Second))
	got = reopen(t, c)
	if len(got.State.Events) != 2 || !got.State.LastEvent.Equal(now.Add(7*time.Second)) {
		t.Fatal("following observe lost")
	}
	if len(got.Observe(newKey(2), now.Add(8*time.Second), ruleClassify)) != 0 {
		t.Fatal("following observe re-emitted")
	}
}

// Positive controls: an uninterrupted snapshot at the cap and a completed
// fallback both restore exactly the runtime retained event count.
func TestReviewSnapshotPositiveControls(t *testing.T) {
	t.Run("cap", func(t *testing.T) {
		s, now := atCap(t, 3)
		if e := s.Save(now); e != nil {
			t.Fatal(e)
		}
		observeFlush(t, s, newKey(99), now.Add(time.Second))
		if e := s.Save(now.Add(2 * time.Second)); e != nil {
			t.Fatal(e)
		}
		if got := reopen(t, s.Config); len(got.State.Events) != 3 {
			t.Fatal("completed snapshot lost cap")
		}
	})
	t.Run("fallback", func(t *testing.T) {
		s, c := journalStore(t)
		now := time.Now()
		if e := s.Save(now); e != nil {
			t.Fatal(e)
		}
		s.Observe(newKey(1), now, ruleClassify)
		s.Observe(newKey(2), now, ruleClassify)
		s.journalWrite = func(f *os.File, b []byte) error {
			_, _ = f.Write(b[:bytes.IndexByte(b, '\n')+11])
			return errors.New("append failure")
		}
		if e := s.Flush(now, true, false); e != nil {
			t.Fatal(e)
		}
		if got := reopen(t, c); len(got.State.Events) != 2 {
			t.Fatal("completed fallback duplicated")
		}
	})
}

// Lost last_seen can change count-pressure eviction, causing re-emission
// without any retention expiry. The uninterrupted execution is the control.
func TestReviewReEmitFromCapOrder(t *testing.T) {
	run := func(crash bool) int {
		s := pruneFixture(t, 3)
		now := time.Now().Round(0)
		observeFlush(t, s, newKey(1), now.Add(-2*time.Minute))
		observeFlush(t, s, newKey(2), now.Add(-time.Minute))
		observeFlush(t, s, newKey(3), now.Add(-30*time.Second))
		if e := s.Save(now.Add(-20 * time.Second)); e != nil {
			t.Fatal(e)
		}
		// Refresh the oldest key, then lose that silent refresh in the crash.
		observeFlush(t, s, newKey(1), now)
		if crash {
			s = reopen(t, s.Config)
		}
		observeFlush(t, s, newKey(4), now.Add(time.Second))
		return len(s.Observe(newKey(1), now.Add(2*time.Second), ruleClassify))
	}
	uninterrupted, crashed := run(false), run(true)
	if uninterrupted != 0 {
		t.Fatal("control emitted unexpectedly")
	}
	if crashed != 0 {
		t.Fatalf("cap-order crash re-emitted %d rows, uninterrupted %d; all keys are minutes old with seven-day retention", crashed, uninterrupted)
	}
}

// Successful unchanged regular-file signer results replay without starting
// any inspection on the first post-crash pass.
func TestReviewSignerRestartNoBurst(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	var paths []string
	for i := 0; i < 5; i++ {
		path := filepath.Join(dir, string(rune('a'+i)))
		if e := os.WriteFile(path, []byte("fixture"), 0600); e != nil {
			t.Fatal(e)
		}
		paths = append(paths, path)
	}
	inspections := 0
	inspect := func(context.Context, string) (string, error) { inspections++; return "Developer ID: Fixture", nil }
	s.inspectSigner = inspect
	for _, path := range paths {
		s.signer(context.Background(), path)
	}
	if inspections != 5 {
		t.Fatal("initial cache was not populated")
	}
	if e := s.Flush(now, false, false); e != nil {
		t.Fatal(e)
	}
	got := reopen(t, c)
	got.inspectSigner = inspect
	inspections = 0
	for _, path := range paths {
		got.signer(context.Background(), path)
	}
	if inspections != 0 {
		t.Fatalf("restart caused %d signer inspections", inspections)
	}
}
