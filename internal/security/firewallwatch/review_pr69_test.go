package firewallwatch

// Regression witnesses from the independent PR69 review r1 (Codex,
// review-pr69-r1.md), kept as written by the reviewer except where noted.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
	// Keeper's adaptation: one record per append now, so "a complete record
	// plus ten bytes of the next" is written explicitly. Slicing past the
	// record read the buffer's spare capacity, or panicked when there was
	// none.
	s.journalWrite = func(f *os.File, b []byte) error {
		if _, e := f.Write(append(append([]byte{}, b...), b[:10]...)); e != nil {
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
// Keeper's adaptation, after r3 finding 1: observations never compact
// coverage between snapshots, and readers never compact it either, so a
// reader after a heartbeat and a crash sees exactly the running watcher's
// coverage: in every window both directions of truncated, the gaps and the
// coalesced counters agree, and the spans are equal in start order.
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
	replayed := reopen(t, s.Config)
	windows := [][2]time.Duration{{100 * time.Millisecond, 900 * time.Millisecond}, {1200 * time.Millisecond, 2800 * time.Millisecond}, {4200 * time.Millisecond, 5800 * time.Millisecond}, {0, 6 * time.Second}}
	for _, w := range windows {
		a := s.Split(t0.Add(w[0]), t0.Add(w[1])).Window
		b := replayed.Split(t0.Add(w[0]), t0.Add(w[1])).Window
		if a.Truncated != b.Truncated || !reflect.DeepEqual(a.CoverageGaps, b.CoverageGaps) || a.CoalescedShortStalls != b.CoalescedShortStalls {
			t.Errorf("window %v: runtime truncated=%t gaps=%d coalesced=%+v; replay truncated=%t gaps=%d coalesced=%+v", w, a.Truncated, len(a.CoverageGaps), a.CoalescedShortStalls, b.Truncated, len(b.CoverageGaps), b.CoalescedShortStalls)
		}
	}
	if a, b := canonicalCoverage(s.State.Coverage), canonicalCoverage(replayed.State.Coverage); a != b {
		t.Fatalf("replayed coverage %s, runtime %s", b, a)
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
			_, _ = f.Write(append(append([]byte{}, b...), b[:10]...)) // keeper's adaptation, as above
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
//
// Keeper's note (r3 finding 3): the refresh here comes twenty seconds after
// the snapshot, past save_interval, so a heartbeat appends it and nothing is
// lost; this is now the durable-refresh control. TestR2UnappendedCapRefresh
// covers the refresh that is not yet appended.
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
