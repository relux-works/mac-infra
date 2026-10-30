package firewallwatch

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func journalStore(t *testing.T) (*Store, Config) {
	t.Helper()
	c := testConfig(t)
	c.MaxEntries = 10000
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	return s, c
}

// observeFlush observes one item and flushes as the run loop does.
func observeFlush(t *testing.T, s *Store, it Item, at time.Time) []Event {
	t.Helper()
	events := s.Observe(it, at, ruleClassify)
	if e := s.Flush(at, len(events) > 0, false); e != nil {
		t.Fatal(e)
	}
	return events
}

func reopen(t *testing.T, c Config) *Store {
	t.Helper()
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func newKey(i int) Item {
	return Item{Source: "nettop", App: fmt.Sprintf("app%d", i), Verdict: "observed", Remote: "lan"}
}

// dirHashes maps every file in the state dir to its content hash.
func dirHashes(t *testing.T, dir string) map[string][32]byte {
	t.Helper()
	files, e := os.ReadDir(dir)
	if e != nil {
		t.Fatal(e)
	}
	hashes := map[string][32]byte{}
	for _, f := range files {
		raw, e := os.ReadFile(filepath.Join(dir, f.Name()))
		if e != nil {
			t.Fatal(e)
		}
		hashes[f.Name()] = sha256.Sum256(raw)
	}
	return hashes
}

func appendRaw(t *testing.T, path string, raw string) {
	t.Helper()
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteString(raw); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}

// Emitted events survive a crash without any snapshot: a reopened store
// replays them from the journal, and state.json was never rewritten for them.
func TestJournalEventsSurviveCrash(t *testing.T) {
	s, c := journalStore(t)
	if e := s.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	before := dirHashes(t, c.StateDir)["state.json"]
	now := time.Now()
	for i := 0; i < 5; i++ {
		if len(observeFlush(t, s, newKey(i), now)) != 1 {
			t.Fatal("new key did not emit")
		}
	}
	if dirHashes(t, c.StateDir)["state.json"] != before {
		t.Fatal("state.json rewritten for emitted events")
	}
	// Crash: s is dropped without a snapshot.
	got := reopen(t, c)
	if len(got.State.Events) != 5 || len(got.State.Entries) != 5 {
		t.Fatalf("replayed %d events, %d entries; want 5 and 5", len(got.State.Events), len(got.State.Entries))
	}
}

// A torn last line is ignored by a reader, which changes no byte in the state
// dir. The watcher's startup snapshot folds the journal, drops the torn tail,
// counts it and removes the journal. Positive control: the records before the
// tail are kept.
func TestJournalTornTail(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	observeFlush(t, s, newKey(1), now)
	appendRaw(t, s.journalPath(), `{"seq":99,"type":"observe","key":"x","ent`)
	before := dirHashes(t, c.StateDir)
	reader := reopen(t, c)
	reader = reopen(t, c)
	if len(reader.State.Events) != 1 || reader.State.Health.JournalTornTail != 1 {
		t.Fatalf("reader: %d events, torn %d", len(reader.State.Events), reader.State.Health.JournalTornTail)
	}
	if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
		t.Fatal("a reader changed the state dir")
	}
	// The watcher: open, then the startup snapshot.
	watcher := reopen(t, c)
	if e := watcher.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(watcher.journalPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("journal not removed by the snapshot", e)
	}
	after := reopen(t, c)
	if len(after.State.Events) != 1 || after.State.Health.JournalTornTail != 1 {
		t.Fatalf("after snapshot: %d events, torn %d", len(after.State.Events), after.State.Health.JournalTornTail)
	}
}

// A complete but invalid last line is also a torn tail; an invalid line before
// the last, a seq gap, a first record past journal_seq+1 or an unknown record
// type refuses the journal instead of skipping silently. Each planted record
// otherwise continues the journal's seq, so only the planted defect can
// refuse it, and each refusal names its cause (PR69 review r1, finding 8).
func TestJournalCorruptionRefused(t *testing.T) {
	setup := func(t *testing.T) (*Store, Config, string, uint64) {
		t.Helper()
		s, c := journalStore(t)
		observeFlush(t, s, newKey(1), time.Now())
		observeFlush(t, s, newKey(2), time.Now())
		records := readJournal(t, s.journalPath())
		raw, e := os.ReadFile(s.journalPath())
		if e != nil || len(records) == 0 {
			t.Fatal(e, len(records))
		}
		return s, c, strings.SplitAfter(string(raw), "\n")[0], records[len(records)-1].Seq
	}
	withSeq := func(line string, seq uint64) string {
		var r journalRecord
		if e := json.Unmarshal([]byte(line), &r); e != nil {
			t.Fatal(e)
		}
		r.Seq = seq
		out, _ := json.Marshal(r)
		return string(out) + "\n"
	}
	cases := []struct {
		name  string
		plant func(first string, last uint64) string
		want  string // empty: admitted as a torn tail
	}{
		{"invalid last line is torn", func(string, uint64) string { return "garbage\n" }, ""},
		{"mid-file garbage", func(first string, last uint64) string { return "garbage\n" + withSeq(first, last+1) }, "invalid character"},
		{"seq gap", func(first string, last uint64) string { return withSeq(first, last+2) }, "seq"},
		{"unknown type", func(_ string, last uint64) string {
			return fmt.Sprintf(`{"seq":%d,"type":"bogus","events_len":0}`, last+1) + "\n"
		}, "unknown record type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, c, first, last := setup(t)
			appendRaw(t, s.journalPath(), tc.plant(first, last))
			_, e := OpenStore(c)
			if tc.want == "" {
				if e != nil {
					t.Fatal("torn complete last line refused:", e)
				}
				return
			}
			if e == nil || !strings.Contains(e.Error(), "corrupt state journal") || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("want a refusal naming %q, got %v", tc.want, e)
			}
		})
	}
	t.Run("first record past journal_seq+1", func(t *testing.T) {
		s, c, _, _ := setup(t)
		var out strings.Builder
		for _, r := range readJournal(t, s.journalPath()) {
			r.Seq += 4
			line, _ := json.Marshal(r)
			out.Write(append(line, '\n'))
		}
		if e := os.WriteFile(s.journalPath(), []byte(out.String()), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := OpenStore(c); e == nil || !strings.Contains(e.Error(), "want 1") {
			t.Fatal("journal starting past journal_seq+1 admitted:", e)
		}
	})
}

// Replay is idempotent: opening the same files twice gives the same state.
func TestJournalReplayIdempotent(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	for i := 0; i < 3; i++ {
		observeFlush(t, s, newKey(i), now)
	}
	s.dirty = true
	if e := s.Checkpoint(now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	a, _ := json.Marshal(reopen(t, c).State)
	b, _ := json.Marshal(reopen(t, c).State)
	if string(a) != string(b) {
		t.Fatal("two replays differ")
	}
}

// After a crash, keys whose emission was journaled do not emit again: not a
// new key, not a spike (deny-window state is journaled even when nothing is
// emitted). The uninterrupted store is the control for the same sequence.
func TestJournalNoReEmitAfterCrash(t *testing.T) {
	base := time.Now()
	run := func(crash bool) []Event {
		s, c := journalStore(t)
		now := base
		deny := Item{Source: "alf", App: "/d", Verdict: "deny", Remote: "lan", LocalPort: intp(80)}
		var all []Event
		step := func(it Item, at time.Time) {
			all = append(all, observeFlush(t, s, it, at)...)
		}
		step(newKey(1), now)
		step(deny, now)                  // new key
		step(deny, now.Add(time.Second)) // deny 2, silent but journaled
		if crash {
			s = reopen(t, c)
		}
		step(deny, now.Add(2*time.Second)) // deny 3: the spike
		step(newKey(1), now.Add(3*time.Second))
		if crash {
			s = reopen(t, c)
		}
		step(deny, now.Add(4*time.Second)) // same window: no second spike
		step(newKey(1), now.Add(5*time.Second))
		return all
	}
	labels := func(events []Event) []string {
		var out []string
		for _, e := range events {
			// The time matters: a lost deny count would move the spike.
			out = append(out, fmt.Sprintf("%s:%t@%v", e.App, strings.Contains(fmt.Sprint(e.Reason), "spike") || e.Counts >= 3, e.TS.Sub(base).Round(time.Second)))
		}
		return out
	}
	want, got := run(false), run(true)
	if len(want) != 3 || !reflect.DeepEqual(labels(want), labels(got)) {
		t.Fatalf("events without crash %v, with crashes %v", labels(want), labels(got))
	}
}

// After a crash only the changes since the last journal append are lost, and
// silent changes are appended at least every save_interval, as full saves
// were before the journal. So the only re-emit path is a key whose last_seen
// refresh came after the last append: it can expire early and emit again
// when it reappears. Controls: a refresh followed by a heartbeat, or by a
// snapshot, survives and nothing re-emits.
func TestJournalOnlyReEmitIsUnappendedRefresh(t *testing.T) {
	retention := time.Duration(testConfig(t).RetentionDays) * 24 * time.Hour
	for _, after := range []string{"crash", "heartbeat", "snapshot"} {
		t.Run(after, func(t *testing.T) {
			s, c := journalStore(t)
			now := time.Now()
			first, bump := now.Add(-retention-2*time.Second), now.Add(-retention+3*time.Second)
			observeFlush(t, s, newKey(1), first) // emits; the append also starts the interval
			s.Observe(newKey(1), bump, ruleClassify)
			if e := s.Flush(bump, false, false); e != nil { // within save_interval: nothing appended
				t.Fatal(e)
			}
			switch after {
			case "heartbeat":
				if e := s.Checkpoint(bump); e != nil {
					t.Fatal(e)
				}
			case "snapshot":
				if e := s.Save(bump); e != nil {
					t.Fatal(e)
				}
			}
			s = reopen(t, c) // crash
			reemitted := len(observeFlush(t, s, newKey(1), time.Now())) > 0
			if reemitted != (after == "crash") {
				t.Fatalf("re-emitted=%t after %s", reemitted, after)
			}
		})
	}
}

// PR69 review r1, finding 7: count-pressure eviction picks the entry with the
// oldest last_seen, so a lost refresh could evict a recently seen key and
// re-emit it. A refresh made durable by a heartbeat keeps the eviction order
// of the uninterrupted watcher: the same key is evicted and nothing else
// re-emits.
func TestJournalCapOrderSurvivesCrash(t *testing.T) {
	run := func(crash bool) int {
		c := testConfig(t)
		c.MaxEntries = 3
		s := reopen(t, c)
		base := time.Now().Add(-time.Hour)
		for i := 0; i < 3; i++ {
			observeFlush(t, s, newKey(i), base.Add(time.Duration(i)*time.Second))
		}
		if e := s.Save(base.Add(3 * time.Second)); e != nil {
			t.Fatal(e)
		}
		s.Observe(newKey(0), base.Add(time.Minute), ruleClassify) // silent refresh of the oldest key
		if e := s.Checkpoint(base.Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
		if crash {
			s = reopen(t, c)
		}
		observeFlush(t, s, newKey(3), base.Add(2*time.Minute)) // evicts the oldest: key 1
		return len(observeFlush(t, s, newKey(0), base.Add(3*time.Minute)))
	}
	if uninterrupted, crashed := run(false), run(true); uninterrupted != 0 || crashed != 0 {
		t.Fatalf("key 0 re-emitted: uninterrupted %d, after crash %d", uninterrupted, crashed)
	}
}

// Crash points around a snapshot lose no record: before the state.json
// rename (the old snapshot plus the whole journal), and after the rename but
// before the journal is removed (records up to journal_seq are skipped, never
// applied twice).
func TestJournalSnapshotCrashPoints(t *testing.T) {
	t.Run("before rename", func(t *testing.T) {
		s, c := journalStore(t)
		now := time.Now()
		for i := 0; i < 3; i++ {
			observeFlush(t, s, newKey(i), now)
		}
		s.atomicWrite = func(path string, b []byte) error {
			if filepath.Base(path) == "state.json" {
				return errors.New("crash before rename")
			}
			return atomicWrite(path, b)
		}
		if e := s.Save(now); e == nil {
			t.Fatal("injected failure ignored")
		}
		if got := reopen(t, c); len(got.State.Events) != 3 {
			t.Fatalf("%d events; want 3", len(got.State.Events))
		}
	})
	t.Run("after rename, before journal removal", func(t *testing.T) {
		s, c := journalStore(t)
		now := time.Now()
		for i := 0; i < 3; i++ {
			observeFlush(t, s, newKey(i), now.Add(time.Duration(i)*time.Second))
		}
		old, e := os.ReadFile(s.journalPath())
		if e != nil {
			t.Fatal(e)
		}
		if e = s.Save(now); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(s.journalPath(), old, 0600); e != nil {
			t.Fatal(e)
		}
		got := reopen(t, c)
		if apps := eventApps(got.State.Events); !reflect.DeepEqual(apps, []string{"app0", "app1", "app2"}) {
			t.Fatalf("events %v; want app0..app2 once each, none applied twice", apps)
		}
		// The watcher continues: a new record follows the old journal's.
		observeFlush(t, got, newKey(9), now)
		if again := reopen(t, c); len(again.State.Events) != 4 {
			t.Fatalf("%d events after a new record; want 4", len(again.State.Events))
		}
	})
}

// A reader opening the store while the watcher appends and rotates always gets
// a consistent view: no error, no duplicate event, never fewer events than a
// previous view. Readers write nothing (checked in TestJournalTornTail).
func TestJournalReaderDuringAppendAndRotation(t *testing.T) {
	s, c := journalStore(t)
	if e := s.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	problems := make(chan string, 16)
	views := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		last := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			r, e := OpenStore(c)
			if e != nil {
				problems <- e.Error()
				return
			}
			seen := map[string]bool{}
			for _, ev := range r.State.Events {
				if seen[ev.App] {
					problems <- "duplicate event " + ev.App
					return
				}
				seen[ev.App] = true
			}
			if len(r.State.Events) < last {
				problems <- fmt.Sprintf("view went back from %d to %d events", last, len(r.State.Events))
				return
			}
			last = len(r.State.Events)
			views++
		}
	}()
	now := time.Now()
	for i := 0; i < 120; i++ {
		observeFlush(t, s, newKey(i), now)
		if i%15 == 14 {
			if e := s.Flush(now, false, true); e != nil {
				t.Fatal(e)
			}
		}
	}
	close(stop)
	wg.Wait()
	close(problems)
	for p := range problems {
		t.Error(p)
	}
	if views == 0 {
		t.Fatal("the reader never completed a view")
	}
}

// A failed append, even one that wrote part of a record, falls back to a
// snapshot that holds the event and removes the journal. Until a snapshot has
// succeeded nothing more is appended, so a torn write stays the last line.
func TestJournalAppendFailureFallsBackToSnapshot(t *testing.T) {
	s, c := journalStore(t)
	torn := func(f *os.File, b []byte) error {
		_, _ = f.Write(b[:len(b)/2])
		return errors.New("disk full")
	}
	s.journalWrite = torn
	now := time.Now()
	observeFlush(t, s, newKey(1), now)
	if _, e := os.Stat(s.journalPath()); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("journal kept after the fallback snapshot", e)
	}
	if got := reopen(t, c); len(got.State.Events) != 1 {
		t.Fatalf("%d events after the fallback; want 1", len(got.State.Events))
	}
	// Both fail: the error surfaces, and the next flush snapshots again
	// instead of appending after the torn bytes.
	s.atomicWrite = func(string, []byte) error { return errors.New("disk full") }
	s.Observe(newKey(2), now, ruleClassify)
	if e := s.Flush(now, true, false); e == nil {
		t.Fatal("double failure hidden")
	}
	appends := 0
	s.journalWrite = func(f *os.File, b []byte) error { appends++; _, e := f.Write(b); return e }
	s.atomicWrite = nil
	s.Observe(newKey(3), now, ruleClassify)
	if e := s.Flush(now, true, false); e != nil {
		t.Fatal(e)
	}
	if appends != 0 {
		t.Fatal("appended after a torn write before a snapshot")
	}
	if got := reopen(t, c); len(got.State.Events) != 3 {
		t.Fatalf("%d events; want 3", len(got.State.Events))
	}
}

// A heartbeat carries coverage beyond each source's open span at the last
// snapshot, with stalls and a source begun after it; the replayed coverage
// equals the watcher's exactly, in its order, and status reports the
// heartbeat's time and health.
func TestJournalHeartbeatCoverageReplay(t *testing.T) {
	s, c := journalStore(t)
	t0 := time.Now().Add(-time.Hour).Round(0)
	s.BeginCoverage(t0)
	if e := s.Save(t0.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	alf := s.Coverage("")
	alf.StallCoverage(t0.Add(2 * time.Second))
	alf.ResumeCoverage(t0.Add(3 * time.Second))
	s.BeginSourceCoverage(SourceNetfilter, t0.Add(4*time.Second))
	s.State.BackendHealthy = true
	s.dirty = true
	beat := t0.Add(5 * time.Second)
	if e := s.Checkpoint(beat); e != nil {
		t.Fatal(e)
	}
	// Opening leaves coverage exact and replay restores it by position, so
	// the spans equal the watcher's in its own order.
	want, _ := json.Marshal(s.State.Coverage)
	got := reopen(t, c)
	have, _ := json.Marshal(got.State.Coverage)
	if string(want) != string(have) {
		t.Fatalf("replayed coverage\n%s\nwant\n%s", have, want)
	}
	if !got.State.Updated.Equal(beat) || !got.State.BackendHealthy {
		t.Fatalf("status as of %v healthy %t; want %v true", got.State.Updated, got.State.BackendHealthy, beat)
	}
	if n := len(got.coverageGaps(t0, beat)); n != 1 {
		t.Fatalf("%d gaps; want the one stall", n)
	}
}

// Every State field is carried either by a heartbeat or by the records and
// snapshot: a new field must be classified here before it can be lost.
func TestHeartbeatCoversState(t *testing.T) {
	tags := func(v any) map[string]bool {
		out := map[string]bool{}
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			out[strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]] = true
		}
		return out
	}
	beat := tags(heartbeat{})
	for tag := range tags(State{}) {
		switch tag {
		case "entries", "events", "signers", "last_event", "evicted_through", "journal_seq", "coverage":
			continue
		case "write_refusals":
			// Set only by openRun, right before the startup snapshot, and
			// never changed while the run lasts.
			continue
		}
		if !beat[tag] {
			t.Errorf("State field %q is in no heartbeat", tag)
		}
	}
}

// A new signer result is due for journaling at once and is replayed; a
// re-inspection with the same result is queued for the next append but is not
// due at once; a changed result is due at once. A bundle directory is
// re-inspected on every sighting, which exercises the re-inspection path.
func TestJournalSigner(t *testing.T) {
	s, c := journalStore(t)
	bundle := t.TempDir()
	result := "Developer ID: X"
	s.inspectSigner = func(context.Context, string) (string, error) { return result, nil }
	s.signer(context.Background(), bundle)
	if !s.delta.urgent || len(s.delta.signers) != 1 {
		t.Fatal("new signer result not due at once")
	}
	s.delta = journalDelta{}
	s.signer(context.Background(), bundle)
	if s.delta.urgent || len(s.delta.signers) != 1 {
		t.Fatal("an unchanged re-inspection must follow with the next append, not at once")
	}
	if e := s.Flush(time.Now(), false, false); e != nil {
		t.Fatal(e)
	}
	if got := reopen(t, c); len(got.State.Signers) != 1 {
		t.Fatalf("%d signers replayed; want 1", len(got.State.Signers))
	}
	result = "Developer ID: Y"
	s.signer(context.Background(), bundle)
	if !s.delta.urgent {
		t.Fatal("changed signer result not due at once")
	}
}

// The tick's checkpoint writes a heartbeat, not state.json, until a snapshot
// is due by time or by record count.
func TestJournalSnapshotCadence(t *testing.T) {
	s, _ := journalStore(t)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	writes := 0
	s.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "state.json" {
			writes++
		}
		return atomicWrite(path, b)
	}
	s.dirty = true
	if e := s.Checkpoint(now.Add(30 * time.Second)); e != nil || writes != 0 {
		t.Fatalf("tick checkpoint: err %v, state writes %d", e, writes)
	}
	s.dirty = true
	if e := s.Checkpoint(now.Add(journalSnapshotInterval + time.Second)); e != nil || writes != 1 {
		t.Fatalf("checkpoint after the snapshot interval: err %v, state writes %d", e, writes)
	}
	s.journalRecords = journalSnapshotRecords
	observeFlush(t, s, newKey(1), now.Add(journalSnapshotInterval+2*time.Second))
	if writes != 2 || s.journalRecords != 0 {
		t.Fatalf("record bound: state writes %d, records %d", writes, s.journalRecords)
	}
}

// A rotation between a reader's journal open and its state.json read still
// gives the reader every record: it holds the old journal and reads the new
// snapshot, whose journal_seq covers it. Reading state.json first would miss
// the records the rotation folded in.
func TestJournalReaderRotationBetweenOpens(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	for i := 0; i < 3; i++ {
		observeFlush(t, s, newKey(i), now)
	}
	afterJournalOpen = func() {
		afterJournalOpen = nil
		if e := s.Save(now); e != nil {
			t.Error(e)
		}
	}
	t.Cleanup(func() { afterJournalOpen = nil })
	if got := reopen(t, c); len(got.State.Events) != 3 {
		t.Fatalf("%d events across the rotation; want 3", len(got.State.Events))
	}
}

// openPrivate checks the opened file, not the path: a symlink, a second hard
// link or a mode other than 0600 is refused, a missing file is no error, and
// a file unlinked after it was opened stays readable, which is what a reader
// racing the watcher's rename or journal removal holds (PR69 module run).
func TestOpenPrivate(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if e := os.WriteFile(good, []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	f, e := openPrivate(good)
	if e != nil || f == nil {
		t.Fatal("private file refused:", e)
	}
	if e = os.Remove(good); e != nil {
		t.Fatal(e)
	}
	if raw, e := io.ReadAll(f); e != nil || string(raw) != "x" {
		t.Fatal("unlinked open file unreadable", e)
	}
	f.Close()
	if f, e := openPrivate(filepath.Join(dir, "missing")); f != nil || e != nil {
		t.Fatal("missing file", f, e)
	}
	target := filepath.Join(dir, "target")
	if e = os.WriteFile(target, []byte("x"), 0600); e != nil {
		t.Fatal(e)
	}
	wide := filepath.Join(dir, "wide")
	if e = os.WriteFile(wide, []byte("x"), 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, filepath.Join(dir, "link")); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(target, filepath.Join(dir, "hard")); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"link", "hard", "wide"} {
		if f, e := openPrivate(filepath.Join(dir, name)); e == nil {
			f.Close()
			t.Errorf("%s admitted", name)
		}
	}
}

// Every field a heartbeat carries comes back after a crash: each is set to a
// non-zero value, a heartbeat is appended, and the reopened state has the
// same value per field. TestHeartbeatCoversState only inventories the tags;
// this checks capture and application (PR69 review r1, finding 8).
func TestHeartbeatRoundTrip(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now().Add(-time.Minute).Round(0)
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	st := &s.State
	st.Parser = ALFParser{Unrecognized: 7, Invalid: 3, Samples: []string{"sample"}}
	st.Netfilter = NetfilterParser{Invalid: 2, RejectedSender: 5}
	st.NetfilterError, st.NettopError = "netfilter log stream ended", "nettop sample failed"
	st.NettopUnrecognized, st.BackendHealthy = 11, true
	st.CoverageEvictedThrough = now.Add(-time.Hour)
	st.Health.Classification.observe(time.Second, now)
	st.Health.JournalTornTail = 1
	s.dirty = true
	if e := s.Checkpoint(now.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	got := reopen(t, c)
	// An append cannot persist its own duration; the next write carries it,
	// as with save timing.
	got.State.Health.Journal = s.State.Health.Journal
	want, _ := json.Marshal(s.State)
	have, _ := json.Marshal(got.State)
	var w, h map[string]json.RawMessage
	json.Unmarshal(want, &w)
	json.Unmarshal(have, &h)
	tags := reflect.TypeOf(heartbeat{})
	for i := 0; i < tags.NumField(); i++ {
		tag := strings.Split(tags.Field(i).Tag.Get("json"), ",")[0]
		if tag == "coverage" {
			continue // TestJournalHeartbeatCoverageReplay
		}
		if string(w[tag]) != string(h[tag]) {
			t.Errorf("%s: replayed %s, want %s", tag, h[tag], w[tag])
		}
	}
}

// Replay reproduces the watcher's entries, events and signers after every
// append, through new keys, refreshes, deny windows and count-pressure
// evictions at a small cap (PR69 review r1, findings 1 and 7).
func TestJournalReplayEqualsRuntime(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 4
	c.SaveInterval = "1ms"
	s := reopen(t, c)
	s.inspectSigner = func(context.Context, string) (string, error) { return "Developer ID: X", nil }
	base := time.Now().Add(-time.Hour).Round(0)
	canon := func(st State) string {
		events := slices.Clone(st.Events)
		sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
		raw, _ := json.Marshal(map[string]any{"entries": st.Entries, "events": events, "signers": st.Signers})
		return string(raw)
	}
	for i := 0; i < 40; i++ {
		at := base.Add(time.Duration(i) * time.Second)
		it := newKey(i % 7)
		if i%5 == 0 {
			it = Item{Source: "alf", App: fmt.Sprintf("/d%d", i%3), Verdict: "deny", Remote: "lan"}
		}
		s.Observe(it, at, ruleClassify)
		if e := s.Flush(at, false, false); e != nil {
			t.Fatal(e)
		}
		if want, got := canon(s.State), canon(reopen(t, c).State); want != got {
			t.Fatalf("step %d: replay %s\nruntime %s", i, got, want)
		}
	}
}

// eventApps lists the events' apps in time order.
func eventApps(events []Event) []string {
	events = slices.Clone(events)
	sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	var apps []string
	for _, e := range events {
		apps = append(apps, e.App)
	}
	return apps
}

// PR69 review r1, finding 2: an append that fails after its record reached
// the disk falls back to a snapshot whose journal_seq covers that record. A
// crash after the snapshot's rename but before the journal's removal must not
// apply the record a second time: each event appears exactly once.
func TestJournalFallbackCrashExactEvents(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	s.Observe(newKey(1), now.Add(time.Second), ruleClassify)
	s.Observe(newKey(2), now.Add(2*time.Second), ruleClassify)
	s.journalWrite = func(f *os.File, b []byte) error {
		if _, e := f.Write(b); e != nil { // the whole record, then the sync fails
			return e
		}
		return errors.New("sync failed")
	}
	s.atomicWrite = func(path string, b []byte) error {
		if strings.HasPrefix(filepath.Base(path), "events-") {
			return errors.New("crash after the snapshot rename, before rotation")
		}
		return atomicWrite(path, b)
	}
	if e := s.Flush(now.Add(2*time.Second), true, false); e == nil {
		t.Fatal("injected crash missing")
	}
	if _, e := os.Stat(s.journalPath()); e != nil {
		t.Fatal("the failed append's record should still be on disk:", e)
	}
	if apps := eventApps(reopen(t, c).State.Events); !reflect.DeepEqual(apps, []string{"app1", "app2"}) {
		t.Fatalf("events %v; want app1, app2 once each", apps)
	}
}

// A watcher whose observation carried a time later than its append's and the
// reader's clock pruned by that reference: entries and events older than
// retention from it are gone. A reader opening now would not expire them by
// its own clock, so only the journaled removals and event count reproduce the
// watcher's state.
func TestJournalReplayFutureObservation(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 2
	s := reopen(t, c)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	observeFlush(t, s, newKey(1), now)
	observeFlush(t, s, newKey(2), now.Add(time.Second))
	future := now.Add(30 * 24 * time.Hour)
	s.Observe(newKey(3), future, ruleClassify) // over the cap: prunes by the future reference
	// The append runs on the present clock, so no snapshot is due and only
	// the journal carries the prune.
	if e := s.Flush(now.Add(2*time.Second), true, false); e != nil {
		t.Fatal(e)
	}
	if len(readJournal(t, s.journalPath())) == 0 {
		t.Fatal("fixture: the prune was not journaled")
	}
	if len(s.State.Entries) != 1 || len(s.State.Events) != 1 {
		t.Fatalf("fixture: runtime holds %d entries, %d events; want 1 and 1", len(s.State.Entries), len(s.State.Events))
	}
	got := reopen(t, c)
	if len(got.State.Entries) != 1 || got.State.Entries[key(cleanItem(newKey(3)))] == nil {
		t.Fatalf("replayed entries %v; want only app3", got.State.Entries)
	}
	if apps := eventApps(got.State.Events); !reflect.DeepEqual(apps, []string{"app3"}) {
		t.Fatalf("replayed events %v; want app3", apps)
	}
}

// A watcher opening the store after a crash must not extend the crashed run's
// span: opening restores the spans exactly, with no running-collector state,
// so the startup snapshot leaves the crash a not_running gap.
func TestJournalCrashedSpanNotExtended(t *testing.T) {
	s, c := journalStore(t)
	t0 := time.Now().Add(-time.Hour).Round(0)
	s.BeginCoverage(t0)
	if e := s.Save(t0.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	s.dirty = true
	if e := s.Checkpoint(t0.Add(2 * time.Second)); e != nil {
		t.Fatal(e)
	}
	// Crash; the next watcher opens and takes its startup snapshot later.
	w := reopen(t, c)
	restart := t0.Add(time.Minute)
	if e := w.Save(restart); e != nil {
		t.Fatal(e)
	}
	gaps := reopen(t, c).coverageGaps(t0, restart)
	if len(gaps) != 1 || gaps[0].Kind != GapNotRunning || !gaps[0].From.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("gaps %+v; want one not_running gap from the last heartbeat", gaps)
	}
}

// PR69 review r3, finding 2: at the event cap every new event removes one, so
// a journal is mostly removal records. Replay computes each event's identity
// once, not once per removal record: at most one call per retained or added
// event, independent of the number of records. (The pre-fix replay made one
// pass over all events per record: here about 150 records x 100 events.)
func TestJournalReplayRemovalCost(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 100
	s := reopen(t, c)
	now := time.Now()
	for i := 0; i < 100; i++ {
		s.Observe(newKey(i), now, ruleClassify)
	}
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	for i := 100; i < 250; i++ {
		observeFlush(t, s, newKey(i), now.Add(time.Duration(i)*time.Millisecond))
	}
	if s.journalRecords < 150 {
		t.Fatalf("fixture: %d journal records; want one per new event", s.journalRecords)
	}
	got := reopen(t, c)
	if added := 150; got.replayIDs > 100+added {
		t.Fatalf("replay computed %d identities for %d records; want at most %d", got.replayIDs, s.journalRecords, 100+added)
	}
	if apps := eventApps(got.State.Events); len(apps) != 100 || apps[0] != "app150" || apps[99] != "app249" {
		t.Fatalf("replayed events %d, first %v; want app150..app249", len(apps), apps[:1])
	}
}

// A failed snapshot may already have pruned and reordered coverage in memory,
// so the journal's positions no longer match the snapshot on disk: after it,
// no record is appended until a snapshot succeeds (PR69 review r5).
func TestJournalFailedSaveBlocksAppends(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	s.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "state.json" {
			return errors.New("disk full")
		}
		return atomicWrite(path, b)
	}
	if e := s.Save(now.Add(time.Second)); e == nil {
		t.Fatal("injected failure ignored")
	}
	appends := 0
	s.journalWrite = func(f *os.File, b []byte) error { appends++; _, e := f.Write(b); return e }
	s.Observe(newKey(1), now.Add(2*time.Second), ruleClassify)
	if e := s.Flush(now.Add(2*time.Second), true, false); e == nil {
		t.Fatal("the snapshot that replaces the append should still fail")
	}
	if appends != 0 {
		t.Fatal("appended after a failed snapshot")
	}
	s.atomicWrite = nil
	s.Observe(newKey(2), now.Add(3*time.Second), ruleClassify)
	if e := s.Flush(now.Add(3*time.Second), true, false); e != nil {
		t.Fatal(e)
	}
	if appends != 0 || len(reopen(t, c).State.Events) != 2 {
		t.Fatal("recovery snapshot missing the events")
	}
}

// A heartbeat whose coverage base or open position does not match the
// snapshot it follows is refused, not applied to the wrong spans.
func TestJournalCoverageBaseMismatchRefused(t *testing.T) {
	for _, field := range []string{"base", "index"} {
		t.Run(field, func(t *testing.T) {
			s, c := journalStore(t)
			t0 := time.Now().Add(-time.Hour).Round(0)
			s.BeginCoverage(t0)
			if e := s.Save(t0.Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			s.dirty = true
			if e := s.Checkpoint(t0.Add(2 * time.Second)); e != nil {
				t.Fatal(e)
			}
			records := readJournal(t, s.journalPath())
			if len(records) != 1 || records[0].Heartbeat == nil || len(records[0].Heartbeat.Coverage.Open) != 1 {
				t.Fatalf("fixture: %d records", len(records))
			}
			if field == "base" {
				records[0].Heartbeat.Coverage.Base++
			} else {
				records[0].Heartbeat.Coverage.Open[0].Index = 5
			}
			line, _ := json.Marshal(records[0])
			if e := os.WriteFile(s.journalPath(), append(line, '\n'), 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := OpenStore(c); e == nil || !strings.Contains(e.Error(), "coverage") {
				t.Fatalf("mismatched coverage %s admitted: %v", field, e)
			}
		})
	}
}

// An append never acknowledges what a reader would refuse: a record carrying
// an invalid entry is refused before it is written, the fallback snapshot
// refuses the same state, and the store on disk still opens (PR69 review r6).
func TestJournalAppendRefusesInvalidRecord(t *testing.T) {
	s, c := journalStore(t)
	now := time.Now()
	if e := s.Save(now); e != nil {
		t.Fatal(e)
	}
	s.Observe(newKey(1), now, ruleClassify)
	k := key(cleanItem(newKey(1)))
	s.State.Entries[k].Count = 0 // invalid: a reader refuses it
	if e := s.Flush(now, true, false); e == nil {
		t.Fatal("invalid record acknowledged")
	}
	if len(readJournal(t, s.journalPath())) != 0 {
		t.Fatal("invalid record written")
	}
	if _, e := OpenStore(c); e != nil {
		t.Fatal("the store on disk no longer opens:", e)
	}
}

// Compaction never merges a later span into a running source's open span:
// after a backward clock step a historical span can sort after the open span,
// and a short stall link would otherwise extend the open span over history
// (PR69 review r6). Control: without a running source the same pair merges.
func TestCompactionKeepsOpenSpan(t *testing.T) {
	t0 := time.Now().Add(-time.Hour).Round(0)
	open := CoverageSpan{Start: t0, End: t0.Add(time.Second), StallAfter: &CoverageStall{From: t0.Add(time.Second), To: t0.Add(1100 * time.Millisecond)}}
	history := CoverageSpan{Start: t0.Add(1100 * time.Millisecond), End: t0.Add(time.Minute)}
	tracker := &SourceCoverage{covering: true, hasOpen: true, openStart: t0}
	got := compactCoverage([]CoverageSpan{open, history}, map[string]*SourceCoverage{"": tracker})
	if len(got) != 2 || !got[0].End.Equal(open.End) {
		t.Fatalf("open span merged with later history: %+v", got)
	}
	if merged := compactCoverage([]CoverageSpan{open, history}, map[string]*SourceCoverage{}); len(merged) != 1 {
		t.Fatalf("control: the pair should merge without a running source, got %+v", merged)
	}
}
