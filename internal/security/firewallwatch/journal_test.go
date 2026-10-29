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
// type refuses the journal instead of skipping silently.
func TestJournalCorruptionRefused(t *testing.T) {
	cases := map[string]func(path string, first string){
		"invalid last line is torn": func(path, first string) { appendRaw(t, path, "garbage\n") },
		// The record after the garbage is the valid next seq (3 follows the
		// heartbeat, 2), so only the garbage line can refuse the journal.
		"mid-file garbage": func(path, first string) {
			appendRaw(t, path, "garbage\n"+strings.Replace(first, `"seq":1`, `"seq":3`, 1))
		},
		"seq gap":      func(path, first string) { appendRaw(t, path, strings.Replace(first, `"seq":1`, `"seq":5`, 1)) },
		"unknown type": func(path, first string) { appendRaw(t, path, `{"seq":2,"type":"bogus"}`+"\n") },
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			s, c := journalStore(t)
			observeFlush(t, s, newKey(1), time.Now())
			raw, e := os.ReadFile(s.journalPath())
			if e != nil {
				t.Fatal(e)
			}
			first := strings.SplitAfter(string(raw), "\n")[0]
			if !strings.Contains(first, `"seq":1,`) {
				t.Fatalf("first record %q", first)
			}
			plant(s.journalPath(), first)
			_, e = OpenStore(c)
			if name == "invalid last line is torn" {
				if e != nil {
					t.Fatal("torn complete last line refused:", e)
				}
				return
			}
			if e == nil || !strings.Contains(e.Error(), "corrupt state journal") {
				t.Fatal("corrupt journal admitted:", e)
			}
		})
	}
	t.Run("first record past journal_seq+1", func(t *testing.T) {
		s, c := journalStore(t)
		observeFlush(t, s, newKey(1), time.Now())
		raw, e := os.ReadFile(s.journalPath())
		if e != nil {
			t.Fatal(e)
		}
		shifted := strings.ReplaceAll(strings.ReplaceAll(string(raw), `"seq":2`, `"seq":6`), `"seq":1,`, `"seq":5,`)
		if e = os.WriteFile(s.journalPath(), []byte(shifted), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e = OpenStore(c); e == nil {
			t.Fatal("journal starting past journal_seq+1 admitted")
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
	run := func(crash bool) []Event {
		s, c := journalStore(t)
		now := time.Now()
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
			out = append(out, fmt.Sprintf("%s:%t", e.App, strings.Contains(fmt.Sprint(e.Reason), "spike") || e.Counts >= 3))
		}
		return out
	}
	want, got := run(false), run(true)
	if len(want) != 3 || !reflect.DeepEqual(labels(want), labels(got)) {
		t.Fatalf("events without crash %v, with crashes %v", labels(want), labels(got))
	}
}

// The only re-emit after a crash: a key whose last_seen bump was lost expires
// earlier and emits again when it reappears. Control: after a snapshot holding
// the bump, the same key does not re-emit.
func TestJournalOnlyReEmitIsEarlyExpiry(t *testing.T) {
	retention := time.Duration(testConfig(t).RetentionDays) * 24 * time.Hour
	for _, snapshot := range []bool{false, true} {
		t.Run(fmt.Sprintf("snapshot=%t", snapshot), func(t *testing.T) {
			s, c := journalStore(t)
			now := time.Now()
			first, bump := now.Add(-retention-time.Minute), now.Add(-retention+3*time.Minute)
			observeFlush(t, s, newKey(1), first) // emits, journaled
			observeFlush(t, s, newKey(1), bump)  // silent last_seen bump
			if snapshot {
				if e := s.Save(bump); e != nil {
					t.Fatal(e)
				}
			}
			s = reopen(t, c) // crash
			reemitted := len(observeFlush(t, s, newKey(1), now)) > 0
			if reemitted == snapshot {
				t.Fatalf("re-emitted=%t with snapshot=%t", reemitted, snapshot)
			}
		})
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
			observeFlush(t, s, newKey(i), now)
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
		if len(got.State.Events) != 3 {
			t.Fatalf("%d events; want 3, none applied twice", len(got.State.Events))
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
// equals the watcher's in canonical order, and status reports the heartbeat's
// time and health.
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
	// Opening prunes, which orders spans by start (stable): compare in that
	// canonical order.
	canonical := slices.Clone(s.State.Coverage)
	sort.SliceStable(canonical, func(i, j int) bool { return canonical[i].Start.Before(canonical[j].Start) })
	want, _ := json.Marshal(canonical)
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
		case "entries", "events", "signers", "journal_seq", "coverage":
			continue
		}
		if !beat[tag] {
			t.Errorf("State field %q is in no heartbeat", tag)
		}
	}
}

// A new signer result is journaled and replayed; a re-inspection with the same
// result is not; a changed result is. A bundle directory is re-inspected on
// every sighting, which exercises the re-inspection path.
func TestJournalSigner(t *testing.T) {
	s, c := journalStore(t)
	bundle := t.TempDir()
	result := "Developer ID: X"
	s.inspectSigner = func(context.Context, string) (string, error) { return result, nil }
	count := func() int {
		n := 0
		for _, r := range s.pending {
			if r.Type == recordSigner {
				n++
			}
		}
		return n
	}
	s.signer(context.Background(), bundle)
	if count() != 1 {
		t.Fatal("new signer result not journaled")
	}
	s.signer(context.Background(), bundle)
	if count() != 1 {
		t.Fatal("unchanged re-inspection journaled")
	}
	if e := s.Flush(time.Now(), false, false); e != nil {
		t.Fatal(e)
	}
	if got := reopen(t, c); len(got.State.Signers) != 1 {
		t.Fatalf("%d signers replayed; want 1", len(got.State.Signers))
	}
	result = "Developer ID: Y"
	s.signer(context.Background(), bundle)
	if count() != 1 {
		t.Fatal("changed signer result not journaled")
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
