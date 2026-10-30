package firewallwatch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

// monoFrom returns wall's wall-clock reading with mono's monotonic reading,
// a synthetic input for clock corrections; the host clock is not changed.
func monoFrom(t *testing.T, wall, mono time.Time) time.Time {
	t.Helper()
	type layout struct {
		wall uint64
		ext  int64
		loc  *time.Location
	}
	out := wall
	p, q := (*layout)(unsafe.Pointer(&out)), (*layout)(unsafe.Pointer(&mono))
	if p.wall>>63 != 1 || q.wall>>63 != 1 {
		t.Fatal("fixture needs monotonic readings")
	}
	p.ext = q.ext
	if !out.Round(0).Equal(wall.Round(0)) || !out.Equal(mono) {
		t.Fatal("time layout changed")
	}
	return out
}

// steppedClock replays wall readings, as a host whose time daemon sets the
// clock back would deliver them.
func steppedClock(readings ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		t := readings[min(i, len(readings)-1)]
		i++
		return t
	}
}

// The run clock never runs backward: a reading behind the latest value is
// held at that value and counted; values carry no monotonic reading; once the
// wall clock passes the held value again it follows the wall clock.
func TestWallClockNeverRunsBackward(t *testing.T) {
	base := time.Now()
	c := &wallClock{read: steppedClock(base, base.Add(time.Second), base.Add(800*time.Millisecond), base.Add(900*time.Millisecond), base.Add(1100*time.Millisecond))}
	var got []time.Time
	for i := 0; i < 5; i++ {
		got = append(got, c.now())
	}
	want := []time.Duration{0, time.Second, time.Second, time.Second, 1100 * time.Millisecond}
	for i, w := range want {
		if !got[i].Equal(base.Round(0).Add(w)) || hasMonotonic(got[i]) {
			t.Fatalf("reading %d = %v (monotonic %t); want base+%v without a monotonic reading", i, got[i], hasMonotonic(got[i]), w)
		}
	}
	if c.heldCount() != 2 {
		t.Fatalf("held %d readings; want 2", c.heldCount())
	}
}

// Regression for the reader refusing the state after a backward wall step:
// an entry refreshed with a reading whose wall time is before its first_seen
// keeps last_seen, counts the held refresh, and the heartbeat, a snapshot and
// a reopen all succeed, for an entry first seen in this run and for one
// loaded from state.json; the count still advances. Negative control: the
// same steps on main d055484 reopen with "corrupt state journal" (in-run) and
// refuse the heartbeat (loaded). Positive control: a forward refresh moves
// last_seen.
func TestBackwardRefreshKeepsStateReadable(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		t.Run(fmt.Sprintf("loaded=%v", loaded), func(t *testing.T) {
			s, c := journalStore(t)
			at := time.Now()
			it := newKey(1)
			observeFlush(t, s, it, at)
			if e := s.Save(at.Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			if loaded {
				s = reopen(t, c)
				if e := s.Save(time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			k := key(it)
			recorded := s.State.Entries[k].LastSeen
			back := sameWallLaterMono(t, at.Add(-time.Second), 2*time.Second)
			s.Observe(it, back, ruleClassify)
			if e := s.Checkpoint(back); e != nil {
				t.Fatalf("heartbeat: %v", e)
			}
			if !s.State.Entries[k].LastSeen.Equal(recorded) || s.State.Entries[k].Count != 2 || s.State.Health.ClockHeldRefreshes != 1 {
				t.Fatalf("last_seen %v count %d held %d; want the recorded last_seen, count 2, one held refresh", s.State.Entries[k].LastSeen, s.State.Entries[k].Count, s.State.Health.ClockHeldRefreshes)
			}
			r, e := OpenStore(c)
			if e != nil {
				t.Fatalf("reopen after the heartbeat: %v", e)
			}
			if r.State.Entries[k].Count != 2 {
				t.Fatal("the held refresh's count was not journaled")
			}
			if e := s.Save(back); e != nil {
				t.Fatalf("snapshot: %v", e)
			}
			if _, e := OpenStore(c); e != nil {
				t.Fatalf("reopen after the snapshot: %v", e)
			}
			later := at.Add(5 * time.Second)
			s.Observe(it, later, ruleClassify)
			if !s.State.Entries[k].LastSeen.Equal(later) {
				t.Fatal("a forward refresh must move last_seen")
			}
		})
	}
}

// A deny window that started just before a backward step stays readable: the
// held refresh keeps last_seen at or after window_start, the deny count still
// advances, and heartbeat and reopen succeed.
func TestBackwardRefreshKeepsDenyWindowReadable(t *testing.T) {
	s, c := journalStore(t)
	at := time.Now()
	it := newKey(1)
	it.Verdict = "deny"
	observeFlush(t, s, it, at)
	back := sameWallLaterMono(t, at.Add(-time.Second), 2*time.Second)
	s.Observe(it, back, ruleClassify)
	if e := s.Checkpoint(back); e != nil {
		t.Fatalf("heartbeat: %v", e)
	}
	if s.State.Entries[key(it)].Denies != 2 {
		t.Fatalf("denies %d; want 2", s.State.Entries[key(it)].Denies)
	}
	if _, e := OpenStore(c); e != nil {
		t.Fatalf("reopen: %v", e)
	}
}

// A collector stall that spans a backward wall step, timed by the run clock,
// stays readable through heartbeat, snapshot and reopen: the clock holds its
// latest value during the step, so the span end, the stall's start and its
// end never run backward. Negative control: the same stall timed with raw
// readings is refused by the writer before it is acknowledged (below), and on
// main d055484 it is written and both the journal and state.json reopen as
// corrupt.
func TestStallAcrossBackwardStepStaysReadable(t *testing.T) {
	s, c := journalStore(t)
	at := time.Now()
	clock := &wallClock{read: steppedClock(at, at.Add(time.Second), at.Add(-time.Second), at.Add(-500*time.Millisecond), at.Add(2*time.Second))}
	s.clock = clock.now
	s.BeginCoverage(s.now())
	if e := s.Save(s.now()); e != nil {
		t.Fatal(e)
	}
	s.StallCoverage(s.now())
	s.ResumeCoverage(s.now())
	if e := s.Checkpoint(s.now()); e != nil {
		t.Fatalf("heartbeat: %v", e)
	}
	if _, e := OpenStore(c); e != nil {
		t.Fatalf("reopen after the heartbeat: %v", e)
	}
	if e := s.Save(s.now()); e != nil {
		t.Fatalf("snapshot: %v", e)
	}
	if _, e := OpenStore(c); e != nil {
		t.Fatalf("reopen after the snapshot: %v", e)
	}
	if clock.heldCount() != 2 {
		t.Fatalf("held %d readings; want 2", clock.heldCount())
	}
}

// The writer checks what the reader will read: a stall whose times are
// ordered by the monotonic clock but reversed by wall time is refused before
// any byte is written, the error says so, and the journal and state.json on
// disk still open. Negative control: on main d055484 the same record is
// written and the journal no longer opens.
func TestWriterRefusesWhatTheReaderWouldReject(t *testing.T) {
	s, c := journalStore(t)
	at := time.Now()
	s.BeginCoverage(at)
	if e := s.Save(at.Add(time.Second)); e != nil {
		t.Fatal(e)
	}
	journal, _ := os.ReadFile(filepath.Join(c.StateDir, journalFile))
	back := sameWallLaterMono(t, at.Add(-time.Second), 2*time.Second)
	s.StallCoverage(back)
	s.ResumeCoverage(sameWallLaterMono(t, at.Add(-time.Second), 3*time.Second))
	e := s.Checkpoint(back)
	if e == nil || !errors.Is(e, errInvalidState) {
		t.Fatalf("checkpoint: %v; want the refusal", e)
	}
	after, _ := os.ReadFile(filepath.Join(c.StateDir, journalFile))
	if string(after) != string(journal) {
		t.Fatal("a refused record reached the journal")
	}
	if _, e := OpenStore(c); e != nil {
		t.Fatalf("reopen: %v", e)
	}
}

// The prune that the first observation after a backward wall step runs is
// appended at once when it removed anything: a crash right after it does not
// bring the removed entry back, so a fully durable key does not lose its slot
// and re-emit only after the crash (the documented re-emit exposure stays
// with the key whose own refresh was lost). With a checkpoint after the step
// the same holds (control). Regression witness from an independent review;
// without the immediate append the crashed run re-emits.
func TestBackwardStepPruneIsAppendedAtOnce(t *testing.T) {
	for _, beat := range []bool{false, true} {
		run := func(crash bool) int {
			s := pruneFixture(t, 4)
			base := time.Now()
			observeFlush(t, s, newKey(1), base.Add(24*time.Hour).Round(0)) // A: durable, wall-only
			if e := s.Save(base.Add(24*time.Hour + time.Second)); e != nil {
				t.Fatal(e)
			}
			s = reopen(t, s.Config)
			if e := s.Save(base.Add(-3 * time.Second)); e != nil {
				t.Fatal(e)
			}
			observeFlush(t, s, newKey(2), base.Add(-2*time.Second)) // E: durable, never refreshed
			observeFlush(t, s, newKey(3), base)                     // B
			observeFlush(t, s, newKey(4), base.Add(time.Second))    // C
			if e := s.Save(base.Add(2 * time.Second)); e != nil {
				t.Fatal(e)
			}
			seq := s.seq
			forward := monoFrom(t, base.Add(9*24*time.Hour), base.Add(3*time.Second))
			observeFlush(t, s, newKey(3), forward)
			back := base.Add(4 * time.Second)
			observeFlush(t, s, newKey(4), back)
			if _, ok := s.State.Entries[key(newKey(1))]; ok {
				t.Fatal("fixture: A should be removed by the backward-step prune")
			}
			if s.seq == seq {
				t.Fatal("the backward-step prune's removal was not appended")
			}
			if beat {
				if e := s.Checkpoint(back); e != nil {
					t.Fatal(e)
				}
			}
			if crash {
				s = reopen(t, s.Config)
			}
			observeFlush(t, s, newKey(5), base.Add(5*time.Second))
			return len(observeFlush(t, s, newKey(2), base.Add(6*time.Second)))
		}
		if live, crashed := run(false), run(true); crashed > live {
			t.Fatalf("checkpoint=%v: durable E re-emits only after a crash: run %d, crashed %d", beat, live, crashed)
		}
	}
}

// Under the run clock a backward wall step is never seen by the store: the
// backward-step branch (prune with the earlier references, then reset them)
// is not taken, the expiry references keep the latest reading, and an entry
// an earlier reading expired stays expired, so observing it again makes it
// new (it emits). This is why production needs no backward-step prune (the
// review found the branch unreachable there). Negative control: a clock that
// does not hold passes the step through, the branch resets the references to
// the earlier reading, and the reference check fails.
func TestRunClockKeepsTheExpiryCutoff(t *testing.T) {
	s := pruneFixture(t, 20)
	base := time.Now().Round(0)
	retention := time.Duration(s.Config.RetentionDays) * 24 * time.Hour
	old, recent := newKey(1), newKey(2)
	observeFlush(t, s, old, base.Add(-retention+time.Second))
	observeFlush(t, s, recent, base)
	if e := s.Save(base); e != nil {
		t.Fatal(e)
	}
	clock := &wallClock{read: steppedClock(base.Add(2*time.Second), base.Add(-time.Second), base.Add(-500*time.Millisecond))}
	observeFlush(t, s, recent, clock.now()) // sets the cutoff past old's last_seen
	seq := s.seq
	observeFlush(t, s, recent, clock.now()) // the wall clock stepped back: held
	if !s.refs.wallAll.Equal(base.Add(2*time.Second)) || s.seq != seq {
		t.Fatalf("references at %v, seq %d -> %d; want the latest reading kept and no prune append", s.refs.wallAll, seq, s.seq)
	}
	if !s.expired(s.State.Entries[key(old)].LastSeen, s.refs) {
		t.Fatal("the backward step lowered the expiry cutoff")
	}
	if len(observeFlush(t, s, old, clock.now())) != 1 {
		t.Fatal("an expired entry seen again after the step must be new")
	}
	if clock.heldCount() != 2 {
		t.Fatalf("held %d readings; want 2", clock.heldCount())
	}
}
