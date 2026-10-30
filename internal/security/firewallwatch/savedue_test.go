package firewallwatch

import (
	"context"
	"errors"
	"testing"
	"time"
)

// The save timer makes a silent refresh durable when it fires, even while
// the run clock holds during a backward wall-clock step. With
// nettop_interval far longer than save_interval (no checkpoint from a nettop
// result), one tick through the run loop's save-timer lane leaves the
// refresh's last_seen in the journal, and a reopened store has it. Negative
// control: the previous timer write, Flush's wall-time test, writes nothing
// on the same held clock, so after a crash the refresh is lost. Positive
// control: with nothing pending the tick appends nothing. Limit: Run's own
// closure wiring (it starts the log collector) is checked by inspection; the
// test covers the loop's dispatch and Store.SaveDue.
func TestSaveTimerWritesDueChangesWhileClockHeld(t *testing.T) {
	stop := errors.New("one tick handled")
	for _, lane := range []string{"save due", "previous flush", "nothing pending"} {
		s, c := journalStore(t)
		s.Config.NettopInterval = "1h"
		base := time.Now().Round(0)
		observeFlush(t, s, newKey(1), base.Add(-2*time.Second))
		if e := s.Save(base.Add(-time.Second)); e != nil {
			t.Fatal(e)
		}
		read := base
		clock := &wallClock{read: func() time.Time { return read }}
		s.clock = clock.now
		k := key(cleanItem(newKey(1)))
		if lane == "nothing pending" {
			s.now() // the run clock's first reading, as a run starts
		} else {
			seq := s.seq
			if len(observeFlush(t, s, newKey(1), s.now())) != 0 || s.seq != seq {
				t.Fatalf("%s: the refresh was not silent", lane)
			}
		}
		// The wall clock steps back an hour; the run clock holds base.
		read = base.Add(-time.Hour)
		seq := s.seq
		ticks := make(chan time.Time, 1)
		ticks <- base.Add(10 * time.Second)
		netLines := (chan []byte)(nil)
		nettopTick := time.NewTicker(time.Hour)
		defer nettopTick.Stop()
		loop := &runLoop{alf: make(chan []byte), netfilter: &netLines, saveTick: ticks, tick: nettopTick, sampler: &nettopSampler{done: make(chan nettopRun)}}
		loop.flush = func(bool) error { return errors.New("the save timer called the row flush") }
		var write error
		loop.saveDue = func() error {
			if lane == "previous flush" {
				write = s.Flush(s.now(), false, false)
			} else {
				write = s.SaveDue(s.now())
			}
			return stop
		}
		if e := loop.run(context.Background()); e != stop || write != nil {
			t.Fatalf("%s: run %v, write %v", lane, e, write)
		}
		if clock.heldCount() == 0 {
			t.Fatalf("%s: the run clock did not hold", lane)
		}
		durable := reopen(t, c).State.Entries[k].LastSeen.Equal(base)
		switch lane {
		case "save due":
			if s.seq != seq+1 || !durable {
				t.Fatalf("save due: seq %d -> %d, refresh durable %t", seq, s.seq, durable)
			}
		case "previous flush":
			if s.seq != seq || durable {
				t.Fatalf("previous flush: seq %d -> %d, refresh durable %t; the control no longer shows the gap", seq, s.seq, durable)
			}
		case "nothing pending":
			if s.seq != seq {
				t.Fatalf("nothing pending: seq %d -> %d", seq, s.seq)
			}
		}
	}
}
