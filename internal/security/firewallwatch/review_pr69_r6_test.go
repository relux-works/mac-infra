package firewallwatch

// Regression witnesses from the independent PR69 review r6 (Codex,
// review-pr69-r6.md), kept as written by the reviewer.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A valid restart after a wall correction, a successful timer-due snapshot and
// the next ordinary stall/resume must not acknowledge an unreadable journal.
// Controls: forward restart; use full Save for the final write (old path),
// which may refuse invalid runtime spans but must preserve the prior disk view.
func TestR6RestartSnapshotThenStall(t *testing.T) {
	for _, back := range []bool{false, true} {
		for _, snapshot := range []bool{false, true} {
			t.Run(fmt.Sprintf("backward=%t/snapshot=%t", back, snapshot), func(t *testing.T) {
				s, c := journalStore(t)
				b := time.Now().Add(-time.Hour).Round(0)
				s.BeginCoverage(b)
				s.EndCoverage(b.Add(10 * time.Second))
				if e := s.Save(b.Add(10 * time.Second)); e != nil {
					t.Fatal(e)
				}
				s = reopen(t, c)
				restart := b.Add(20 * time.Second)
				if back {
					restart = b.Add(-10 * time.Minute)
				}
				if e := s.Save(restart); e != nil {
					t.Fatal(e)
				}
				s.BeginCoverage(restart.Add(time.Second))
				if e := s.Checkpoint(restart.Add(5 * time.Second)); e != nil {
					t.Fatal(e)
				}
				if e := s.Checkpoint(restart.Add(301 * time.Second)); e != nil {
					t.Fatal(e)
				}
				if s.journalRecords != 0 {
					t.Fatal("five-minute checkpoint did not snapshot")
				}
				if e := s.validateState(); e != nil {
					t.Fatal("pre-stall fixture invalid", e)
				}
				s.StallCoverage(restart.Add(302 * time.Second))
				s.ResumeCoverage(restart.Add(303 * time.Second))
				var writeErr error
				if snapshot {
					writeErr = s.Save(restart.Add(304 * time.Second))
				} else {
					writeErr = s.Checkpoint(restart.Add(304 * time.Second))
				}
				// Keeper's adaptation: the open span is now found by its
				// tracker, so the backward case produces no invalid span and
				// both the heartbeat and the full snapshot succeed.
				if writeErr != nil {
					t.Fatal(writeErr)
				}
				if e := s.validateState(); e != nil {
					t.Fatal("runtime spans invalid after the stall:", e)
				}
				before := dirHashes(t, c.StateDir)
				r, readErr := OpenStore(c)
				if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
					t.Fatal("reader mutated files")
				}
				t.Logf("backward=%t snapshot=%t write=%v reopen=%v spans=%s", back, snapshot, writeErr, readErr, canonicalCoverage(s.State.Coverage))
				if readErr != nil {
					t.Fatalf("acknowledged checkpoint left restart unreadable: %v", readErr)
				}
				if writeErr == nil && canonicalCoverage(s.State.Coverage) != canonicalCoverage(r.State.Coverage) {
					t.Fatal("runtime/replay differ")
				}
			})
		}
	}
}

// Acknowledged deltas must leave Run's mandatory startup snapshot possible.
// Controls: a larger configured limit accepts the same stream; a full-save
// final write rejects overflow while keeping the preceding snapshot usable.
func TestR6AcknowledgedStateCapacity(t *testing.T) {
	for _, limit := range []int64{4096, 8192} {
		for _, snapshot := range []bool{false, true} {
			t.Run(fmt.Sprintf("limit=%d/snapshot=%t", limit, snapshot), func(t *testing.T) {
				s, c := journalStore(t)
				c.MaxStateBytes = limit
				s.Config = c
				if e := c.Validate(); e != nil {
					t.Fatal("fixture config", e)
				}
				b := time.Now().Add(-time.Minute).Round(0)
				for i := 0; i < 4; i++ {
					s.Observe(newKey(i), b, ruleClassify)
				}
				if e := s.Save(b); e != nil {
					t.Fatal("initial snapshot", e)
				}
				disk, _ := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
				item := newKey(42)
				item.App = strings.Repeat("x", 500)
				s.Observe(item, b.Add(time.Second), ruleClassify)
				var writeErr error
				if snapshot {
					writeErr = s.Save(b.Add(time.Second))
				} else {
					writeErr = s.Flush(b.Add(time.Second), true, false)
				}
				raw, _ := json.Marshal(s.State)
				journal, _ := os.ReadFile(s.journalPath())
				// Keeper's adaptation: at 4096 bytes the journal path now
				// refuses the write as the full save does (the journal holds at
				// most max_state_bytes minus the snapshot), so nothing that
				// cannot restart is acknowledged; the four-event state stays.
				if writeErr != nil && limit != 4096 {
					t.Fatal("unexpected final write", writeErr)
				}
				if limit == 4096 && writeErr == nil {
					t.Fatal("an overflowing write must be refused")
				}
				before := dirHashes(t, c.StateDir)
				r := reopen(t, c)
				if !reflect.DeepEqual(before, dirHashes(t, c.StateDir)) {
					t.Fatal("reader mutated bytes")
				}
				restartErr := r.Save(time.Now()) // exactly Run's pre-collector call
				t.Logf("limit=%d snapshot=%t initial=%d journal=%d runtime=%d restored-events=%d write=%v startup=%v", limit, snapshot, len(disk), len(journal), len(raw), len(r.State.Events), writeErr, restartErr)
				if restartErr != nil {
					t.Errorf("acknowledged delta prevents startup: %v", restartErr)
				}
				if want := map[bool]int{true: 4, false: 5}[limit == 4096]; len(r.State.Events) != want {
					t.Errorf("restored %d events; want %d", len(r.State.Events), want)
				}
			})
		}
	}
}
