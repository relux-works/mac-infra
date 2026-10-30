package firewallwatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func readFlag(c Config) string {
	b, _ := os.ReadFile(filepath.Join(c.StateDir, "new-events.flag"))
	return string(b)
}

// emitNewKey observes a new key and flushes it as the run loop does.
func emitNewKey(t *testing.T, s *Store, i int, at time.Time) string {
	t.Helper()
	if len(s.Observe(newKey(i), at, ruleClassify)) == 0 {
		t.Fatal("fixture key did not emit")
	}
	if e := s.Flush(at, true, false); e != nil {
		t.Fatal(e)
	}
	return s.State.LastEvent.Format(time.RFC3339Nano) + "\n"
}

// While Run runs (openRun), an emitted event's flag stamp is written off
// the run loop: Flush returns while the flag write is still blocked, the
// journal append is already durable, and the stamp lands once the write
// proceeds. stopFlags then makes flag writes synchronous again. Negative
// control: a writeFlag that ignores the writer blocks Flush on the flag write.
func TestFlagWrittenOffTheRunLoop(t *testing.T) {
	c := testConfig(t)
	s, e := openRun(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	s.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "new-events.flag" {
			<-release
		}
		return atomicWrite(path, b)
	}
	flushed := make(chan string, 1)
	go func() { flushed <- emitNewKey(t, s, 1, time.Now()) }()
	var stamp string
	select {
	case stamp = <-flushed:
	case <-time.After(2 * time.Second):
		t.Fatal("Flush waited for the flag write: it ran on the run loop")
	}
	if s.journalRecords != 1 {
		t.Fatalf("%d journal records; the event's append must be durable before Flush returns", s.journalRecords)
	}
	if readFlag(c) == stamp {
		t.Fatal("flag written although its write is still blocked")
	}
	once.Do(func() { close(release) })
	deadline := time.Now().Add(2 * time.Second)
	for readFlag(c) != stamp {
		if time.Now().After(deadline) {
			t.Fatalf("flag %q; want %q", readFlag(c), stamp)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if e := s.stopFlags(); e != nil || s.flags != nil {
		t.Fatalf("stop: %v, writer still set: %t", e, s.flags != nil)
	}
	s.atomicWrite = nil
	stamp = emitNewKey(t, s, 2, time.Now().Add(time.Second))
	if readFlag(c) != stamp {
		t.Fatal("after stopFlags the flag must be written synchronously again")
	}
}

// Review r1 finding: while the run loop is busy (here a 400 ms stand-in for a
// slow classification right after an emitting line), the flag is still
// stamped within 250 ms of the event's append. Negative control: stamping the
// flag on the loop at the next line's end leaves it unwritten for the whole
// 400 ms.
func TestFlagStampedWhileLoopIsBusy(t *testing.T) {
	c := testConfig(t)
	s, e := openRun(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer s.stopFlags()
	appended := time.Now()
	stamp := emitNewKey(t, s, 1, appended)
	stamped := make(chan time.Duration, 1)
	go func() {
		for time.Since(appended) < 2*time.Second {
			if readFlag(c) == stamp {
				stamped <- time.Since(appended)
				return
			}
			time.Sleep(2 * time.Millisecond)
		}
		stamped <- -1
	}()
	time.Sleep(400 * time.Millisecond) // the run loop is busy
	if d := <-stamped; d < 0 || d > 250*time.Millisecond {
		t.Fatalf("flag stamped after %v while the loop was busy; bound is 250ms", d)
	}
}

// The writer writes the newest stamp posted: with a slow write and many
// posts it coalesces, never writes an older stamp after a newer one, and
// stop writes the last stamp posted.
func TestFlagWriterWritesNewestStamp(t *testing.T) {
	var mu sync.Mutex
	var written []string
	w := startFlagWriter(func(b []byte) error {
		time.Sleep(20 * time.Millisecond)
		mu.Lock()
		written = append(written, string(b))
		mu.Unlock()
		return nil
	})
	const posts = 50
	for i := 0; i < posts; i++ {
		if e := w.post([]byte(fmt.Sprintf("%03d", i))); e != nil {
			t.Fatal(e)
		}
		time.Sleep(time.Millisecond)
	}
	if e := w.stop(); e != nil {
		t.Fatal(e)
	}
	if len(written) == 0 || written[len(written)-1] != fmt.Sprintf("%03d", posts-1) {
		t.Fatalf("last write %v; want the last stamp posted", written)
	}
	if len(written) >= posts {
		t.Fatalf("%d writes for %d posts; a slow write must coalesce", len(written), posts)
	}
	for i := 1; i < len(written); i++ {
		if written[i] <= written[i-1] {
			t.Fatalf("stamp %s written after %s", written[i], written[i-1])
		}
	}
}

// A flag write error is kept: later posts and stop return it, and through the
// store the next emitting Flush fails as a synchronous flag error did. A
// stamp posted just before stop is still written (positive control).
func TestFlagWriterKeepsWriteError(t *testing.T) {
	failed := errors.New("flag disk full")
	w := startFlagWriter(func([]byte) error { return failed })
	if e := w.post([]byte("a")); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(2 * time.Second)
	for w.post([]byte("b")) == nil {
		if time.Now().After(deadline) {
			t.Fatal("write error never surfaced to post")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if e := w.stop(); !errors.Is(e, failed) {
		t.Fatalf("stop: %v; want the write error", e)
	}

	got := make(chan string, 1)
	w = startFlagWriter(func(b []byte) error { got <- string(b); return nil })
	if e := w.post([]byte("last")); e != nil {
		t.Fatal(e)
	}
	if e := w.stop(); e != nil || <-got != "last" {
		t.Fatal("stop must write the last stamp posted")
	}

	c := testConfig(t)
	s, e := openRun(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	s.flags.stop()
	s.flags = startFlagWriter(func([]byte) error { return failed })
	emitNewKey(t, s, 1, time.Now())
	deadline = time.Now().Add(2 * time.Second)
	for {
		s.Observe(newKey(2), time.Now(), ruleClassify)
		if e := s.Flush(time.Now(), true, false); e != nil {
			if !errors.Is(e, failed) {
				t.Fatalf("Flush: %v; want the flag write error", e)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the flag write error never reached the run loop")
		}
		time.Sleep(2 * time.Millisecond)
	}
	if e := s.stopFlags(); !errors.Is(e, failed) {
		t.Fatalf("stopFlags: %v", e)
	}
}

// The flag never leads the journal: an event whose journal append fails, and
// whose fallback snapshot fails too, is durable nowhere, and the flag never
// shows it, also after the writer drained. Once storage works again the next
// event is stamped (positive control). Negative control: posting the stamp
// before the append makes the flag show the lost event.
func TestFlagNeverAheadOfJournal(t *testing.T) {
	c := testConfig(t)
	s, e := openRun(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	failed := errors.New("disk refused")
	s.journalWrite = func(*os.File, []byte) error { return failed }
	s.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "state.json" {
			return failed
		}
		return atomicWrite(path, b)
	}
	if len(s.Observe(newKey(1), time.Now(), ruleClassify)) == 0 {
		t.Fatal("fixture key did not emit")
	}
	lost := s.State.LastEvent.Format(time.RFC3339Nano) + "\n"
	if e := s.Flush(time.Now(), true, false); !errors.Is(e, failed) {
		t.Fatalf("Flush: %v; want the storage failure", e)
	}
	if e := s.stopFlags(); e != nil {
		t.Fatal(e)
	}
	if readFlag(c) == lost {
		t.Fatal("the flag shows an event that no journal append or snapshot holds")
	}
	s.journalWrite, s.atomicWrite = nil, nil
	s.journalBroken = false
	stamp := emitNewKey(t, s, 2, time.Now().Add(time.Second))
	if readFlag(c) != stamp {
		t.Fatalf("flag %q; want the durable event %q", readFlag(c), stamp)
	}
}

// One coalescing slot: a burst of 200000 stamps while the writer is stalled
// leaves the heap flat (under 1 MiB of growth after GC) and, once the writer
// resumes, the newest stamp is the one written last.
func TestFlagWriterMemoryIsBounded(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var last string
	w := startFlagWriter(func(b []byte) error {
		<-release
		mu.Lock()
		last = string(b)
		mu.Unlock()
		return nil
	})
	if e := w.post([]byte("first")); e != nil {
		t.Fatal(e)
	}
	time.Sleep(20 * time.Millisecond) // the writer is now stalled inside write
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const burst = 200000
	for i := 0; i < burst; i++ {
		if e := w.post([]byte(fmt.Sprintf("2026-10-30T05:00:00.%09dZ\n", i))); e != nil {
			t.Fatal(e)
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 1<<20 {
		t.Fatalf("heap grew %d bytes over a burst of %d stamps", grew, burst)
	}
	close(release)
	if e := w.stop(); e != nil {
		t.Fatal(e)
	}
	if want := fmt.Sprintf("2026-10-30T05:00:00.%09dZ\n", burst-1); last != want {
		t.Fatalf("last written %q; want %q", last, want)
	}
}

// Review r1 regression, through the real collectSample: a nettop sample whose
// first row emits and whose second row takes 400 ms (a slow classification)
// still has the first row's stamp on disk within 250 ms of its flush.
func TestFlagStampedDuringSlowSampleRow(t *testing.T) {
	c := testConfig(t)
	s, e := openRun(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	defer s.stopFlags()
	var flushedAt time.Time
	var stamp string
	stamped := make(chan time.Duration, 1)
	collect := func(it Item) bool {
		if it.App == "slow" {
			go func() {
				for time.Since(flushedAt) < 2*time.Second {
					if readFlag(c) == stamp {
						stamped <- time.Since(flushedAt)
						return
					}
					time.Sleep(2 * time.Millisecond)
				}
				stamped <- -1
			}()
			time.Sleep(400 * time.Millisecond)
			return false
		}
		return len(s.Observe(it, time.Now(), ruleClassify)) > 0
	}
	flush := func(emitted bool) error {
		e := s.Flush(time.Now(), emitted, false)
		if emitted {
			flushedAt, stamp = time.Now(), s.State.LastEvent.Format(time.RFC3339Nano)+"\n"
		}
		return e
	}
	rows := []Item{newKey(1), {App: "slow"}}
	if _, e := collectSample(rows, collect, flush, noDrain); e != nil {
		t.Fatal(e)
	}
	if d := <-stamped; d < 0 || d > 250*time.Millisecond {
		t.Fatalf("first row's flag stamped after %v during the slow row; bound is 250ms", d)
	}
}

// Bound with the pause between writes: a stamp posted right after a write has
// started is on disk within that write, flagWriteGap and one more write
// (here under 50 ms + 100 ms + 50 ms, checked against 400 ms), and stop does
// not wait for the pause. Negative control: a writer that posts without
// waking the goroutine never writes the second stamp until stop.
func TestFlagWriterBoundWithGap(t *testing.T) {
	var mu sync.Mutex
	var written []string
	w := startFlagWriter(func(b []byte) error {
		time.Sleep(50 * time.Millisecond)
		mu.Lock()
		written = append(written, string(b))
		mu.Unlock()
		return nil
	})
	if e := w.post([]byte("1")); e != nil {
		t.Fatal(e)
	}
	time.Sleep(10 * time.Millisecond) // the first write is in progress
	posted := time.Now()
	if e := w.post([]byte("2")); e != nil {
		t.Fatal(e)
	}
	for {
		mu.Lock()
		n := len(written)
		mu.Unlock()
		if n == 2 {
			break
		}
		if time.Since(posted) > 400*time.Millisecond {
			t.Fatalf("second stamp not written %v after its post", time.Since(posted))
		}
		time.Sleep(2 * time.Millisecond)
	}
	if e := w.post([]byte("3")); e != nil {
		t.Fatal(e)
	}
	stopped := time.Now()
	if e := w.stop(); e != nil {
		t.Fatal(e)
	}
	if d := time.Since(stopped); d > flagWriteGap {
		t.Fatalf("stop took %v; it must not wait for the pause", d)
	}
	if written[len(written)-1] != "3" {
		t.Fatalf("written %v; stop must write the last stamp", written)
	}
}

// Review r2: a snapshot stamps the flag only after rotateJournal's directory
// sync made it durable. When the rotation fails, Save fails and the flag does
// not show the new event, which no journal append holds. Negative control:
// stamping before the rotation, as before, shows it.
func TestSnapshotStampsAfterItsDurabilityBarrier(t *testing.T) {
	s, c := journalStore(t)
	at := time.Now()
	emitNewKey(t, s, 1, at)
	before := readFlag(c)
	if len(s.Observe(newKey(2), at.Add(time.Second), ruleClassify)) == 0 {
		t.Fatal("fixture key did not emit")
	}
	journal := filepath.Join(c.StateDir, journalFile)
	if e := os.Remove(journal); e != nil {
		t.Fatal(e)
	}
	if e := os.MkdirAll(filepath.Join(journal, "blocked"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := s.Save(at.Add(time.Second)); e == nil {
		t.Fatal("fixture: the rotation should fail")
	}
	if readFlag(c) != before {
		t.Fatal("the flag shows an event of a snapshot that did not complete")
	}
}

// Review r2: a flag write error ends the run even while the loop is idle:
// the writer's failure channel wakes the loop, which returns the error at
// once instead of waiting for another stamp. Negative control: a loop that
// does not select the failure channel runs until its context ends.
func TestFlagFailureEndsAnIdleRun(t *testing.T) {
	failed := errors.New("flag disk full")
	w := startFlagWriter(func([]byte) error { return failed })
	defer w.stop()
	f := newLoopFixture(make(chan []byte), time.Hour, time.Hour, &fakeNettop{})
	f.loop.flagFailed, f.loop.flagErr = w.failure(), w.error
	if e := w.post([]byte("x")); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if e := f.loop.run(ctx); !errors.Is(e, failed) || time.Since(start) > 2*time.Second {
		t.Fatalf("run returned %v after %v; want the write error at once", e, time.Since(start))
	}
}

// Review r2, startup ownership: the startup snapshot's stamp goes through
// the flag writer. startRun returns while that write is still blocked, and
// the stamp lands once it proceeds. Negative control: starting the writer
// after the startup snapshot writes the stamp on the caller and blocks.
func TestStartupStampGoesThroughTheWriter(t *testing.T) {
	s, c := journalStore(t)
	stamp := emitNewKey(t, s, 1, time.Now())
	if e := os.Remove(filepath.Join(c.StateDir, "new-events.flag")); e != nil {
		t.Fatal(e)
	}
	r, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	r.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "new-events.flag" {
			<-release
		}
		return atomicWrite(path, b)
	}
	started := make(chan error, 1)
	go func() { _, e := r.startRun(time.Now); started <- e }()
	select {
	case e := <-started:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("startRun waited for the flag write: the startup stamp did not go through the writer")
	}
	once.Do(func() { close(release) })
	if e := r.stopFlags(); e != nil || readFlag(c) != stamp {
		t.Fatalf("stop %v, flag %q; want %q", e, readFlag(c), stamp)
	}
}

// A start that fails stops the flag writer again: a refused startup snapshot
// leaves no writer goroutine behind. Positive control: finishRun after a
// good start writes the final stamp and stops the writer.
func TestRunStartAndFinishOwnTheWriter(t *testing.T) {
	s, c := journalStore(t)
	emitNewKey(t, s, 1, time.Now())
	r, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	failed := errors.New("disk refused")
	r.atomicWrite = func(path string, b []byte) error {
		if filepath.Base(path) == "state.json" {
			return failed
		}
		return atomicWrite(path, b)
	}
	if _, e := r.startRun(time.Now); !errors.Is(e, failed) || r.flags != nil {
		t.Fatalf("start: %v, writer left: %t", e, r.flags != nil)
	}
	g, e := openRun(c, time.Now)
	if e != nil {
		t.Fatal(e)
	}
	stamp := emitNewKey(t, g, 2, time.Now().Add(time.Second))
	if e := g.finishRun(nil, g.now()); e != nil || g.flags != nil || readFlag(c) != stamp {
		t.Fatalf("finish: %v, writer left %t, flag %q; want %q", e, g.flags != nil, readFlag(c), stamp)
	}
}
