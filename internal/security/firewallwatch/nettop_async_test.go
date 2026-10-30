package firewallwatch

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// stallCounter is a collectionObserver that counts feeder stalls.
type stallCounter struct{ stalls atomic.Int64 }

func (c *stallCounter) StallCoverage(time.Time)  { c.stalls.Add(1) }
func (c *stallCounter) ResumeCoverage(time.Time) {}
func (c *stallCounter) EndCoverage(time.Time)    {}

// fakeNettop records command starts, completions and overlap.
type fakeNettop struct {
	mu       sync.Mutex
	starts   []time.Time
	running  int
	overlap  int
	sawCtx   []error
	duration time.Duration // 0: run until the context ends (the timeout)
}

func (f *fakeNettop) command(ctx context.Context, out io.Writer) error {
	f.mu.Lock()
	f.starts = append(f.starts, time.Now())
	f.running++
	f.overlap = max(f.overlap, f.running)
	f.mu.Unlock()
	if f.duration == 0 {
		<-ctx.Done()
	} else {
		time.Sleep(f.duration) // ignores the context: a command that returns late
	}
	f.mu.Lock()
	f.running--
	f.sawCtx = append(f.sawCtx, ctx.Err())
	f.mu.Unlock()
	return ctx.Err()
}

// loopFixture wires runLoop as Run does, with a fake nettop command.
type loopFixture struct {
	loop      *runLoop
	nettop    *fakeNettop
	mu        sync.Mutex
	completed []time.Time
	flushes   []time.Time
	handled   int
}

func newLoopFixture(alf <-chan []byte, interval, saveEvery time.Duration, nettop *fakeNettop) *loopFixture {
	f := &loopFixture{nettop: nettop}
	var netLines chan []byte
	f.loop = &runLoop{
		alf: alf, netfilter: &netLines, saveTick: time.NewTicker(saveEvery).C,
		tick: time.NewTicker(interval), interval: interval, sampler: newNettopSampler(nettop.command),
		onALF: func(line []byte, ok bool) (bool, error) {
			if !ok {
				return true, nil
			}
			f.mu.Lock()
			f.handled++
			f.mu.Unlock()
			return false, nil
		},
		onNetfilter: func([]byte, bool) error { return nil },
		flush: func(bool) error {
			f.mu.Lock()
			f.flushes = append(f.flushes, time.Now())
			f.mu.Unlock()
			return nil
		},
		sample: func(nettopRun, time.Time) error {
			f.mu.Lock()
			f.completed = append(f.completed, time.Now())
			f.mu.Unlock()
			return nil
		},
	}
	return f
}

// paced writes n lines, one every gap, then closes the pipe.
func paced(w *io.PipeWriter, n int, gap time.Duration) {
	t := time.NewTicker(gap)
	defer t.Stop()
	for i := 0; i < n; i++ {
		<-t.C
		if _, e := w.Write([]byte("line " + strconv.Itoa(i) + "\n")); e != nil {
			break
		}
	}
	w.Close()
}

// BUG-261030-pq91zb witness: under a steady line flood (one line per 3 ms,
// about 330 lines/s, the order of the 01:33-01:38Z episode), a nettop command
// that runs to its timeout does not stall the feeder, because the loop keeps
// handling lines while it runs; the save timer keeps firing during the command;
// and every line is handled. The queue holds 64 lines, so a loop blocked for
// the 500 ms command fills it in about 192 ms: the synchronous shape at 09479cc
// stalls here (negative control m1). Limit: a scheduler pause of over ~190 ms
// on the test host would also stall; the control blocks 500 ms per sample.
func TestRunLoopHandlesLinesWhileNettopRuns(t *testing.T) {
	const interval, lines = 500 * time.Millisecond, 600
	queue := make(chan []byte, 64)
	r, w := io.Pipe()
	stalls := &stallCounter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fed := make(chan error, 1)
	go func() { fed <- feedLines(ctx, r, queue, stalls, time.Now) }()
	go paced(w, lines, 3*time.Millisecond)

	nettop := &fakeNettop{}
	f := newLoopFixture(queue, interval, 50*time.Millisecond, nettop)
	if e := f.loop.run(ctx); e != nil {
		t.Fatal(e)
	}
	f.loop.sampler.wait()
	<-fed

	nettop.mu.Lock()
	starts := append([]time.Time(nil), nettop.starts...)
	nettop.mu.Unlock()
	if len(starts) < 2 || len(f.completed) < 1 {
		t.Fatalf("fixture ran %d commands, %d completed; want at least 2 and 1", len(starts), len(f.completed))
	}
	if n := stalls.stalls.Load(); n != 0 {
		t.Fatalf("feeder stalled %d times while nettop ran", n)
	}
	if f.handled != lines {
		t.Fatalf("handled %d of %d lines", f.handled, lines)
	}
	during := 0
	for _, at := range f.flushes {
		if at.After(starts[0]) && at.Before(f.completed[0]) {
			during++
		}
	}
	if during == 0 {
		t.Fatal("the save timer did not fire while the first command ran")
	}
}

// BUG-261030-pq91zb: at most one nettop child runs at a time, and a sample
// that outlasts nettop_interval is not followed at once by another: the next
// command starts about a full interval after the previous one completed. The
// fake command ignores its context and returns 2.5 intervals after it started
// (a late command). Negative controls: without the busy guard the commands
// overlap (m3); without the tick restart the next command starts within half
// an interval of the completion (m2).
func TestNettopSamplerOneCommandNoBackToBack(t *testing.T) {
	const interval = 100 * time.Millisecond
	nettop := &fakeNettop{duration: 250 * time.Millisecond}
	f := newLoopFixture(make(chan []byte), interval, time.Hour, nettop)
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	if e := f.loop.run(ctx); e != nil {
		t.Fatal(e)
	}
	f.loop.sampler.wait()

	nettop.mu.Lock()
	defer nettop.mu.Unlock()
	if nettop.overlap != 1 {
		t.Fatalf("%d nettop commands ran at once; want 1", nettop.overlap)
	}
	if len(f.completed) < 2 || len(nettop.starts) < 3 {
		t.Fatalf("fixture: %d starts, %d completed", len(nettop.starts), len(f.completed))
	}
	for i, done := range f.completed {
		if i+1 >= len(nettop.starts) {
			break
		}
		if gap := nettop.starts[i+1].Sub(done); gap < interval*8/10 {
			t.Fatalf("command %d started %v after the previous sample completed; want about %v", i+1, gap, interval)
		}
	}
	for i, e := range nettop.sawCtx {
		if e == nil {
			t.Fatalf("command %d returned before its timeout; the fixture needs a late command", i)
		}
	}
}

// BUG-261030-pq91zb: cancellation while a command runs ends the loop cleanly;
// wait cancels that command and returns once it has, and its result is never
// collected. Positive control: the same fixture without cancellation collects
// the command's result (TestNettopSamplerOneCommandNoBackToBack). Limit: here
// cancellation usually wins the select before the result is sent; the case
// where both are ready is TestRunLoopDropsResultReadyAtCancellation.
func TestRunLoopCancelDuringNettop(t *testing.T) {
	nettop := &fakeNettop{}
	f := newLoopFixture(make(chan []byte), 50*time.Millisecond, time.Hour, nettop)
	ctx, cancel := context.WithCancel(context.Background())
	// The command's own timeout is far away: only the cancellation can end it.
	f.loop.interval = time.Hour
	f.loop.tick.Reset(50 * time.Millisecond)
	go func() {
		for {
			nettop.mu.Lock()
			started := len(nettop.starts) > 0
			nettop.mu.Unlock()
			if started {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	done := make(chan error, 1)
	go func() { done <- f.loop.run(ctx) }()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not end on cancellation")
	}
	waited := make(chan struct{})
	go func() { f.loop.sampler.wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("wait did not return after cancellation")
	}
	nettop.mu.Lock()
	defer nettop.mu.Unlock()
	if nettop.running != 0 || len(nettop.sawCtx) != 1 || nettop.sawCtx[0] != context.Canceled || len(f.completed) != 0 {
		t.Fatalf("running=%d ctx=%v collected=%d", nettop.running, nettop.sawCtx, len(f.completed))
	}
}

// PR70 review r1: when a command result and cancellation are both ready, the
// loop never collects the result, whichever case select picks, and the sampler
// ends idle with no result left behind. Each of 200 rounds starts with both
// ready; the shape without the cancellation check collects in about half of
// them (negative control m6). Positive control: a result without cancellation
// is collected (TestNettopSamplerOneCommandNoBackToBack).
func TestRunLoopDropsResultReadyAtCancellation(t *testing.T) {
	for round := 0; round < 200; round++ {
		f := newLoopFixture(make(chan []byte), time.Hour, time.Hour, &fakeNettop{})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		sampler := f.loop.sampler
		sampler.busy, sampler.stop, sampler.start = true, func() {}, time.Now()
		sampler.done <- nettopRun{output: &cappedBuffer{limit: 1}, err: context.Canceled}
		if e := f.loop.run(ctx); e != nil {
			t.Fatal(e)
		}
		sampler.wait()
		if len(f.completed) != 0 || sampler.busy || len(sampler.done) != 0 {
			t.Fatalf("round %d: collected=%d busy=%t left=%d", round, len(f.completed), sampler.busy, len(sampler.done))
		}
	}
}

// BUG-261030-pq91zb, sysadmin condition $l3Q3xcKA: a command that outlives its
// timeout is killed by its own PID and nothing else. The child here starts a
// grandchild that keeps the output pipe open; runChild still returns within
// WaitDelay, the child is gone, and both the grandchild and an unrelated
// sibling process are untouched. Negative control: without WaitDelay runChild
// blocks until the grandchild exits (m4).
func TestRunChildKillsOnlyItsOwnChild(t *testing.T) {
	dir := t.TempDir()
	sibling := exec.Command("/bin/sleep", "30")
	if e := sibling.Start(); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = sibling.Process.Kill(); _ = sibling.Wait() })
	pidFile := filepath.Join(dir, "grandchild")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	child := exec.CommandContext(ctx, "/bin/sh", "-c", `/bin/sleep 30 & echo $! > "$1"; wait`, "sh", pidFile)
	start := time.Now()
	e := runChild(child, &cappedBuffer{limit: 1 << 10})
	elapsed := time.Since(start)
	raw, readErr := os.ReadFile(pidFile)
	grandchild, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if grandchild > 0 {
		t.Cleanup(func() { _ = syscall.Kill(grandchild, syscall.SIGKILL) })
	}
	if e == nil || elapsed > 5*time.Second {
		t.Fatalf("runChild returned %v after %v; want a kill error within the WaitDelay bound", e, elapsed)
	}
	if ws, ok := child.ProcessState.Sys().(syscall.WaitStatus); !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("child state %v; want killed by SIGKILL", child.ProcessState)
	}
	if readErr != nil || grandchild <= 0 || syscall.Kill(grandchild, 0) != nil {
		t.Fatalf("grandchild %d (read %v) is not alive: the kill reached beyond the child", grandchild, readErr)
	}
	if syscall.Kill(sibling.Process.Pid, 0) != nil {
		t.Fatal("an unrelated process was killed")
	}
}
