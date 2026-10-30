package firewallwatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func noDrain() error { return nil }

// BUG-261029-kpyw8s: a nettop sample drains the collector queues before every
// item, so slow classifications do not leave the feeders blocked for the whole
// sample. A failed drain stops the sample before that item is classified.
func TestCollectSampleDrainsBeforeEachItem(t *testing.T) {
	items := []Item{{App: "a"}, {App: "b"}, {App: "c"}}
	var calls []string
	collect := func(it Item) bool { calls = append(calls, "collect "+it.App); return it.App == "b" }
	flush := func(bool) error { calls = append(calls, "flush"); return nil }
	drain := func() error { calls = append(calls, "drain"); return nil }
	emitted, e := collectSample(items, collect, flush, drain)
	// flush runs after every row, emitting or not (PR69 review r2).
	want := []string{"drain", "collect a", "flush", "drain", "collect b", "flush", "drain", "collect c", "flush"}
	if e != nil || !emitted || !reflect.DeepEqual(calls, want) {
		t.Fatalf("emitted=%t err=%v calls=%v; want %v", emitted, e, calls, want)
	}

	calls = nil
	failed := errors.New("ALF log stream ended")
	n := 0
	drain = func() error {
		if n++; n == 2 {
			return failed
		}
		return nil
	}
	if _, e := collectSample(items, collect, flush, drain); !errors.Is(e, failed) || !reflect.DeepEqual(calls, []string{"collect a", "flush"}) {
		t.Fatalf("err=%v calls=%v; want the drain error after one item", e, calls)
	}
}

// drainQueued handles every line already queued on both sources without
// blocking, and returns once the queues are empty. An empty queue returns at
// once (the positive control for "does not wait").
func TestDrainQueuedEmptiesReadyLines(t *testing.T) {
	alf, net := make(chan []byte, 4), make(chan []byte, 4)
	for i := 0; i < 3; i++ {
		alf <- []byte(fmt.Sprintf("alf%d", i))
	}
	net <- []byte("net0")
	var got []string
	onALF := func(l []byte, ok bool) (bool, error) { got = append(got, string(l)); return false, nil }
	onNet := func(l []byte, ok bool) error { got = append(got, string(l)); return nil }
	if e := drainQueued(context.Background(), alf, &net, onALF, onNet); e != nil || len(got) != 4 || len(alf) != 0 || len(net) != 0 {
		t.Fatalf("err=%v handled=%v left alf=%d net=%d", e, got, len(alf), len(net))
	}
	got = nil
	if e := drainQueued(context.Background(), alf, &net, onALF, onNet); e != nil || len(got) != 0 {
		t.Fatalf("empty queues: err=%v handled=%v", e, got)
	}
}

// A feeder that keeps the queue full cannot hold the sample: one drain handles
// at most one queue's worth, then the sample continues. Netfilter is disabled
// here; TestDrainQueuedBoundIsPerSource covers both sources.
func TestDrainQueuedIsBounded(t *testing.T) {
	alf := make(chan []byte, 4)
	var net chan []byte // netfilter disabled
	for i := 0; i < cap(alf); i++ {
		alf <- []byte("x")
	}
	handled := 0
	onALF := func(l []byte, ok bool) (bool, error) { handled++; alf <- l; return false, nil } // refills at once
	onNet := func([]byte, bool) error { t.Fatal("disabled netfilter selected"); return nil }
	if e := drainQueued(context.Background(), alf, &net, onALF, onNet); e != nil || handled != cap(alf) {
		t.Fatalf("err=%v handled=%d; want %d", e, handled, cap(alf))
	}
}

// After cancellation nothing is drained, so the sample keeps its shutdown
// behaviour. A closed ALF queue ends the drain with the handler's verdict, and
// a netfilter queue its handler set to nil is not selected again.
func TestDrainQueuedCancellationAndClosedQueues(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	alf := make(chan []byte, 2)
	alf <- []byte("x")
	var net chan []byte
	onALF := func([]byte, bool) (bool, error) { t.Fatal("drained after cancellation"); return false, nil }
	if e := drainQueued(ctx, alf, &net, onALF, nil); e != nil || len(alf) != 1 {
		t.Fatalf("cancelled: err=%v left=%d", e, len(alf))
	}

	ended := errors.New("ALF log stream ended")
	closedALF := make(chan []byte, 2)
	close(closedALF)
	calls := 0
	onEnd := func(_ []byte, ok bool) (bool, error) { calls++; return !ok, ended }
	if e := drainQueued(context.Background(), closedALF, &net, onEnd, nil); !errors.Is(e, ended) || calls != 1 {
		t.Fatalf("closed ALF: err=%v calls=%d", e, calls)
	}

	empty := make(chan []byte, 2)
	net = make(chan []byte, 2)
	close(net)
	ends := 0
	onNet := func(_ []byte, ok bool) error {
		if !ok {
			ends++
			net = nil
		}
		return nil
	}
	if e := drainQueued(context.Background(), empty, &net, nil, onNet); e != nil || ends != 1 || net != nil {
		t.Fatalf("closed netfilter: err=%v ends=%d", e, ends)
	}
}

// PR67 review r1, finding 1: with both sources enabled, each has its own
// budget of one queue's worth. A refilling ALF queue cannot spend the
// netfilter budget, and both sources are still served within one drain.
func TestDrainQueuedBoundIsPerSource(t *testing.T) {
	alf, net := make(chan []byte, 4), make(chan []byte, 4)
	for i := 0; i < cap(alf); i++ {
		alf <- []byte("a")
	}
	net <- []byte("n1")
	net <- []byte("n2")
	alfHandled, netHandled := 0, 0
	onALF := func(l []byte, ok bool) (bool, error) { alfHandled++; alf <- l; return false, nil } // refills at once
	onNet := func([]byte, bool) error { netHandled++; return nil }
	if e := drainQueued(context.Background(), alf, &net, onALF, onNet); e != nil || alfHandled != cap(alf) || netHandled != 2 {
		t.Fatalf("err=%v alf=%d net=%d; want %d and 2", e, alfHandled, netHandled, cap(alf))
	}

	// Both sources refilling: each stops at its own capacity.
	for len(net) < cap(net) {
		net <- []byte("n")
	}
	alfHandled, netHandled = 0, 0
	onNet = func(l []byte, ok bool) error { netHandled++; net <- l; return nil }
	if e := drainQueued(context.Background(), alf, &net, onALF, onNet); e != nil || alfHandled != cap(alf) || netHandled != cap(net) {
		t.Fatalf("err=%v alf=%d net=%d; want %d each", e, alfHandled, netHandled, cap(alf))
	}
}

func nettopResult(t *testing.T, raw []byte, err error) nettopRun {
	t.Helper()
	out := &cappedBuffer{limit: 4 << 20}
	if _, e := out.Write(raw); e != nil {
		t.Fatal(e)
	}
	return nettopRun{output: out, err: err}
}

// PR67 review r1, finding 2: a nettop sample is a slow-operation candidate on
// every exit. A failed or timed-out collector command records the sample with
// no rows, sets nettop_error and emits nothing; a successful one records its
// parsed row count and clears the error. BUG-261030-pq91zb: a command killed at
// its timeout after writing complete rows (a late sample) collects none of
// them, and the recorded duration runs from the command start.
func TestSampleNettopRecordsEveryExit(t *testing.T) {
	saved := slowOpThreshold
	slowOpThreshold = 0
	t.Cleanup(func() { slowOpThreshold = saved })
	raw, e := os.ReadFile("testdata/nettop.csv")
	if e != nil {
		t.Fatal(e)
	}
	s := pruneFixture(t, 20)
	collected := 0
	collect := func(Item) bool { collected++; return false }
	flush := func(bool) error { return nil }

	timeout := errors.New("signal: killed")
	emitted, e := s.sampleNettop(nettopResult(t, nil, timeout), time.Now(), collect, flush, noDrain)
	ops := s.State.Health.SlowOps
	if emitted || e != nil || s.State.NettopError == "" || len(ops) != 1 || ops[0].Kind != SlowNettopSample || ops[0].Items != 0 {
		t.Fatalf("failed command: emitted=%t err=%v nettop_error=%q ops=%+v", emitted, e, s.State.NettopError, ops)
	}

	start := time.Now().Add(-30 * time.Second)
	_, e = s.sampleNettop(nettopResult(t, raw, nil), start, collect, flush, noDrain)
	ops = s.State.Health.SlowOps
	if e != nil || s.State.NettopError != "" || len(ops) != 2 || ops[1].Items != 7 || collected != 7 {
		t.Fatalf("successful command: err=%v nettop_error=%q collected=%d ops=%+v", e, s.State.NettopError, collected, ops)
	}
	if time.Duration(ops[1].NS) < 30*time.Second {
		t.Fatalf("duration %v does not include the command time", time.Duration(ops[1].NS))
	}

	collected = 0
	emitted, e = s.sampleNettop(nettopResult(t, raw, timeout), time.Now(), collect, flush, noDrain)
	ops = s.State.Health.SlowOps
	if emitted || e != nil || collected != 0 || s.State.NettopError == "" || len(ops) != 3 || ops[2].Items != 0 {
		t.Fatalf("late sample: emitted=%t err=%v collected=%d nettop_error=%q ops=%+v", emitted, e, collected, s.State.NettopError, ops)
	}

	// A drain error still records the sample with its rows.
	failed := errors.New("ALF log stream ended")
	_, e = s.sampleNettop(nettopResult(t, raw, nil), time.Now(), collect, flush, func() error { return failed })
	if ops = s.State.Health.SlowOps; !errors.Is(e, failed) || len(ops) != 4 || ops[3].Items != 7 {
		t.Fatalf("drain error: err=%v ops=%+v", e, ops)
	}
}
