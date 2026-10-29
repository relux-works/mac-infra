package firewallwatch

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
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
	want := []string{"drain", "collect a", "drain", "collect b", "flush", "drain", "collect c"}
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
	if _, e := collectSample(items, collect, flush, drain); !errors.Is(e, failed) || !reflect.DeepEqual(calls, []string{"collect a"}) {
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
// at most one queue's worth per source, then the sample continues.
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
