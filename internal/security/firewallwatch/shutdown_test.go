package firewallwatch

import (
	"context"
	"errors"
	"math"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Claim: queued shutdown rows persist as backend_shutdown/digest with no review rows or new backend requests.
func TestShutdownQueuedRowsNoReview(t *testing.T) {
	for _, mode := range []string{"cancelled", "backend_stop"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int64
			cl, _ := fakeClassifier(t, func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				embeddingHandler(w, r)
			}, 1, .5)
			s, err := OpenStore(cl.cfg)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			queued := make(chan Item, 3)
			for port := 51000; port < 51003; port++ {
				queued <- Item{Source: "nettop", App: "java", Kind: "outbound", Verdict: "observed", Remote: "loopback", Bucket: "127.0.0.0/24", LocalPort: intp(port)}
			}
			close(queued)
			if mode == "cancelled" {
				cancel()
			} else {
				cl.backend.Stop()
			}
			before := requests.Load()
			for it := range queued {
				if !s.collect(ctx, cl, it) {
					t.Fatal("shutdown row was not retained")
				}
			}
			if requests.Load() != before || len(s.State.Signers) != 0 {
				t.Fatal("shutdown started backend or signer work")
			}
			if err := s.Save(time.Now()); err != nil {
				t.Fatal(err)
			}
			loaded, err := OpenStore(cl.cfg)
			if err != nil {
				t.Fatal(err)
			}
			split := loaded.Split(time.Now().Add(-time.Minute), time.Now())
			if len(split.NeedsReview) != 0 {
				t.Fatalf("shutdown produced %d needs_review rows: %+v", len(split.NeedsReview), split.NeedsReview)
			}
			if len(loaded.State.Events) != 3 || len(loaded.State.Entries) != 3 || split.Window.EventsInWindow != 3 {
				t.Fatalf("shutdown rows lost: %+v", loaded.State)
			}
			for _, e := range loaded.State.Events {
				if e.Label != "digest" || e.Reason != "backend_shutdown" || e.Counts != 1 {
					t.Fatalf("unexpected shutdown row: %+v", e)
				}
			}
			t.Log("queued=3 retained backend_shutdown=3 needs_review=0 new backend requests=0")
		})
	}
}

// Claim: HTTP failure, unexpected child exit and an unloaded pool during normal running remain classifier_unavailable in needs_review.
func TestRunningClassifierFailureNeedsReview(t *testing.T) {
	for _, mode := range []string{"http_failure", "unexpected_exit", "unloaded_pool"} {
		t.Run(mode, func(t *testing.T) {
			var fail atomic.Bool
			cl, _ := fakeClassifier(t, func(w http.ResponseWriter, r *http.Request) {
				if fail.Load() {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				embeddingHandler(w, r)
			}, 1, .5)
			if d := cl.Classify(context.Background(), unmatched("near")); d.Label != "noise" || d.Reason != "knn" {
				t.Fatalf("healthy control: %+v", d)
			}
			switch mode {
			case "http_failure":
				fail.Store(true)
			case "unexpected_exit":
				done := make(chan struct{})
				cl.backend.done = done
				close(done)
			case "unloaded_pool":
				cl.vectors = nil
			}
			s, err := OpenStore(cl.cfg)
			if err != nil {
				t.Fatal(err)
			}
			it := unmatched("near")
			it.Source = "nettop"
			s.collect(context.Background(), cl, it)
			if err := s.Save(time.Now()); err != nil {
				t.Fatal(err)
			}
			loaded, err := OpenStore(cl.cfg)
			if err != nil {
				t.Fatal(err)
			}
			rows := loaded.Split(time.Now().Add(-time.Minute), time.Now()).NeedsReview
			if len(rows) != 1 || rows[0].Reason != "classifier_unavailable" || rows[0].Label != "decide" {
				t.Fatalf("normal failure hidden: %+v", rows)
			}
			t.Log("healthy control=noise/knn failure=classifier_unavailable needs_review=1")
		})
	}
}

// Claim: cancellation or explicit backend Stop during an embedding request records backend_shutdown instead of classifier_unavailable.
func TestShutdownInFlightNoReview(t *testing.T) {
	for _, mode := range []string{"cancelled", "backend_stop"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var trigger atomic.Bool
			var backend *Backend
			cl, _ := fakeClassifier(t, func(w http.ResponseWriter, r *http.Request) {
				if trigger.Load() {
					if mode == "cancelled" {
						cancel()
					} else {
						backend.Stop()
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				embeddingHandler(w, r)
			}, 1, .5)
			backend = cl.backend
			trigger.Store(true)
			s, err := OpenStore(cl.cfg)
			if err != nil {
				t.Fatal(err)
			}
			it := unmatched("near")
			it.Source = "nettop"
			s.collect(ctx, cl, it)
			if len(s.State.Events) != 1 || s.State.Events[0].Reason != "backend_shutdown" || s.State.Events[0].Label != "digest" || len(s.Split(time.Now().Add(-time.Minute), time.Now()).NeedsReview) != 0 {
				t.Fatalf("in-flight shutdown: %+v", s.State.Events)
			}
		})
	}
}

type shutdownObserver struct {
	*SourceCoverage
	stalled chan struct{}
}

func (o shutdownObserver) StallCoverage(at time.Time) {
	o.SourceCoverage.StallCoverage(at)
	close(o.stalled)
}

// Claim: teardown counts all 64 queued lines plus the cancelled feeder's blocked line for both sources, across saves and reloads.
func TestShutdownDiscardedLinesAccounted(t *testing.T) {
	c := testConfig(t)
	s, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{"", SourceNetfilter} {
		coverage := s.Coverage(source)
		s.BeginSourceCoverage(source, time.Now())
		ctx, cancel := context.WithCancel(context.Background())
		lines := make(chan []byte, 64)
		stalled := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			done <- feedLines(ctx, strings.NewReader(strings.Repeat("{}\n", 65)), lines, shutdownObserver{coverage, stalled})
		}()
		select {
		case <-stalled:
		case <-time.After(time.Second):
			cancel()
			t.Fatal("feeder did not fill queue")
		}
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("feeder: %v", err)
		}
		// An earlier save can close coverage before deferred queue cleanup.
		if err := s.Save(time.Now()); err != nil {
			t.Fatal(err)
		}
		discardLines(lines, coverage)
	}
	for i := 0; i < 2; i++ {
		if err := s.Save(time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	want := DroppedLines{ALF: 65, Netfilter: 65}
	if loaded.State.Health.ShutdownDroppedLines != want || loaded.Status()["shutdown_dropped_lines"] != want || len(loaded.State.Events) != 0 {
		t.Fatalf("discard accounting: %+v", loaded.Status())
	}
	loaded.Coverage("").DropLines(math.MaxUint64)
	if err := loaded.Save(time.Now()); err != nil {
		t.Fatal(err)
	}
	if loaded.State.Health.ShutdownDroppedLines.ALF != math.MaxUint64 {
		t.Fatal("discard count did not saturate")
	}
	t.Log("discarded alf=65 netfilter=65 persisted without double counting; saturation passed")
}

// Claim: actual non-nettop denies retain real_deny precedence even when cancellation marks their classification backend_shutdown.
func TestShutdownRealDenyPreserved(t *testing.T) {
	s, err := OpenStore(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.collect(ctx, nil, Item{Source: "alf", App: "test", Verdict: "deny"})
	split := s.Split(time.Now().Add(-time.Minute), time.Now())
	if len(split.RealDeny) != 1 || split.RealDeny[0].Reason != "backend_shutdown" || len(split.NeedsReview) != 0 {
		t.Fatalf("real deny lost: %+v", split)
	}
}

// PR63 review r1: a repeat escalation (an existing key whose rule now decides) is recorded as backend_shutdown, stays out of needs_review and leaves the escalation unrecorded after cancellation or backend Stop; while running, the same upload spike still reaches needs_review.
func TestShutdownRepeatEscalationNoReview(t *testing.T) {
	for _, mode := range []string{"running", "cancelled", "backend_stop"} {
		t.Run(mode, func(t *testing.T) {
			cl, _ := fakeClassifier(t, embeddingHandler, 1, .5)
			s, e := OpenStore(cl.cfg)
			if e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			it := Item{Source: "nettop", App: "near", Kind: "outbound", Verdict: "observed", Remote: "lan", Count: 1}
			s.collect(ctx, cl, it)
			if len(s.Split(time.Now().Add(-time.Minute), time.Now()).NeedsReview) != 0 {
				t.Fatal("healthy first observation reached needs_review")
			}
			switch mode {
			case "cancelled":
				cancel()
			case "backend_stop":
				cl.backend.Stop()
			}
			it.MBOut = 1000
			s.collect(ctx, cl, it)
			split := s.Split(time.Now().Add(-time.Minute), time.Now())
			if mode == "running" {
				if len(split.NeedsReview) != 1 || split.NeedsReview[0].Reason != "policy_upload_spike" {
					t.Fatalf("running control: %+v", split.NeedsReview)
				}
				return
			}
			if len(split.NeedsReview) != 0 {
				t.Fatalf("shutdown repeat escalation reached needs_review: %+v", split.NeedsReview)
			}
			last := s.State.Events[len(s.State.Events)-1]
			if last.Label != "digest" || last.Reason != "backend_shutdown" || last.Counts != 2 {
				t.Fatalf("shutdown repeat row: %+v", last)
			}
			if entry := s.State.Entries[key(cleanItem(it))]; len(entry.Escalated) != 0 {
				t.Fatalf("shutdown recorded an escalation that would suppress the next run's review: %v", entry.Escalated)
			}
		})
	}
}
