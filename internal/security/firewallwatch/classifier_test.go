package firewallwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeClassifier(t *testing.T, handler http.HandlerFunc, k int, threshold float64) (*Classifier, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	host, p, e := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if e != nil || host != "127.0.0.1" {
		t.Fatal(server.URL)
	}
	c := testConfig(t)
	c.Port, _ = strconv.Atoi(p)
	c.K = k
	c.NoveltySimilarity = &threshold
	pool := []Item{{ID: "n1", App: "near", Kind: "outbound", Verdict: "allow", Remote: "internet", Signer: "dev", Label: "noise"}, {ID: "d1", App: "far", Kind: "outbound", Verdict: "allow", Remote: "internet", Signer: "dev", Label: "digest"}}
	var b strings.Builder
	for _, it := range pool {
		raw, _ := json.Marshal(it)
		b.Write(raw)
		b.WriteByte('\n')
	}
	_ = os.WriteFile(c.LabelledPool, []byte(b.String()), 0600)
	cl, e := NewClassifier(c)
	if e != nil {
		t.Fatal(e)
	}
	if e = cl.Init(context.Background()); e != nil {
		t.Fatal(e)
	}
	return cl, server
}
func embeddingHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Input []string `json:"input"`
	}
	if r.URL.Path != "/v1/embeddings" || json.NewDecoder(r.Body).Decode(&request) != nil {
		http.Error(w, "bad", 400)
		return
	}
	var data []any
	for i, text := range request.Input {
		v := []float64{1, 0}
		if strings.Contains(text, `app="far"`) {
			v = []float64{0, 1}
		}
		if strings.Contains(text, `app="novel"`) {
			v = []float64{-1, 0}
		}
		data = append(data, map[string]any{"index": i, "embedding": v})
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}
func unmatched(app string) Item {
	return Item{App: app, Kind: "outbound", Verdict: "allow", Signer: "dev", Remote: "internet"}
}

// Deterministic vectors choose the closest labelled neighbour, novelty fails to
// decide, and a weighted tie picks the riskier label as in the benchmark.
func TestKNN(t *testing.T) {
	cl, _ := fakeClassifier(t, embeddingHandler, 1, .5)
	for _, tc := range []struct{ app, label, reason string }{{"near", "noise", "knn"}, {"far", "digest", "knn"}, {"novel", "decide", "novel"}} {
		d := cl.Classify(context.Background(), unmatched(tc.app))
		if d.Label != tc.label || d.Reason != tc.reason || len(d.Neighbours) != 1 {
			t.Fatalf("%s %+v", tc.app, d)
		}
	}
	cl.cfg.K = 2
	cl.vectors = [][]float64{{1, 0}, {1, 0}}
	d := cl.Classify(context.Background(), unmatched("near"))
	if d.Label != "digest" {
		t.Fatal("tie", d)
	}
	cl.pool[1].Label = "decide"
	d = cl.Classify(context.Background(), unmatched("near"))
	if d.Label != "decide" {
		t.Fatal("riskier tie", d)
	}
}

// Timeout, HTTP failure, invalid JSON/shape/norm/dimensions and redirection all
// return classifier_unavailable/decide. The same backend first passes a control.
func TestClassifierFailures(t *testing.T) {
	for _, mode := range []string{"timeout", "500", "garbage", "empty", "index", "duplicate", "zero", "dimensions", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			var fail atomic.Bool
			cl, server := fakeClassifier(t, func(w http.ResponseWriter, r *http.Request) {
				if !fail.Load() {
					embeddingHandler(w, r)
					return
				}
				switch mode {
				case "timeout":
					time.Sleep(60 * time.Millisecond)
					embeddingHandler(w, r)
				case "500":
					w.WriteHeader(500)
				case "garbage":
					fmt.Fprint(w, "garbage")
				case "empty":
					fmt.Fprint(w, `{"data":[]}`)
				case "index":
					fmt.Fprint(w, `{"data":[{"index":7,"embedding":[1,0]}]}`)
				case "duplicate":
					fmt.Fprint(w, `{"data":[{"index":0,"embedding":[1,0]},{"index":0,"embedding":[1,0]}]}`)
				case "zero":
					fmt.Fprint(w, `{"data":[{"index":0,"embedding":[0,0]}]}`)
				case "dimensions":
					fmt.Fprint(w, `{"data":[{"index":0,"embedding":[1]}]}`)
				case "redirect":
					http.Redirect(w, r, "http://192.0.2.9:80", 302)
				}
			}, 1, .5)
			if d := cl.Classify(context.Background(), unmatched("near")); d.Label != "noise" {
				t.Fatal("positive control", d)
			}
			fail.Store(true)
			cl.client.Timeout = 10 * time.Millisecond
			d := cl.Classify(context.Background(), unmatched("near"))
			if d.Label != "decide" || d.Reason != "classifier_unavailable" || cl.Healthy() {
				t.Fatal(d)
			}
			// Hard rules continue to work through backend failures.
			it := unmatched("x")
			it.Verdict = "deny"
			if d := cl.Classify(context.Background(), it); d.Reason != "hard_non_allow" {
				t.Fatal(d)
			}
			server.Close()
		})
	}
}

// Hash mismatch precedes executable lookup: a fake binary is never started.
func TestModelMismatch(t *testing.T) {
	c := testConfig(t)
	_ = os.WriteFile(c.Model, []byte("model"), 0600)
	stop, e := StartBackend(context.Background(), c)
	if stop != nil || e == nil || !strings.Contains(e.Error(), "sha256 mismatch") {
		t.Fatalf("%v", e)
	}
	sum := sha256.Sum256([]byte("model"))
	c.ModelSHA256 = hex.EncodeToString(sum[:])
	_, e = StartBackend(context.Background(), c)
	if e == nil || strings.Contains(e.Error(), "mismatch") {
		t.Fatal("matching hash did not pass hash gate", e)
	}
}

// Child lifecycle uses a task-owned local fixture process, not llama-server;
// cancellation during startup reaps the child and returns promptly.
func TestBackendStartupCancellation(t *testing.T) {
	c := testConfig(t)
	model := []byte("model")
	_ = os.WriteFile(c.Model, model, 0600)
	h := sha256.Sum256(model)
	c.ModelSHA256 = hex.EncodeToString(h[:])
	c.LlamaServer = filepath.Join(t.TempDir(), "child")
	_ = os.WriteFile(c.LlamaServer, []byte("#!/bin/sh\nexec /bin/sleep 20\n"), 0700)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	c.Port = listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, e = StartBackend(ctx, c)
	if e == nil || time.Since(start) > 3*time.Second {
		t.Fatal(e)
	}
}

// Metric arithmetic is independent of model quality: a hand-computed confusion
// matrix has accuracy 1/2, macro F1 4/9, and exactly one decide->noise error.
func TestMetrics(t *testing.T) {
	items := []Item{{Label: "noise"}, {Label: "digest"}, {Label: "decide"}, {Label: "decide"}}
	pred := []string{"noise", "digest", "noise", "digest"}
	i := 0
	m := Evaluate(context.Background(), items, func(context.Context, Item) Decision { d := Decision{Label: pred[i]}; i++; return d })
	if m.Accuracy != .5 || m.MacroF1 < .444444 || m.MacroF1 > .444445 || m.DecideToNoise != 1 || m.N != 4 || m.P50MS < 0 || m.P95MS < m.P50MS {
		t.Fatalf("%+v", m)
	}
}

// Idle health checks discover backend loss without requiring a new dedup item;
// a ready HTTP server alone is insufficient if the pool never initialized.
func TestIdleHealth(t *testing.T) {
	var down atomic.Bool
	cl, _ := fakeClassifier(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if down.Load() {
				w.WriteHeader(500)
			}
			return
		}
		embeddingHandler(w, r)
	}, 1, .5)
	if !cl.CheckHealth(context.Background()) {
		t.Fatal("healthy backend rejected")
	}
	down.Store(true)
	if cl.CheckHealth(context.Background()) || cl.Healthy() {
		t.Fatal("failed backend still healthy")
	}
	down.Store(false)
	cl.vectors = nil
	if cl.CheckHealth(context.Background()) {
		t.Fatal("uninitialized pool marked ready")
	}
}
