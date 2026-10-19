package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/relux-works/mac-infra/internal/maccore"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/security/firewallwatch"
)

func watchConfig(t *testing.T, port int) (string, firewallwatch.Config) {
	t.Helper()
	root := t.TempDir()
	threshold := .5
	pool, e := filepath.Abs("../../internal/security/firewallwatch/testdata/fixtures-v1.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	c := firewallwatch.Config{Schema: "mac-infra.firewall-watch/v1", StateDir: filepath.Join(root, "state"), MaxEntries: 200, RetentionDays: 7, NettopInterval: "10s", DenySpikeCount: 3, DenySpikeWindow: "1m", K: 3, NoveltySimilarity: &threshold, ClassifierTimeout: "120s", LlamaServer: "/opt/homebrew/bin/llama-server", Model: "/Users/alexis/src/relux-works/swarm/local-models/models/qwen3-embedding-0.6b/gguf/Qwen3-Embedding-0.6B-Q8_0.gguf", ModelSHA256: "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439", LabelledPool: pool, Port: port}
	path := filepath.Join(root, "config.json")
	raw, _ := json.Marshal(c)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path, c
}

// The CLI evaluates both copied fixture sets using a loopback fake embedding
// service; it does not execute a real backend or any host collectors.
func TestWatchClassifyFake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&v)
		data := []any{}
		for i := range v.Input {
			data = append(data, map[string]any{"index": i, "embedding": []float64{1, 0}})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	defer server.Close()
	_, p, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	port, _ := strconv.Atoi(p)
	config, _ := watchConfig(t, port)
	old := startWatchBackend
	defer func() { startWatchBackend = old }()
	startWatchBackend = func(context.Context, firewallwatch.Config) (func(), error) { return func() {}, nil }
	for _, file := range []string{"fixtures-v1.jsonl", "fixtures-v2-heldout.jsonl"} {
		var out, errOut bytes.Buffer
		code := run([]string{"watch", "classify", "--config", config, "--fixtures", "../../internal/security/firewallwatch/testdata/" + file, "--json"}, &out, &errOut)
		if code != 0 {
			t.Fatal(code, errOut.String())
		}
		var m firewallwatch.Metrics
		if e := json.Unmarshal(out.Bytes(), &m); e != nil {
			t.Fatal(e)
		}
		if m.N < 31 || m.Unavailable != 0 || !strings.Contains(m.Dataset, "self-labelled") {
			t.Fatal(out.String())
		}
	}
	// Tiny fixture: all three true labels, same vector; k=3 votes noise. Thus
	// 1/3 accuracy, F1(noise)=1/2 => macro F1=1/6, one decide->noise error.
	tiny := filepath.Join(t.TempDir(), "tiny.jsonl")
	raw := ""
	for i, label := range []string{"noise", "digest", "decide"} {
		b, _ := json.Marshal(firewallwatch.Item{ID: strconv.Itoa(i), App: "test", Kind: "outbound", Signer: "dev", Verdict: "allow", Remote: "internet", Label: label})
		raw += string(b) + "\n"
	}
	_ = os.WriteFile(tiny, []byte(raw), 0600)
	var out, errOut bytes.Buffer
	code := run([]string{"watch", "classify", "--config", config, "--fixtures", tiny, "--json"}, &out, &errOut)
	var m firewallwatch.Metrics
	_ = json.Unmarshal(out.Bytes(), &m)
	if code != 0 || m.Accuracy != 1.0/3 || m.MacroF1 != 1.0/6 || m.DecideToNoise != 1 {
		t.Fatal(code, out.String(), errOut.String())
	}
}

// Command-specific flags and missing required operands fail as usage errors;
// absent/unsafe configurations fail as operational errors.
func TestWatchUsage(t *testing.T) {
	for _, args := range [][]string{{"watch"}, {"watch", "wat"}, {"watch", "run"}, {"watch", "run", "--json", "--config", "x"}, {"watch", "classify", "--config", "x"}, {"watch", "status", "--config", "x", "--since", "1h"}, {"watch", "digest", "--config", "x", "--since", "-1h"}} {
		var o, e bytes.Buffer
		if code := run(args, &o, &e); code != 2 {
			t.Fatal(args, code, e.String())
		}
	}
	var o, e bytes.Buffer
	if code := run([]string{"watch", "status", "--config", "/nonexistent-watch-config"}, &o, &e); code != 1 {
		t.Fatal(code)
	}
}

// Status/digest read saved shadow events, apply the duration filter, and never
// enter any of the existing privileged-helper operations.
func TestWatchStatusDigest(t *testing.T) {
	calls := stubHelper(t, maccore.Response{}, nil)
	config, c := watchConfig(t, 41235)
	store, e := firewallwatch.OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	store.Observe(firewallwatch.Item{App: "sample app", Source: "nettop", Verdict: "observed", Remote: "lan"}, now, func(firewallwatch.Item) firewallwatch.Decision {
		return firewallwatch.Decision{Label: "digest", Reason: "test"}
	})
	if e = store.Save(now); e != nil {
		t.Fatal(e)
	}
	for _, command := range []string{"status", "digest"} {
		var o, errOut bytes.Buffer
		args := []string{"watch", command, "--config", config, "--json"}
		if command == "digest" {
			args = append(args, "--since", "1h")
		}
		if code := run(args, &o, &errOut); code != 0 {
			t.Fatal(code, errOut.String())
		}
		var report map[string]any
		if e = json.Unmarshal(o.Bytes(), &report); e != nil {
			t.Fatal(e)
		}
		if command == "status" && report["entries"] != float64(1) {
			t.Fatal(o.String())
		}
		if command == "digest" && !strings.Contains(o.String(), "sample app") {
			t.Fatal(o.String())
		}
	}
	if calls.status != 0 || calls.plan != 0 || calls.apply != 0 {
		t.Fatal("watch called privileged helper", calls)
	}
}
