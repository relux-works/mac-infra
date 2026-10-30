package main

import (
	"bytes"
	"encoding/json"
	"github.com/relux-works/mac-infra/internal/maccore"
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
	root, e := os.MkdirTemp("", "fw-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	threshold := .5
	pool, e := filepath.Abs("../../internal/security/firewallwatch/testdata/fixtures-v1.jsonl")
	if e != nil {
		t.Fatal(e)
	}
	netfilterSource := false
	c := firewallwatch.Config{Schema: "mac-infra.firewall-watch/v1", StateDir: filepath.Join(root, "state"), MaxEntries: 200, RetentionDays: 7, NettopInterval: "10s", DenySpikeCount: 3, DenySpikeWindow: "1m", K: 3, NoveltySimilarity: &threshold, ClassifierTimeout: "120s", LlamaServer: "/opt/homebrew/bin/llama-server", Model: "/Users/alexis/src/relux-works/swarm/local-models/models/qwen3-embedding-0.6b/gguf/Qwen3-Embedding-0.6B-Q8_0.gguf", ModelSHA256: "06507c7b42688469c4e7298b0a1e16deff06caf291cf0a5b278c308249c3e439", LabelledPool: pool, SaveInterval: "10s", SignerFailureTTL: "1s", MaxStateBytes: 32 << 20, MaxModelBytes: 2 << 30, NetfilterSource: &netfilterSource, NetfilterJournalDir: "/private/tmp/netfilter-journal-unused"}
	path := filepath.Join(root, "config.json")
	raw, _ := json.Marshal(c)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	return path, c
}

// The CLI evaluates both fixture sets through a child-owned UNIX fake embedder;
// it starts only that fixture child and never a host collector.
func TestWatchClassifyFake(t *testing.T) {
	config, c := watchConfig(t, 0)
	c = fixtureBackend(t, c)
	configRaw, _ := json.Marshal(c)
	if e := os.WriteFile(config, configRaw, 0600); e != nil {
		t.Fatal(e)
	}
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
	for _, args := range [][]string{{"watch"}, {"watch", "wat"}, {"watch", "run"}, {"watch", "run", "--json", "--config", "x"}, {"watch", "classify", "--config", "x"}, {"watch", "status", "--config", "x", "--since", "1h"}, {"watch", "digest", "--config", "x", "--since", "-1h"}, {"watch", "digest", "--config", "x", "--since", "1h", "--split"}, {"watch", "status", "--config", "x", "--json", "--split"}} {
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

// digest --json --split reads the saved store through the real CLI path and
// emits the split document (window, health, buckets); --split alone is a
// usage error (TestWatchUsage).
func TestWatchDigestSplit(t *testing.T) {
	stubHelper(t, maccore.Response{}, nil)
	config, c := watchConfig(t, 41236)
	store, e := firewallwatch.OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	store.Observe(firewallwatch.Item{App: "sample app", Source: "nettop", Verdict: "observed", Remote: "internet-raw-ip"}, now, func(firewallwatch.Item) firewallwatch.Decision {
		return firewallwatch.Decision{Label: "decide", Reason: "policy_raw_ip"}
	})
	if e = store.Save(now); e != nil {
		t.Fatal(e)
	}
	var o, errOut bytes.Buffer
	if code := run([]string{"watch", "digest", "--config", config, "--json", "--since", "1h", "--split"}, &o, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	var split firewallwatch.DigestSplit
	if e = json.Unmarshal(o.Bytes(), &split); e != nil {
		t.Fatal(e, o.String())
	}
	if g := split.KnownFP[firewallwatch.KnownFPNettopRawIP]; g.Count != 1 || g.Rows[0].App != "sample app" || split.Window.EventsInWindow != 1 {
		t.Fatalf("split: %s", o.String())
	}
	// The consumer reads only split JSON, including positive coalesced totals
	// even when no exact coverage gap remains.
	store.State.Coverage = []firewallwatch.CoverageSpan{{Start: now.Add(-2 * time.Hour), End: now, ShortStalls: 3, ShortStalledNS: 60000000}}
	if e = store.Save(now); e != nil {
		t.Fatal(e)
	}
	o.Reset()
	if code := run([]string{"watch", "digest", "--config", config, "--json", "--since", "1h", "--split"}, &o, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	if e = json.Unmarshal(o.Bytes(), &split); e != nil {
		t.Fatal(e)
	}
	if !split.Window.Truncated || len(split.Window.CoverageGaps) != 0 || split.Window.CoalescedShortStalls.Count != 3 || split.Window.CoalescedShortStalls.StalledNS != 60000000 || !bytes.Contains(o.Bytes(), []byte(`"coalesced_short_stalls":{"count":3,"stalled_ns":60000000}`)) {
		t.Fatalf("coalesced stalls missing from CLI split: %s", o.String())
	}
}

// Both status formats expose persisted queue and timing health without starting a collector.
func TestWatchHealthOutput(t *testing.T) {
	config, c := watchConfig(t, 0)
	s, err := firewallwatch.OpenStore(c)
	if err != nil {
		t.Fatal(err)
	}
	maxAt := time.Date(2026, 10, 29, 0, 15, 0, 0, time.UTC)
	s.State.Health = firewallwatch.RunHealth{
		LineQueueHighWater: firewallwatch.QueueHighWater{ALF: 64, Netfilter: 32, MaxAt: firewallwatch.QueueHighWaterTimes{ALF: &maxAt, Netfilter: &maxAt}},
		Classification:     firewallwatch.TimingSummary{LastNS: 1000000, MaxNS: 2000000, Count: 3, MaxAt: &maxAt},
		Maintenance:        firewallwatch.TimingSummary{LastNS: 3000000, MaxNS: 4000000, Count: 2, MaxAt: &maxAt},
	}
	if err = s.Save(time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, asJSON := range []bool{false, true} {
		var out, errOut bytes.Buffer
		args := []string{"watch", "status", "--config", config}
		if asJSON {
			args = append(args, "--json")
		}
		if code := run(args, &out, &errOut); code != 0 {
			t.Fatal(code, errOut.String())
		}
		if asJSON {
			var status map[string]any
			if err = json.Unmarshal(out.Bytes(), &status); err != nil {
				t.Fatal(err)
			}
			queue := status["line_queue_high_water"].(map[string]any)
			timing := status["run_loop_timing"].(map[string]any)["classification"].(map[string]any)
			maintenance := status["run_loop_timing"].(map[string]any)["maintenance"].(map[string]any)
			times := queue["max_at"].(map[string]any)
			if queue["alf"] != float64(64) || queue["netfilter"] != float64(32) || timing["count"] != float64(3) || times["alf"] != maxAt.Format(time.RFC3339) || times["netfilter"] != maxAt.Format(time.RFC3339) || timing["max_at"] != maxAt.Format(time.RFC3339) || maintenance["count"] != float64(2) || maintenance["max_at"] != maxAt.Format(time.RFC3339) {
				t.Fatal(status)
			}
		} else {
			for _, want := range []string{"line queue high-water: alf=64 netfilter=32", "save: last=", "classification: last=1ms max=2ms count=3", "maintenance: last=3ms max=4ms count=2", "maxima at: line queue alf=2026-10-29T00:15:00Z netfilter=2026-10-29T00:15:00Z; save=unknown classification=2026-10-29T00:15:00Z maintenance=2026-10-29T00:15:00Z"} {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("missing %s: %s", want, out.String())
				}
			}
		}
	}
}

// watch repair is wired: without --out it is a usage error (2); against a
// readable state directory it writes the repair beside it, reports JSON with
// no changes and an opening copy, and exits 0; a second run into the same
// output refuses with 1. It never starts a backend or collector.
func TestWatchRepairCLI(t *testing.T) {
	config, c := watchConfig(t, 0)
	s, e := firewallwatch.OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	if e := s.Save(time.Now()); e != nil {
		t.Fatal(e)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"watch", "repair", "--config", config}, &out, &errOut); code != 2 {
		t.Fatalf("missing --out: exit %d", code)
	}
	dir := filepath.Join(t.TempDir(), "repair")
	out.Reset()
	errOut.Reset()
	if code := run([]string{"watch", "repair", "--config", config, "--out", dir}, &out, &errOut); code != 0 {
		t.Fatalf("repair: exit %d, %s", code, errOut.String())
	}
	var report firewallwatch.RepairReport
	if e := json.Unmarshal(out.Bytes(), &report); e != nil || !report.Opens || len(report.Changes) != 0 {
		t.Fatalf("report %s (%v)", out.String(), e)
	}
	if code := run([]string{"watch", "repair", "--config", config, "--out", dir}, &out, &errOut); code != 1 {
		t.Fatalf("existing output: exit %d", code)
	}
}
