package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/mac-infra/internal/security/firewallwatch"
)

// One actual pinned CPU backend evaluates both independent heldout sets against
// the expanded pool. This proves only synthetic policy conformance; it neither
// measures real traffic accuracy nor changes a live pool, config, or service.
func TestWatchNetfilterRealModel(t *testing.T) {
	if os.Getenv("MAC_FIREWALL_REAL_MODEL") != "1" {
		t.Skip("set MAC_FIREWALL_REAL_MODEL=1 for the pinned CPU model evaluation")
	}
	_, cfg := watchConfig(t, 0)
	pool, err := filepath.Abs("../../internal/security/firewallwatch/testdata/fixtures-v3-pool.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	cfg.LabelledPool = pool
	training, err := firewallwatch.LoadItems(pool)
	if err != nil {
		t.Fatal(err)
	}
	netfilterIDs := map[string]bool{}
	for _, it := range training {
		if it.Source == "netfilter" {
			netfilterIDs[it.ID] = true
		}
	}
	wrapper := filepath.Join(t.TempDir(), "cpu-server")
	if err = os.WriteFile(wrapper, []byte("#!/bin/sh\nexec /opt/homebrew/bin/llama-server --device none --n-gpu-layers 0 --no-kv-offload --threads 2 --threads-batch 2 \"$@\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.LlamaServer = wrapper
	ctx := context.Background()
	backend, err := firewallwatch.StartBackend(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(backend.Stop)
	classifier, err := firewallwatch.NewClassifier(cfg)
	if err != nil {
		t.Fatal(err)
	}
	classifier.BindBackend(backend)
	if err = classifier.Init(ctx); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"fixtures-v2-heldout.jsonl", "fixtures-v4-netfilter-heldout.jsonl"} {
		t.Run(file, func(t *testing.T) {
			items, err := firewallwatch.LoadItems("../../internal/security/firewallwatch/testdata/" + file)
			if err != nil {
				t.Fatal(err)
			}
			unmatched, voted, netfilterVoted := 0, 0, 0
			metrics := firewallwatch.Evaluate(ctx, items, func(ctx context.Context, it firewallwatch.Item) firewallwatch.Decision {
				d := classifier.Classify(ctx, it)
				if _, fired := firewallwatch.Rules(it); !fired && it.Source == "netfilter" {
					unmatched++
					if d.Reason == "knn" && len(d.Neighbours) > 0 {
						hasVote, hasNetfilterVote := false, false
						for _, neighbour := range d.Neighbours {
							if neighbour.Similarity >= *cfg.NoveltySimilarity {
								hasVote = true
								if netfilterIDs[neighbour.ID] {
									hasNetfilterVote = true
								}
							}
						}
						if hasVote {
							voted++
						}
						if hasNetfilterVote {
							netfilterVoted++
						}
					}
				}
				if d.Label != it.Label {
					t.Logf("mismatch id=%s expected=%s actual=%s reason=%s", it.ID, it.Label, d.Label, d.Reason)
				}
				return d
			})
			raw, err := json.Marshal(metrics)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("metrics=%s unmatched_netfilter=%d qualifying_knn=%d qualifying_netfilter_neighbour=%d", raw, unmatched, voted, netfilterVoted)
			if metrics.Accuracy < .85 || metrics.DecideToNoise != 0 || metrics.Unavailable != 0 {
				t.Errorf("synthetic quality gate: %+v", metrics)
			}
			if file == "fixtures-v4-netfilter-heldout.jsonl" && (unmatched == 0 || voted == 0 || netfilterVoted == 0) {
				t.Errorf("netfilter pool supplied no qualifying kNN neighbours: unmatched=%d voted=%d netfilterVoted=%d", unmatched, voted, netfilterVoted)
			}
		})
	}
}
