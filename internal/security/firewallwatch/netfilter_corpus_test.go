package firewallwatch

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The versioned pool preserves every historical training row, adds netfilter
// examples for all policy labels, and never trains on a heldout rendered input.
// This checks corpus integrity and rule expectations, not embedding quality.
func TestNetfilterCorpus(t *testing.T) {
	base, err := os.ReadFile("testdata/fixtures-v1.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	poolRaw, err := os.ReadFile("testdata/fixtures-v3-pool.jsonl")
	if err != nil || !bytes.HasPrefix(poolRaw, base) {
		t.Fatalf("historical pool prefix changed: %v", err)
	}
	pool, err := LoadItems("testdata/fixtures-v3-pool.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	held, err := LoadItems("testdata/fixtures-v4-netfilter-heldout.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	renders := map[string]bool{}
	for _, it := range pool {
		if ids[it.ID] {
			t.Fatalf("duplicate training id %q", it.ID)
		}
		ids[it.ID] = true
		renders[Render(it)] = true
	}
	labels := map[string]int{}
	for _, it := range pool {
		if it.Source == SourceNetfilter {
			labels[it.Label]++
		}
	}
	for _, label := range []string{"noise", "digest", "decide"} {
		if labels[label] == 0 {
			t.Fatalf("netfilter training label missing: %s", label)
		}
	}
	heldLabels := map[string]int{}
	for _, it := range held {
		if ids[it.ID] {
			t.Fatalf("duplicate heldout id %q", it.ID)
		}
		ids[it.ID] = true
		heldLabels[it.Label]++
		if renders[Render(it)] {
			t.Fatalf("heldout feature leakage: %s", it.ID)
		}
		if it.Source != SourceNetfilter || it.Verdict != "observed" || (it.Kind != "inbound" && it.Kind != "outbound") {
			t.Fatalf("invalid netfilter heldout shape: %+v", it)
		}
		if it.Remote == "internet" && (it.Host == "" || !strings.HasSuffix(it.Host, ".test")) {
			t.Fatalf("synthetic destination missing: %+v", it)
		}
	}
	if len(held) == 0 {
		t.Fatal("empty netfilter heldout")
	}
	for _, label := range []string{"noise", "digest", "decide"} {
		if heldLabels[label] == 0 {
			t.Fatalf("netfilter heldout label missing: %s", label)
		}
	}

	// These seven independently specified risk classes must stay conservative,
	// even with an unavailable embedder or a majority of benign neighbours.
	expected := map[string]string{
		"nfh013": "policy_unsigned_outbound",
		"nfh014": "policy_unsigned_outbound",
		"nfh015": "policy_unusual_port",
		"nfh016": "policy_exposed_service",
		"nfh017": "policy_user_path",
		"nfh018": "policy_non_network_app",
		"nfh019": "policy_raw_ip",
	}
	found := map[string]bool{}
	for _, it := range held {
		d, fired := Rules(it)
		if reason, ok := expected[it.ID]; ok {
			found[it.ID] = true
			if it.Label != "decide" || !fired || d.Label != "decide" || d.Reason != reason {
				t.Fatalf("risk expectation %s: label=%s decision=%+v fired=%t", it.ID, it.Label, d, fired)
			}
		} else if fired {
			t.Fatalf("benign positive control bypasses kNN: %s %+v", it.ID, d)
		}
	}
	for id := range expected {
		if !found[id] {
			t.Fatalf("risk example missing: %s", id)
		}
	}
}
