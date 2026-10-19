package firewallwatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	threshold := .5
	dir := t.TempDir()
	return Config{Schema: "mac-infra.firewall-watch/v1", StateDir: filepath.Join(dir, "state"), MaxEntries: 20, RetentionDays: 7, NettopInterval: "5s", DenySpikeCount: 3, DenySpikeWindow: "1m", K: 1, NoveltySimilarity: &threshold, ClassifierTimeout: "1s", LlamaServer: "/not/a/real/llama-server", Model: filepath.Join(dir, "model"), ModelSHA256: strings.Repeat("0", 64), LabelledPool: filepath.Join(dir, "pool.jsonl"), Port: 41235}
}

// Valid explicit configuration is admitted; each missing/unknown/unsafe value
// is independently rejected, including omission of a valid zero threshold.
func TestConfig(t *testing.T) {
	c := testConfig(t)
	raw, _ := json.Marshal(c)
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	path := filepath.Join(t.TempDir(), "config.json")
	write := func(v any, perm os.FileMode) {
		t.Helper()
		b, _ := json.Marshal(v)
		if e := os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
		_ = os.Chmod(path, perm)
	}
	write(c, 0600)
	if _, e := LoadConfig(path); e != nil {
		t.Fatal(e)
	}
	for field := range fields {
		t.Run("missing_"+field, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range fields {
				if k != field {
					m[k] = v
				}
			}
			write(m, 0600)
			if _, e := LoadConfig(path); e == nil {
				t.Fatal("missing field accepted")
			}
		})
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		perm   os.FileMode
	}{
		{"unknown", func(m map[string]any) { m["oops"] = true }, 0600},
		{"null", func(m map[string]any) { m["novelty_similarity"] = nil }, 0600},
		{"bad_perms", func(map[string]any) {}, 0620},
		{"non_port", func(m map[string]any) { m["port"] = "0.0.0.0:1234" }, 0600},
		{"out_of_range", func(m map[string]any) { m["port"] = 65536 }, 0600},
		{"relative_path", func(m map[string]any) { m["state_dir"] = "relative" }, 0600},
		{"zero_interval", func(m map[string]any) { m["nettop_interval"] = "0s" }, 0600},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]any{}
			for k, v := range fields {
				m[k] = v
			}
			tc.mutate(m)
			write(m, tc.perm)
			if _, e := LoadConfig(path); e == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

// Backend authority is exactly numeric IPv4 loopback, with no URL escape hatches.
func TestBackendURL(t *testing.T) {
	for _, s := range []string{"https://127.0.0.1:3", "http://localhost:3", "http://0.0.0.0:3", "http://127.0.0.1:0", "http://127.0.0.1:65536", "http://127.0.0.1:3/path", "http://127.0.0.1:3?x=1", "http://user@127.0.0.1:3", "http://127.0.0.1:3#frag", "http://[::1]:3"} {
		if ValidateBackend(s) == nil {
			t.Errorf("accepted %s", s)
		}
	}
	if e := ValidateBackend("http://127.0.0.1:12345"); e != nil {
		t.Fatal(e)
	}
}
