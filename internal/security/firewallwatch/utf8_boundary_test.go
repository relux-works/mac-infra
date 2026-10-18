package firewallwatch

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// Regression (N1): truncation at the 256-byte sample cap and the 1024-byte
// Sanitize cap never splits a UTF-8 rune, so parse -> save -> reload succeeds at
// both boundaries; an all-ASCII control just over each cap reloads too.
func TestUTF8TruncationSurvivesSaveReload(t *testing.T) {
	for _, tc := range []struct {
		name    string
		message string
		app     string
	}{
		{"sample cap splits é", strings.Repeat("x", 255) + "é tail", "/Applications/A.app"},
		{"sample cap ascii control", strings.Repeat("x", 257), "/Applications/A.app"},
		{"sanitize cap splits é", "unknown shape", "/" + strings.Repeat("x", 1022) + "é/tail"},
		{"sanitize cap ascii control", "unknown shape", "/" + strings.Repeat("x", 1030)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testConfig(t)
			if e := os.Mkdir(c.StateDir, 0700); e != nil && !os.IsExist(e) {
				t.Fatal(e)
			}
			s, e := OpenStore(c)
			if e != nil {
				t.Fatal(e)
			}
			line, _ := json.Marshal(map[string]string{"category": "fw", "eventMessage": tc.message})
			s.State.Parser.Parse(line)
			now := time.Now().UTC()
			s.Observe(Item{Source: "alf", Kind: "unknown", Remote: "unknown", App: tc.app, Signer: "Apple", Verdict: "allow", Count: 1}, now,
				func(Item) Decision { return Decision{Label: "digest", Reason: "test"} })
			for _, v := range s.State.Parser.Samples {
				if !utf8.ValidString(v) || len(v) > 256 {
					t.Fatalf("sample not valid UTF-8 within cap: %d bytes", len(v))
				}
			}
			if e := s.Save(now); e != nil {
				t.Fatalf("save: %v", e)
			}
			if _, e := OpenStore(c); e != nil {
				t.Fatalf("reload refused: %v", e)
			}
		})
	}
}

// Sanitize output is valid UTF-8, within its cap, and idempotent even for invalid input bytes.
func TestSanitizeUTF8Idempotent(t *testing.T) {
	for _, in := range []string{strings.Repeat("é", 600), strings.Repeat("x", 1023) + "€", "bad\xff\xfebytes", strings.Repeat("x", 1023) + "\xff"} {
		out := Sanitize(in)
		if !utf8.ValidString(out) || len(out) > 1024 || Sanitize(out) != out {
			t.Fatalf("Sanitize(%q...) invalid/non-idempotent", in[:min(8, len(in))])
		}
	}
}
