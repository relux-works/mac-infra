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

// Sanitize output meets the persisted-text invariants (valid UTF-8, within its
// cap, no control characters) even for invalid input bytes.
func TestSanitizePersistedInvariants(t *testing.T) {
	for _, in := range []string{strings.Repeat("é", 600), strings.Repeat("x", 1023) + "€", "bad\xff\xfebytes", strings.Repeat("x", 1023) + "\xff"} {
		out := Sanitize(in)
		if !persistedText(out, 1024) {
			t.Fatalf("Sanitize(%q...) breaks persisted-text invariants", in[:min(8, len(in))])
		}
	}
}

// Regression (N1b): a cut at the 1024-byte cap can turn a non-address token into
// an address-looking fragment ("fd7a::12345" -> "fd7a::12"). Values stored that
// way, in App and in Signer, must still save and reload; the validator checks the
// persisted-text invariants (valid UTF-8, within cap, no control characters),
// not Sanitize idempotence. IPv4 is not affected: the redaction regex already
// masks a valid dotted prefix such as 10.0.0.123 inside 10.0.0.1234 before the cut.
func TestCapCutAddressFragmentSurvivesSaveReload(t *testing.T) {
	for name, tc := range map[string]struct {
		tail string
		cut  int
	}{"ipv6 cut": {"fd7a::12345", 3}, "ipv6 compressed cut": {"fd7a:115c::abcde", 1}} {
		for _, field := range []string{"app", "signer"} {
			t.Run(name+"/"+field, func(t *testing.T) {
				c := testConfig(t)
				if e := os.Mkdir(c.StateDir, 0700); e != nil && !os.IsExist(e) {
					t.Fatal(e)
				}
				s, e := OpenStore(c)
				if e != nil {
					t.Fatal(e)
				}
				prefix := "/"
				if field == "signer" {
					prefix = "Developer ID Application: /"
				}
				// Exactly tc.cut bytes over the cap, so the cut leaves an address fragment.
				long := prefix + strings.Repeat("x", 1024+tc.cut-len(prefix)-len(tc.tail)-1) + "/" + tc.tail
				if cut := Sanitize(long); Sanitize(cut) == cut {
					t.Fatal("fixture does not reproduce the address-fragment cut")
				}
				it := Item{Source: "alf", Kind: "unknown", Remote: "unknown", App: "/Applications/A.app", Signer: "Apple", Verdict: "allow", Count: 1}
				if field == "app" {
					it.App = long
				} else {
					it.Signer = long
				}
				now := time.Now().UTC()
				s.Observe(it, now, func(Item) Decision { return Decision{Label: "digest", Reason: "test"} })
				if e := s.Save(now); e != nil {
					t.Fatalf("save: %v", e)
				}
				if _, e := OpenStore(c); e != nil {
					t.Fatalf("reload refused: %v", e)
				}
			})
		}
	}
}

// The relaxed validator still refuses persisted text that breaks the invariants:
// a control character, invalid UTF-8 or an over-cap value in a stored event, each
// next to a valid control that reloads.
func TestPersistedTextInvariants(t *testing.T) {
	for _, tc := range []struct {
		name string
		app  string
		ok   bool
	}{
		{"valid", "/Applications/A.app", true},
		{"control char", "/Applications/A\x01.app", false},
		{"invalid utf8", "/Applications/A\xff.app", false},
		{"over cap", "/" + strings.Repeat("x", 1025), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := persistedText(tc.app, 1024); got != tc.ok {
				t.Fatalf("persistedText = %v, want %v", got, tc.ok)
			}
		})
	}
}
