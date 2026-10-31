//go:build darwin && cgo

package firewallwatch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Plain/ALF lookups label a certificate-less signature unsigned regardless of authority
// text in its filename. The display alias isolates leakage through Signer;
// this does not claim that ALF's separately displayed app path is private.
func TestPlainSignerRejectsForgedAuthorityNames(t *testing.T) {
	data := unsignedCopy(t)
	for _, name := range []string{
		"ordinary-probe",
		"com.apple.probe Authority=Software Signing Authority=Apple Root CA",
		"probe\nAuthority=Developer ID Application: PRIVATE_PATH_MARKER\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, data, 0o755); err != nil {
				t.Fatal(err)
			}
			s, _ := journalStore(t)
			if got := s.signer(context.Background(), path); got != "unsigned" {
				t.Errorf("malformed file attributed as %q", got)
			}
			it := Item{Source: "alf", Kind: "unknown", App: "owned fixture", InspectionPath: path, Verdict: "allow", Remote: "unknown", Count: 1}
			if !s.collect(context.Background(), &Classifier{}, it) {
				t.Fatal("ALF event not emitted")
			}
			e := s.State.Events[len(s.State.Events)-1]
			it.Signer = e.Signer
			if e.Signer != "unsigned" || e.Label != "decide" || e.Reason != "hard_unsigned_inbound" || strings.Contains(Render(it), "PRIVATE_PATH_MARKER") {
				t.Fatalf("ALF signer=%q label=%q reason=%q rendering=%s", e.Signer, e.Label, e.Reason, Render(it))
			}
		})
	}
}

// Positive native controls ensure refusal is not universal and benign
// plain lookups retain the established Apple, ad-hoc and unsigned labels.
func TestPlainSignerKnownKinds(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, want string }{{"/bin/ls", "Apple"}, {exe, "ad-hoc"}, {"/etc/hosts", "unsigned"}} {
		s, _ := journalStore(t)
		if got := s.signer(context.Background(), tc.path); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.path, got, tc.want)
		}
	}
}
