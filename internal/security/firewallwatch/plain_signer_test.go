package firewallwatch

import (
	"context"
	"testing"
)

// Plain lookups reject old text authority, even with an old populated hash
// or failure TTL, after either snapshot loading or journal replay. A fresh
// signature result repairs the entry and is reused by the next lookup.
func TestPlainSignerReinspectsLegacyPersistence(t *testing.T) {
	for _, mode := range []string{"snapshot", "journal"} {
		for _, old := range []struct {
			name, source, hash string
			failed             bool
		}{
			{"text", "", "", false},
			{"text-plus-hash", "", hashA, false},
			{"failed-text", "", hashA, true},
		} {
			t.Run(mode+"/"+old.name, func(t *testing.T) {
				s, path, _ := signerFixture(t, "Apple", hashA)
				now := s.now()
				if mode == "journal" {
					if err := s.Save(now); err != nil {
						t.Fatal(err)
					}
				}
				s.runningSigner(context.Background(), path, hashA)
				for k, v := range s.State.Signers {
					v.Value = "Developer ID: PRIVATE_PATH_MARKER"
					v.SignatureSource, v.CDHash, v.Failed = old.source, old.hash, old.failed
					s.State.Signers[k] = v
					s.signerChanged(k)
				}
				var err error
				if mode == "snapshot" {
					err = s.Save(now)
				} else {
					err = s.appendJournal(now, false)
				}
				if err != nil {
					t.Fatal(err)
				}
				r, err := OpenStore(s.Config)
				if err != nil {
					t.Fatal(err)
				}
				runs := 0
				r.inspectSigner = func(context.Context, string) (codeFacts, error) {
					runs++
					return codeFacts{Signer: "ad-hoc", CDHash: hashA}, nil
				}
				for i := 0; i < 2; i++ {
					if got := r.signer(context.Background(), path); got != "ad-hoc" || runs != 1 {
						t.Fatalf("old text authority reused: signer=%q inspections=%d", got, runs)
					}
				}
				for _, v := range r.State.Signers {
					if v.SignatureSource != signatureSourceV1 || v.CDHash != hashA {
						t.Fatalf("fresh signature provenance lost: %+v", v)
					}
				}
			})
		}
	}
}
