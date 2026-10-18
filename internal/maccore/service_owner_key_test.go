//go:build darwin && cgo

package maccore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ownerKeyDERFixture(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	mustVPN(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	mustVPN(t, err)
	return der
}

// Claim: the fake privileged installer publishes the supplied SPKI snapshot as 0444 with root ownership commands, rotates it, and preserves its bytes/mode/inode when no pin was requested.
func TestInstallOwnerKeySnapshot(t *testing.T) {
	f := newInstallFixture(t)
	cfg := DefaultServiceConfig()
	pin := ownerKeyDERFixture(t)
	mustVPN(t, installReviewedSnapshotWithOwnerKey([]byte("helper"), pin, cfg, 501, 20, f.ops))
	for i := 0; i < 2; i++ {
		got := readVPN(t, f.path(cfg.OwnerKeyPath))
		info, err := os.Stat(f.path(cfg.OwnerKeyPath))
		mustVPN(t, err)
		if !bytes.Equal(got, pin) || info.Mode().Perm() != 0o444 {
			t.Fatal("pin snapshot or mode changed")
		}
		owned := false
		for _, call := range f.calls {
			if strings.Contains(call, "/usr/sbin/chown 0:0 ") && strings.HasSuffix(call, "/owner-presence.spki") {
				owned = true
			}
		}
		if !owned {
			t.Fatal("pin had no root ownership command")
		}
		f.calls = nil
		mustVPN(t, installReviewedSnapshot([]byte("helper update"), cfg, 501, 20, f.ops))
		after, err := os.Stat(f.path(cfg.OwnerKeyPath))
		mustVPN(t, err)
		if !os.SameFile(info, after) || !bytes.Equal(readVPN(t, f.path(cfg.OwnerKeyPath)), pin) || after.Mode() != info.Mode() {
			t.Fatal("unrequested pin changed")
		}
		for _, call := range f.calls {
			if strings.Contains(call, cfg.OwnerKeyPath) {
				t.Fatal("no-pin install touched pin:", call)
			}
		}
		pin = ownerKeyDERFixture(t)
		mustVPN(t, installReviewedSnapshotWithOwnerKey([]byte("helper"), pin, cfg, 501, 20, f.ops))
	}
}

// Claim: each injected failure (pin staging, staged-pin publication, activation) is reached and reported as itself, with activation otherwise succeeding; it restores the prior pin and helper/plist bytes and inodes, or remove the incomplete first pin; malformed snapshots fail before fake commands.
func TestInstallOwnerKeyFailures(t *testing.T) {
	for _, failure := range []string{"stage", "publish", "activate", "firstPin"} {
		t.Run(failure, func(t *testing.T) {
			f := newInstallFixture(t)
			cfg := DefaultServiceConfig()
			oldKey := ownerKeyDERFixture(t)
			if failure != "firstPin" {
				mustVPN(t, installReviewedSnapshotWithOwnerKey([]byte("old"), oldKey, cfg, 501, 20, f.ops))
			} else {
				mustVPN(t, installReviewedSnapshot([]byte("old"), cfg, 501, 20, f.ops))
			}
			previous := map[string][]byte{}
			identities := map[string]os.FileInfo{}
			for _, p := range []string{defaultServiceBinaryPath, cfg.PlistPath, cfg.OwnerKeyPath} {
				data, err := os.ReadFile(f.path(p))
				if os.IsNotExist(err) {
					continue
				}
				mustVPN(t, err)
				previous[p] = data
				identities[p], err = os.Stat(f.path(p))
				mustVPN(t, err)
			}
			ops := f.ops
			original := ops.command
			reached := false
			ops.command = func(input []byte, name string, args ...string) ([]byte, error) {
				if failure == "stage" && name == "/bin/sh" && strings.HasSuffix(args[len(args)-1], "/owner-presence.spki") {
					reached = true
					return nil, fmt.Errorf("injected pin staging failure")
				}
				// The staged pin moving onto the pin path, not the old pin
				// moving to its backup or back from it.
				if failure == "publish" && name == "/bin/mv" && len(args) == 3 && args[2] == cfg.OwnerKeyPath && args[1] != cfg.OwnerKeyPath && filepath.Base(args[1]) == "owner-presence.spki" {
					reached = true
					return nil, fmt.Errorf("injected pin publication failure")
				}
				return original(input, name, args...)
			}
			want := map[string]string{"stage": "injected pin staging failure", "publish": "injected pin publication failure", "activate": "injected activation failure", "firstPin": "injected activation failure"}[failure]
			activate := func() error { return nil }
			if failure == "activate" || failure == "firstPin" {
				activate = func() error { reached = true; return fmt.Errorf("injected activation failure") }
			}
			err := installReviewedSnapshotWithOwnerKey([]byte("new"), ownerKeyDERFixture(t), cfg, 501, 20, ops, activate)
			if err == nil || !strings.Contains(err.Error(), want) || !reached {
				t.Fatalf("error=%v reached=%v, want %q", err, reached, want)
			}
			for p, want := range previous {
				after, err := os.Stat(f.path(p))
				mustVPN(t, err)
				if !bytes.Equal(readVPN(t, f.path(p)), want) || !os.SameFile(identities[p], after) {
					t.Fatalf("prior file changed: %s", p)
				}
			}
			if failure == "firstPin" {
				if _, err := os.Lstat(f.path(cfg.OwnerKeyPath)); !os.IsNotExist(err) {
					t.Fatal("incomplete first pin retained")
				}
			}
		})
	}
	f := newInstallFixture(t)
	if err := installReviewedSnapshotWithOwnerKey([]byte("helper"), []byte("bad"), DefaultServiceConfig(), 501, 20, f.ops); err == nil || len(f.calls) != 0 {
		t.Fatal("invalid SPKI reached privileged seam")
	}
}
