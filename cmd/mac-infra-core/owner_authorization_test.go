package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/maccore"
	"golang.org/x/sys/unix"
)

// Claim: install requires both owner-key flags, rejects hash mismatch/non-P-256/unsafe files before its installer seam, and passes the verified byte snapshot on success.
func TestInstallOwnerKeyPreflight(t *testing.T) {
	old := installService
	t.Cleanup(func() { installService = old })
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "owner.spki")
	if err := os.WriteFile(path, der, 0o600); err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&other.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	otherPath := filepath.Join(dir, "p384.spki")
	if err := os.WriteFile(otherPath, otherDER, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		args  []string
		exit  int
		calls int
	}{
		{"missingSHA", []string{"--owner-key", path}, 2, 0},
		{"missingFile", []string{"--expect-owner-key-sha256", ownerSHA256(der)}, 2, 0},
		{"emptyFile", []string{"--owner-key", "", "--expect-owner-key-sha256", ownerSHA256(der)}, 2, 0},
		{"badSHA", []string{"--owner-key", path, "--expect-owner-key-sha256", "bad"}, 2, 0},
		{"mismatch", []string{"--owner-key", path, "--expect-owner-key-sha256", strings.Repeat("0", 64)}, 1, 0},
		{"nonP256", []string{"--owner-key", otherPath, "--expect-owner-key-sha256", ownerSHA256(otherDER)}, 1, 0},
		{"symlink", []string{"--owner-key", link, "--expect-owner-key-sha256", ownerSHA256(der)}, 1, 0},
		{"valid", []string{"--owner-key", path, "--expect-owner-key-sha256", ownerSHA256(der)}, 1, 1},
		{"noPin", nil, 1, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			installService = func(_ maccore.ServiceConfig, _ string, _, _ int, opts maccore.InstallOptions) error {
				calls++
				if tc.name == "valid" {
					if !bytes.Equal(opts.OwnerKey, der) {
						t.Fatal("installer did not receive verified bytes")
					}
					if err := os.WriteFile(path, []byte("source changed after preflight"), 0o600); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(opts.OwnerKey, der) {
						t.Fatal("snapshot follows source path")
					}
				} else if opts.OwnerKey != nil {
					t.Fatal("unrequested pin mutation")
				}
				return errors.New("fixture stops privileged installer")
			}
			var out, diagnostics bytes.Buffer
			if exit := run(append([]string{"install"}, tc.args...), &out, &diagnostics); exit != tc.exit || calls != tc.calls {
				t.Fatalf("exit=%d calls=%d err=%s", exit, calls, &diagnostics)
			}
			if tc.name == "valid" && !strings.Contains(out.String(), "owner key: "+path+"\nowner key sha256: "+ownerSHA256(der)+"\n") {
				t.Fatalf("missing key announcement: %s", &out)
			}
		})
	}
}

// Claim: authorize writes the returned statement with private mode and prints its hash/short digest; existing files and symlinks are never replaced or followed.
func TestVPNCoreAuthorizeCLI(t *testing.T) {
	old := callVPNCore
	t.Cleanup(func() { callVPNCore = old })
	statement := []byte("statement\n")
	digest := strings.Repeat("a", 64)
	callVPNCore = func(_ maccore.ServiceConfig, r maccore.Request) (maccore.Response, error) {
		if r.Action != maccore.ActionVPNCoreAuthorize || r.VPNCore.AuthorizeAction != "install" || r.VPNCore.ExpectedDigest != digest {
			t.Fatalf("request=%+v", r)
		}
		return maccore.Response{OK: true, Authorization: statement}, nil
	}
	dir := t.TempDir()
	outPath := filepath.Join(dir, "authz")
	var out, diagnostics bytes.Buffer
	args := []string{"vpn-core", "authorize", "--action", "install", "--expect-digest", digest, "--out", outPath}
	if exit := run(args, &out, &diagnostics); exit != 0 {
		t.Fatalf("exit=%d err=%s", exit, &diagnostics)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, statement) || info.Mode().Perm() != 0o600 || !strings.Contains(out.String(), ownerSHA256(statement)) || !strings.Contains(out.String(), "digest: aaaaaaaa\n") {
		t.Fatalf("output=%s file=%q mode=%o", &out, content, info.Mode())
	}
	for _, symlink := range []bool{false, true} {
		if symlink {
			if err := os.Rename(outPath, outPath+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outPath+".real", outPath); err != nil {
				t.Fatal(err)
			}
		}
		out.Reset()
		diagnostics.Reset()
		if exit := run(args, &out, &diagnostics); exit != 1 {
			t.Fatalf("existing output exit=%d", exit)
		}
		got, err := os.ReadFile(outPath)
		if err != nil || !bytes.Equal(got, statement) {
			t.Fatal("existing output changed")
		}
	}
}

// Claim: malformed authorize flags never contact the helper, and required mutation input flags cannot be omitted.
func TestVPNCoreAuthorizationCLIUsage(t *testing.T) {
	old := callVPNCore
	t.Cleanup(func() { callVPNCore = old })
	callVPNCore = func(maccore.ServiceConfig, maccore.Request) (maccore.Response, error) {
		t.Fatal("invalid CLI reached daemon")
		return maccore.Response{}, nil
	}
	d := strings.Repeat("a", 64)
	for _, args := range [][]string{
		{"authorize", "--action", "other", "--expect-digest", d, "--out", "unused"},
		{"authorize", "--action", "install", "--expect-digest", d},
		{"authorize", "--action", "install", "--expect-digest", strings.ToUpper(d), "--out", "unused"},
		{"install", "--package", "/fixture/package", "--expect-digest", d},
		{"rollback", "--expect-digest", d, "--authorization", "unused"},
		{"rollback", "--expect-digest", d, "--signature", "unused"},
	} {
		var out, diagnostics bytes.Buffer
		if exit := run(append([]string{"vpn-core"}, args...), &out, &diagnostics); exit != 2 {
			t.Fatalf("args=%v exit=%d err=%s", args, exit, &diagnostics)
		}
	}
}

// Claim: both CLI input files reject symlinks, directories, FIFOs and sizes above 4 KiB without a daemon call; exact-limit regular files pass unchanged.
func TestVPNCoreAuthorizationCLIInputSafety(t *testing.T) {
	old := callVPNCore
	t.Cleanup(func() { callVPNCore = old })
	for _, input := range []string{"authorization", "signature"} {
		for _, kind := range []string{"symlink", "directory", "fifo", "oversize", "regularLimit"} {
			t.Run(input+"/"+kind, func(t *testing.T) {
				authz, sig := vpnCLIInputs(t)
				path := authz
				if input == "signature" {
					path = sig
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "symlink":
					target := path + ".real"
					if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0o700); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(path, 0o600); err != nil {
						t.Fatal(err)
					}
				default:
					size := 4097
					if kind == "regularLimit" {
						size = 4096
					}
					if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, size), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				calls := 0
				callVPNCore = func(_ maccore.ServiceConfig, r maccore.Request) (maccore.Response, error) {
					calls++
					data := r.VPNCore.Authorization
					if input == "signature" {
						data = r.VPNCore.Signature
					}
					if len(data) != 4096 {
						t.Fatal("limit snapshot changed")
					}
					return maccore.Response{OK: true}, nil
				}
				var out, diagnostics bytes.Buffer
				exit := run([]string{"vpn-core", "rollback", "--expect-digest", strings.Repeat("a", 64), "--authorization", authz, "--signature", sig}, &out, &diagnostics)
				wantExit, wantCalls := 1, 0
				if kind == "regularLimit" {
					wantExit, wantCalls = 0, 1
				}
				if exit != wantExit || calls != wantCalls {
					t.Fatalf("exit=%d calls=%d err=%s", exit, calls, &diagnostics)
				}
			})
		}
	}
}

// Claim: status reports pin presence and fingerprint from service inspection, including absence without an invented digest.
func TestStatusOwnerKey(t *testing.T) {
	old := inspectService
	t.Cleanup(func() { inspectService = old })
	for _, pinned := range []bool{false, true} {
		inspectService = func(maccore.ServiceConfig) (maccore.ServiceStatus, error) {
			return maccore.ServiceStatus{OwnerKeyPinned: pinned, OwnerKeySHA256: strings.Repeat("a", 64)}, nil
		}
		var out, diagnostics bytes.Buffer
		if exit := run([]string{"status"}, &out, &diagnostics); exit != 0 {
			t.Fatal(exit, &diagnostics)
		}
		want := "owner key pinned: false"
		if pinned {
			want = "owner key pinned: true"
		}
		if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "owner key sha256:") != pinned {
			t.Fatalf("status=%s", &out)
		}
	}
}
