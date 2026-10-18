package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/maccore"
)

// Claim: valid mutation verbs send the fixed target, package, digest and authorization/signature bytes; malformed flags/positionals never reach the helper.
func TestVPNCoreCLI(t *testing.T) {
	old := callVPNCore
	t.Cleanup(func() { callVPNCore = old })
	authz, sig := vpnCLIInputs(t)
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		args   []string
		code   int
		action maccore.Action
	}{
		{[]string{"install", "--package", "/fixture/pkg", "--expect-digest", digest, "--authorization", authz, "--signature", sig}, 0, maccore.ActionVPNCoreInstall},
		{[]string{"rollback", "--expect-digest", digest, "--authorization", authz, "--signature", sig}, 0, maccore.ActionVPNCoreRollback},
		{[]string{"status"}, 0, maccore.ActionVPNCoreStatus},
		{nil, 2, ""}, {[]string{"other"}, 2, ""}, {[]string{"install", "--package", "/fixture/pkg"}, 2, ""},
		{[]string{"install", "--package", "relative", "--expect-digest", digest}, 2, ""},
		{[]string{"install", "stray", "--expect-digest", digest}, 2, ""},
		{[]string{"rollback", "--expect-digest", strings.ToUpper(digest)}, 2, ""},
		{[]string{"rollback", "--expect-digest", ""}, 2, ""},
		{[]string{"rollback", "--package", "/fixture/pkg", "--expect-digest", digest}, 2, ""},
		{[]string{"status", "--expect-digest", digest}, 2, ""},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			calls := 0
			callVPNCore = func(cfg maccore.ServiceConfig, r maccore.Request) (maccore.Response, error) {
				calls++
				if cfg != maccore.DefaultServiceConfig() || r.Action != tc.action || r.VPNCore.Target != "vpn-core" {
					t.Fatalf("request=%+v", r)
				}
				if tc.action != maccore.ActionVPNCoreStatus && (r.VPNCore.ExpectedDigest != digest || string(r.VPNCore.Authorization) != "statement" || string(r.VPNCore.Signature) != "signature") {
					t.Fatal("unpinned request")
				}
				return maccore.Response{OK: true, VPNCore: &maccore.VPNCoreStatus{State: "installed"}}, nil
			}
			var out, err bytes.Buffer
			if got := run(append([]string{"vpn-core"}, tc.args...), &out, &err); got != tc.code {
				t.Fatalf("code=%d err=%s", got, &err)
			}
			if (calls == 1) != (tc.action != "") {
				t.Fatalf("calls=%d", calls)
			}
		})
	}
}

// Helper refusal codes and recovery details survive CLI failure output.
func TestVPNCoreCLIRefusal(t *testing.T) {
	old := callVPNCore
	t.Cleanup(func() { callVPNCore = old })
	callVPNCore = func(maccore.ServiceConfig, maccore.Request) (maccore.Response, error) {
		return maccore.Response{ErrorCode: "restart_failed", VPNCore: &maccore.VPNCoreStatus{State: "restart_failed", RecoveryPath: "/fixture/previous"}}, errors.New("restart failed")
	}
	authz, sig := vpnCLIInputs(t)
	var out, err bytes.Buffer
	if run([]string{"vpn-core", "rollback", "--expect-digest", strings.Repeat("a", 64), "--authorization", authz, "--signature", sig}, &out, &err) != 1 || !strings.Contains(err.String(), "restart_failed") || !strings.Contains(out.String(), "/fixture/previous") {
		t.Fatalf("out=%s err=%s", &out, &err)
	}
}

// Claim: the hidden CLI streams only the three fixture files in fixed framed order and emits a bounded refusal on invalid arguments, without installing or executing them.
func TestVPNCoreSourceCLI(t *testing.T) {
	// Keep source fixtures in the checkout even when TMPDIR was not set.
	if err := os.MkdirAll(".temp", 0o700); err != nil {
		t.Fatal(err)
	}
	pkg, err := os.MkdirTemp(".temp", "vpn-core-source-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(pkg) })
	pkg, err = filepath.Abs(pkg)
	if err != nil {
		t.Fatal(err)
	}
	pkg, err = filepath.EvalSymlinks(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(pkg, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []string{"never execute binary", "never execute tool", "manifest bytes"}
	for i, path := range []string{"vpn-core", "bin/sing-box", "manifest.json"} {
		if err := os.WriteFile(filepath.Join(pkg, path), []byte(contents[i]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var out, diagnostics bytes.Buffer
	if code := run([]string{"_vpn-core-source", pkg}, &out, &diagnostics); code != 0 || diagnostics.Len() != 0 {
		t.Fatalf("worker exit=%d stderr=%s", code, &diagnostics)
	}
	for _, want := range contents {
		var size uint64
		if err := binary.Read(&out, binary.BigEndian, &size); err != nil || size != uint64(len(want)) {
			t.Fatalf("frame length=%d err=%v", size, err)
		}
		payload := make([]byte, size)
		if _, err := io.ReadFull(&out, payload); err != nil || string(payload) != want {
			t.Fatalf("payload=%s err=%v", payload, err)
		}
	}
	if out.Len() != 0 {
		t.Fatal("trailing source bytes")
	}
	for _, args := range [][]string{{"_vpn-core-source"}, {"_vpn-core-source", pkg, "extra"}, {"_vpn-core-source", "relative"}} {
		out.Reset()
		diagnostics.Reset()
		if code := run(args, &out, &diagnostics); code != 1 || out.Len() != 0 || diagnostics.Len() > 1024 {
			t.Fatalf("invalid source exit=%d stderr=%s", code, &diagnostics)
		}
		var refusal struct {
			Code string `json:"code"`
		}
		if json.Unmarshal(diagnostics.Bytes(), &refusal) != nil || refusal.Code != "invalid_package_path" {
			t.Fatalf("invalid refusal=%s", &diagnostics)
		}
	}
}

func vpnCLIInputs(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	authz, sig := filepath.Join(dir, "authorization"), filepath.Join(dir, "signature")
	if err := os.WriteFile(authz, []byte("statement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sig, []byte("signature"), 0o600); err != nil {
		t.Fatal(err)
	}
	return authz, sig
}
