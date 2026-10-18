package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/maccore"
)

// Valid CLI verbs send only the fixed target, package and digest; malformed flags/positionals never reach the helper.
func TestVPNCoreCLI(t *testing.T) {
	old := callVPNCore
	t.Cleanup(func() { callVPNCore = old })
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		args   []string
		code   int
		action maccore.Action
	}{
		{[]string{"install", "--package", "/fixture/pkg", "--expect-digest", digest}, 0, maccore.ActionVPNCoreInstall},
		{[]string{"rollback", "--expect-digest", digest}, 0, maccore.ActionVPNCoreRollback},
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
				if tc.action != maccore.ActionVPNCoreStatus && r.VPNCore.ExpectedDigest != digest {
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
	var out, err bytes.Buffer
	if run([]string{"vpn-core", "rollback", "--expect-digest", strings.Repeat("a", 64)}, &out, &err) != 1 || !strings.Contains(err.String(), "restart_failed") || !strings.Contains(out.String(), "/fixture/previous") {
		t.Fatalf("out=%s err=%s", &out, &err)
	}
}
