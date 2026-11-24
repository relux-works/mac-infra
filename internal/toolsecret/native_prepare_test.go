//go:build darwin && cgo

package toolsecret

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNativePreparationFixtureContainsNoKeychainItemCalls(t *testing.T) {
	source, err := os.ReadFile("testdata/native_prepare_fixture.m")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"SecItemAdd(", "SecItemCopyMatching(", "SecItemUpdate(", "SecItemDelete(",
		"SecKeychainItemCopyAccess(", "SecKeychainItemSetAccess(", "SecKeychainCreate(",
		"SecKeychainOpen(",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("in-memory native preparation fixture calls forbidden API %s", forbidden)
		}
	}
}

func TestNativePreparationNarrowsOnlyPlannedEncryptACLsInMemory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := filepath.Join(t.TempDir(), "native-prepare-fixture")
	compile := exec.CommandContext(ctx, "/usr/bin/clang",
		"-Wno-deprecated-declarations", "-DTOOLSECRET_TEST_TRACE", "-framework", "Foundation", "-framework", "Security",
		"-o", fixture, "testdata/native_prepare_fixture.m")
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile in-memory native fixture: %v\n%s", err, output)
	}

	for _, tc := range []struct {
		mode string
		want []TrustedApplication
	}{
		{
			mode: "owner-only",
			want: []TrustedApplication{{
				Path:        "/test/owner",
				Requirement: `identifier "works.relux.test" and anchor apple generic and certificate leaf[subject.OU] = TESTTEAM and certificate leaf = H"0123456789012345678901234567890123456789"`,
			}},
		},
		{
			mode: "owner-and-rollback",
			want: []TrustedApplication{
				{
					Path:        "/test/owner",
					Requirement: `identifier "works.relux.test" and anchor apple generic and certificate leaf[subject.OU] = TESTTEAM and certificate leaf = H"0123456789012345678901234567890123456789"`,
				},
				{Path: "/usr/bin/security", Requirement: `identifier "com.apple.security" and anchor apple`},
			},
		},
	} {
		run := exec.CommandContext(ctx, fixture, tc.mode)
		output, err := run.Output()
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				t.Fatalf("in-memory native fixture %s: %v\n%s", tc.mode, err, exit.Stderr)
			}
			t.Fatalf("in-memory native fixture %s: %v", tc.mode, err)
		}
		var got Item
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatalf("decode fixture %s output: %v\n%s", tc.mode, err, output)
		}
		encryptACLs, opaqueOwnerACLs := 0, 0
		for _, acl := range got.WriterACLs {
			switch strings.Join(acl.Authorizations, ",") {
			case "encrypt":
				encryptACLs++
				if acl.AnyApplication || acl.ContentsUnverified || !reflect.DeepEqual(acl.Applications, tc.want) {
					t.Fatalf("fixture %s encrypt ACL = %#v, want independently specified applications %#v", tc.mode, acl, tc.want)
				}
			case "change_acl":
				opaqueOwnerACLs++
				if !acl.ContentsUnverified || acl.AnyApplication || len(acl.Applications) != 0 {
					t.Fatalf("fixture %s did not preserve the unrelated opaque owner ACL: %#v", tc.mode, acl)
				}
			default:
				t.Fatalf("fixture %s produced unexpected writer ACL: %#v", tc.mode, acl)
			}
		}
		if encryptACLs != 1 || opaqueOwnerACLs != 1 {
			t.Fatalf("fixture %s has %d encrypt ACLs and %d opaque owner ACLs, want one each: %#v", tc.mode, encryptACLs, opaqueOwnerACLs, got.WriterACLs)
		}
	}

	for _, mode := range []string{"mixed", "unsupported", "opaque", "wrong-list"} {
		run := exec.CommandContext(ctx, fixture, mode)
		if output, err := run.CombinedOutput(); err != nil {
			t.Fatalf("in-memory refusal fixture %s: %v\n%s", mode, err, output)
		}
	}
}
