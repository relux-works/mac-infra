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
		"-Wno-deprecated-declarations", "-framework", "Foundation", "-framework", "Security",
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
				Requirement: `identifier "works.relux.test" and anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM" and certificate leaf = H"0123456789012345678901234567890123456789"`,
			}},
		},
		{
			mode: "owner-and-rollback",
			want: []TrustedApplication{
				{
					Path:        "/test/owner",
					Requirement: `identifier "works.relux.test" and anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM" and certificate leaf = H"0123456789012345678901234567890123456789"`,
				},
				{Path: "/usr/bin/security", Requirement: `identifier "com.apple.security" and anchor apple`},
			},
		},
	} {
		run := exec.CommandContext(ctx, fixture, tc.mode)
		output, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("in-memory native fixture %s: %v\n%s", tc.mode, err, output)
		}
		var got Item
		if err := json.Unmarshal(output, &got); err != nil {
			t.Fatalf("decode fixture %s output: %v\n%s", tc.mode, err, output)
		}
		want := []ReleaseACL{{Authorizations: []string{"encrypt"}, Applications: tc.want}}
		if !reflect.DeepEqual(got.WriterACLs, want) {
			t.Fatalf("fixture %s writer ACLs = %#v, want independently specified %#v", tc.mode, got.WriterACLs, want)
		}
	}

	for _, mode := range []string{"mixed", "unsupported", "opaque", "wrong-list"} {
		run := exec.CommandContext(ctx, fixture, mode)
		if output, err := run.CombinedOutput(); err != nil {
			t.Fatalf("in-memory refusal fixture %s: %v\n%s", mode, err, output)
		}
	}
}
