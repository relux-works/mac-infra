//go:build darwin && cgo

package toolsecret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == WorkerArgument {
		os.Exit(Worker(os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}

func bounded(t *testing.T, timeout time.Duration, name string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed (deadline=%v): %v\n%s", filepath.Base(name), ctx.Err(), err, out)
	}
	return out
}

type keychainFixture struct{ path, password, helper, id1, id2, probe string }

func (f keychainFixture) call(t *testing.T, exe, op string, extra map[string]any) nativeResponse {
	t.Helper()
	req := map[string]any{"operation": op, "keychain": f.path, "password": f.password}
	for k, v := range extra {
		req[k] = v
	}
	body, _ := json.Marshal(req)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe)
	cmd.Stdin = bytes.NewReader(body)
	var trace bytes.Buffer
	cmd.Stderr = &trace
	cmd.WaitDelay = time.Second
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("fixture %s failed (deadline=%v): %v; %s", op, ctx.Err(), err, &trace)
	}
	var r nativeResponse
	if json.Unmarshal(out, &r) != nil {
		t.Fatal("invalid fixture metadata response")
	}
	if r.Status != 0 {
		r.Message += "; " + trace.String()
	}
	return r
}
func searchList(t *testing.T) []byte {
	t.Helper()
	return bounded(t, 10*time.Second, "/usr/bin/security", "list-keychains", "-d", "user")
}
func searchPaths(t *testing.T, data []byte) []string {
	t.Helper()
	var p []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		s, err := strconv.Unquote(strings.TrimSpace(line))
		if err != nil {
			t.Fatal("cannot parse keychain search list")
		}
		p = append(p, s)
	}
	return p
}
func requireStatus(t *testing.T, r nativeResponse) {
	t.Helper()
	if r.Status != 0 {
		t.Fatalf("fixture status %d: %s", r.Status, r.Message)
	}
}

func newKeychainFixture(t *testing.T) keychainFixture {
	t.Helper()
	dir := t.TempDir()
	var pw [32]byte
	if _, err := rand.Read(pw[:]); err != nil {
		t.Fatal(err)
	}
	f := keychainFixture{path: filepath.Join(dir, "throwaway.keychain-db"), password: hex.EncodeToString(pw[:]), helper: filepath.Join(dir, "adhoc"), id1: filepath.Join(dir, "identifier-v1"), id2: filepath.Join(dir, "identifier-v2"), probe: filepath.Join(dir, "probe")}
	for _, entry := range []struct {
		out, variant string
		identifier   bool
	}{{f.helper, "adhoc", false}, {f.id1, "v1", true}, {f.id2, "v2", true}} {
		bounded(t, 60*time.Second, "/usr/bin/clang", "-DTOOLSECRET_TEST_TRACE", "-Wno-deprecated-declarations", "-framework", "Foundation", "-framework", "Security", "-DVARIANT=\""+entry.variant+"\"", "-o", entry.out, "testdata/fixture.m", "native_darwin.m")
		args := []string{"--force", "--sign", "-", "--options", "runtime"}
		if entry.identifier {
			args = append(args, "--identifier", "works.relux.toolsecret.fixture", "--requirements", `=designated => identifier "works.relux.toolsecret.fixture"`)
		}
		bounded(t, 10*time.Second, "/usr/bin/codesign", append(args, entry.out)...)
	}
	bounded(t, 60*time.Second, "go", "build", "-o", f.probe, "../../cmd/mac-tool-secret-probe")
	before := searchList(t)
	original := searchPaths(t, before)
	// Register restoration BEFORE creation (SecKeychainCreate changes this list).
	t.Cleanup(func() {
		bounded(t, 10*time.Second, "/usr/bin/security", append([]string{"list-keychains", "-d", "user", "-s"}, original...)...)
		if after := searchList(t); !bytes.Equal(before, after) {
			t.Error("user keychain search list was not restored")
		}
	})
	t.Cleanup(func() {
		r := f.call(t, f.helper, "delete", nil)
		if r.Status != 0 && r.Status != -25300 {
			t.Errorf("delete disposable keychain status %d", r.Status)
		}
	})
	requireStatus(t, f.call(t, f.helper, "create", nil))
	// Restore immediately too, so fixture lifetime does not expose it to other queries.
	bounded(t, 10*time.Second, "/usr/bin/security", append([]string{"list-keychains", "-d", "user", "-s"}, original...)...)
	return f
}

// Claim: opt-in native inventory is prompt-free on foreign temp items, reads stored cdhash/identifier requirements, and pins both SPI symbols at startup.
func TestKeychainInventoryAndProbe(t *testing.T) {
	if os.Getenv("MAC_TOOL_SECRET_KEYCHAIN_TESTS") != "1" {
		t.Skip("set MAC_TOOL_SECRET_KEYCHAIN_TESTS=1; disposable keychains only")
	}
	// Claim decision 75: actual macOS requirement serialization preserves a rejected Team-OU DR and accepted leaf/root/anchor pins.
	t.Run("requirement-pin-round-trip", func(t *testing.T) {
		const hash = `H"0123456789012345678901234567890123456789"`
		for _, tc := range []struct {
			requirement string
			class       RequirementClass
		}{
			{`anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM"`, TeamOUForgeable},
			{`identifier "owner" and anchor apple generic and certificate leaf[subject.OU] = TESTTEAM`, TeamOUForgeable},
			{`certificate leaf = ` + hash, Anchored},
			{`certificate root = ` + hash, Anchored},
			{`anchor = ` + hash, Anchored},
		} {
			canonical := strings.TrimSpace(string(bounded(t, 10*time.Second, "/usr/bin/csreq", "-r", "="+tc.requirement, "-t")))
			if ClassifyRequirement(canonical) != tc.class || CertificatePinned(canonical) != (tc.class == Anchored) {
				t.Fatalf("native requirement serialization differs: %q", canonical)
			}
		}
	})
	f := newKeychainFixture(t)
	n := Native{}
	if err := n.Startup(context.Background()); err != nil {
		t.Fatalf("SPI startup regression: %v", err)
	}
	for _, tc := range []struct{ service, creator, trusted string }{{"test.security", f.helper, "/usr/bin/security"}, {"test.adhoc", f.helper, ""}, {"test.identifier", f.id1, ""}} {
		requireStatus(t, f.call(t, tc.creator, "add", map[string]any{"service": tc.service, "account": "test", "trusted": tc.trusted}))
	}
	for _, auth := range []string{"export_clear", "export_wrapped", "any"} {
		requireStatus(t, f.call(t, f.helper, "add", map[string]any{"service": "test.release." + auth, "account": "test", "trusted": "/usr/bin/security", "authorization": auth}))
	}
	for _, auth := range WriterAuthorizations {
		for _, trusted := range []string{f.id1, "/usr/bin/security"} {
			kind := "owner"
			if trusted == "/usr/bin/security" {
				kind = "foreign"
			}
			requireStatus(t, f.call(t, f.id1, "add", map[string]any{"service": "test.writer." + auth + "." + kind, "account": "test", "trusted": trusted, "authorization": auth}))
		}
	}
	requireStatus(t, f.call(t, f.helper, "add", map[string]any{"service": "test.probe-allowed", "account": "test", "trusted": f.probe}))
	// Regression witness: replace the original ad-hoc creator path with an
	// identifier-signed rebuild. Inventory must still see the OLD cdhash trust.
	replacement, e := os.ReadFile(f.id2)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(f.helper+".replacement", replacement, 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(f.helper+".replacement", f.helper); e != nil {
		t.Fatal(e)
	}
	current, e := n.Owner(context.Background(), f.helper)
	if e != nil {
		t.Fatal(e)
	}
	if ClassifyRequirement(current.Requirement) != IdentifierOnly {
		t.Fatal("stale-path control did not change designated requirement")
	}
	items, err := n.Inventory(context.Background(), f.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 7+2*len(WriterAuthorizations) {
		t.Fatalf("inventory got %d items", len(items))
	}
	for _, item := range items {
		r := Inspect(item)
		var classes []RequirementClass
		for _, a := range r.Applications {
			classes = append(classes, a.Classification)
		}
		switch item.Service {
		case "test.security":
			if !slices.Contains(r.Flags, "generic_reader") {
				t.Fatalf("security not flagged: %+v", r)
			}
		case "test.adhoc":
			if !slices.Contains(classes, CDHashOnly) || !slices.Contains(r.Flags, "weak_requirement") {
				t.Fatalf("stale cdhash misclassified: %+v", r)
			}
		case "test.identifier":
			if !slices.Contains(classes, IdentifierOnly) || !slices.Contains(r.Flags, "weak_requirement") {
				t.Fatalf("identifier misclassified: %+v", r)
			}
		}
		if strings.HasPrefix(item.Service, "test.release.") {
			auth := strings.TrimPrefix(item.Service, "test.release.")
			if !slices.Contains(r.Flags, "generic_reader") || len(item.ReleaseACLs) != 1 || !slices.Contains(item.ReleaseACLs[0].Authorizations, auth) {
				t.Fatalf("plaintext authorization missing: %s", auth)
			}
		}
	}
	// Positive owner checks inspect only status. Rebuilt same-DR creator works;
	// this deliberately weak experiment identity must still be refused by bind.
	for _, exe := range []string{f.id1, f.id2} {
		requireStatus(t, f.call(t, exe, "read", map[string]any{"service": "test.identifier", "account": "test"}))
	}
	owner, err := n.Owner(context.Background(), f.id1)
	if err != nil {
		t.Fatal(err)
	}
	if !owner.AdHoc || !owner.HardenedRuntime || ClassifyRequirement(owner.Requirement) != IdentifierOnly || ValidateOwner(owner) == nil {
		t.Fatalf("weak native owner passed policy: %+v", owner)
	}
	// Claim keeper delta 2: real writer tags and stored applications survive metadata reading; foreign grants differ from same-identity controls.
	t.Run("writer-acls", func(t *testing.T) {
		for _, item := range items {
			if !strings.HasPrefix(item.Service, "test.writer.") {
				continue
			}
			parts := strings.Split(strings.TrimPrefix(item.Service, "test.writer."), ".")
			auth, foreign := parts[0], parts[1] == "foreign"
			matched := false
			for _, acl := range item.WriterACLs {
				if !slices.Contains(acl.Authorizations, auth) || len(acl.Applications) != 1 {
					continue
				}
				wantPath := f.id1
				if foreign {
					wantPath = "/usr/bin/security"
				}
				if acl.Applications[0].Path != wantPath {
					continue
				}
				matched = true
				if ForeignWriter(acl, owner.Requirement) != foreign {
					t.Fatalf("writer control differs: %s: %+v", item.Service, acl)
				}
			}
			if !matched {
				t.Fatalf("native writer grant absent: %s: %+v", item.Service, item.WriterACLs)
			}
			if len(Inspect(item).Writers) == 0 {
				t.Fatal("writer inventory report absent")
			}
		}
	})
	for _, service := range []string{"test.adhoc", "test.identifier"} {
		out := bounded(t, 15*time.Second, f.probe, "--keychain", f.path, "--service", service, "--account", "test")
		if string(out) != "refused\n" {
			t.Fatalf("non-owner probe: %q", out)
		}
	}
	// No test attempts SecKeychainItemSetAccess (change_acl): on macOS 26.5.1 it
	// raises a SecurityAgent dialog on the owner's screen even after
	// SecKeychainSetUserInteractionAllowed(false), and the dialog can outlive the
	// client and block securityd host-wide (incident 2026-10-29 11:30Z). bind
	// therefore runs only at an attended --owner-sitting and is not exercised here.
	// Claim F5: allowed, missing and locked synthetic items all fail the real probe; refused is the paired passing control above.
	t.Run("probe-three-outcomes", func(t *testing.T) {
		check := func(service, want string) {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, f.probe, "--keychain", f.path, "--service", service, "--account", "test")
			var out bytes.Buffer
			cmd.Stdout = &out
			err := cmd.Run()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || out.String() != want+"\n" {
				t.Fatalf("probe outcome %s exit=%v output=%q", service, err, out.String())
			}
		}
		check("test.probe-allowed", "allowed")
		check("test.absent", "inconclusive")
		requireStatus(t, f.call(t, f.helper, "lock", nil))
		check("test.identifier", "inconclusive")
		requireStatus(t, f.call(t, f.id1, "read", map[string]any{"service": "test.identifier", "account": "test"}))
	})
	// Claim: full anchored bind/rebuild acceptance needs an admitted certificate identity.
	t.Run("anchored-bind-verify-rebuilt-owner", func(t *testing.T) {
		t.Skip("no admitted certificate signing identity; production bind correctly refuses these experimental ad-hoc owners")
	})
	// Host-side env/argv and DYLD checks need a real hardened anchored owner.
	t.Run("anchored-owner-env-argv-dyld", func(t *testing.T) {
		t.Skip("no admitted certificate signing identity or trust change; sysadmin owner-sitting lane required")
	})
}
