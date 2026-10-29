package toolsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// Claim keeper delta 2: every writer tag is reported and foreign writers fail verify, paired with owner-only and prompt-only controls.
func TestForeignWriters(t *testing.T) {
	for _, auth := range append(append([]string{}, WriterAuthorizations[:]...), "any") {
		t.Run(auth, func(t *testing.T) {
			i := boundItem()
			i.Service = "works.relux.writer-test"
			i.WriterACLs = []ReleaseACL{{Authorizations: []string{auth}, Applications: []TrustedApplication{OwnerApplication(validOwner())}}}
			r := Inspect(i)
			if len(r.Writers) != 1 || r.Writers[0].ForeignWriter || slices.Contains(r.Flags, "foreign_writer") || len(Verify(i, validOwner())) != 0 {
				t.Fatal("owner writer control failed")
			}
			i.WriterACLs[0].Applications = append(i.WriterACLs[0].Applications, TrustedApplication{"/test/foreign", strings.ReplaceAll(strongDR, "works.relux.test", "works.relux.foreign")})
			r = Inspect(i)
			if len(r.Writers) != 1 || !r.Writers[0].ForeignWriter || !slices.Contains(r.Flags, "foreign_writer") || !slices.Contains(Verify(i, validOwner()), "foreign_writer") {
				t.Fatal("foreign writer accepted")
			}
			f := newFake()
			f.items = []Item{i}
			c, out, _ := testCLI(t, f)
			if c.Run(context.Background(), []string{"inventory", "--json"}) != 0 {
				t.Fatal("writer inventory failed")
			}
			var inventory struct {
				Result []InventoryItem `json:"result"`
			}
			if json.Unmarshal(out.Bytes(), &inventory) != nil || len(inventory.Result) != 1 || len(inventory.Result[0].Writers) != 1 || !inventory.Result[0].Writers[0].ForeignWriter {
				t.Fatal("CLI hid foreign writer")
			}
			out.Reset()
			if c.Run(context.Background(), []string{"verify", "--service", i.Service, "--account", i.Account, "--owner", validOwner().Path, "--json"}) != 3 || !strings.Contains(out.String(), "foreign_writer") {
				t.Fatal("CLI accepted foreign writer")
			}
			f.items[0].WriterACLs[0].Applications = []TrustedApplication{OwnerApplication(validOwner())}
			out.Reset()
			if c.Run(context.Background(), []string{"verify", "--service", i.Service, "--account", i.Account, "--owner", validOwner().Path, "--json"}) != 0 {
				t.Fatal("CLI refused owner-only writer")
			}
		})
	}
	for _, kind := range []string{"any-application", "unreadable-contents", "unreadable-requirement", "generic", "ambiguous-owner", "no-owner"} {
		t.Run(kind, func(t *testing.T) {
			i := boundItem()
			i.WriterACLs = []ReleaseACL{{Authorizations: []string{"item_modify"}, Applications: []TrustedApplication{OwnerApplication(validOwner())}}}
			switch kind {
			case "any-application":
				i.WriterACLs[0].AnyApplication = true
			case "unreadable-contents":
				i.WriterACLs[0].ContentsUnverified = true
			case "unreadable-requirement":
				i.WriterACLs[0].Applications[0].Requirement = ""
			case "generic":
				i.WriterACLs[0].Applications[0].Path = "/usr/bin/security"
			case "ambiguous-owner":
				i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, TrustedApplication{"/test/other", strings.ReplaceAll(strongDR, "works.relux.test", "works.relux.other")})
			case "no-owner":
				i.ReleaseACLs = nil
			}
			if !slices.Contains(Inspect(i).Flags, "foreign_writer") || len(Verify(i, validOwner())) == 0 {
				t.Fatal("unestablished writer accepted")
			}
		})
	}
	i := boundItem()
	i.WriterACLs = []ReleaseACL{{Authorizations: []string{"change_acl"}, Applications: []TrustedApplication{}}}
	if len(Inspect(i).Flags) != 0 || len(Verify(i, validOwner())) != 0 {
		t.Fatal("prompt-only control treated as automatic foreign writer")
	}
	i.WriterACLs[0] = ReleaseACL{Authorizations: []string{"sign"}, AnyApplication: true}
	if len(Inspect(i).Writers) != 0 || len(Verify(i, validOwner())) != 0 {
		t.Fatal("non-writer control flagged")
	}
}

// Claim F2: each plaintext authorization is inventoried, removed by bind, and rejected by verify, paired with the clean owner control.
func TestPlaintextAuthorizations(t *testing.T) {
	for _, auth := range []string{"decrypt", "export_clear", "export_wrapped", "any"} {
		t.Run(auth, func(t *testing.T) {
			i := boundItem()
			if len(Verify(i, validOwner())) != 0 {
				t.Fatal("owner control failed")
			}
			i.ReleaseACLs = append(i.ReleaseACLs, ReleaseACL{Authorizations: []string{auth}, Applications: []TrustedApplication{{"/usr/bin/security", `identifier "com.apple.security" and anchor apple`}}})
			if !slices.Contains(Inspect(i).Flags, "generic_reader") || len(Verify(i, validOwner())) == 0 {
				t.Fatal("plaintext release hidden")
			}
			p, e := PlanBind(i, validOwner(), BindOptions{})
			if e != nil {
				t.Fatal(e)
			}
			var auths []string
			for _, acl := range p.After.ReleaseACLs {
				auths = append(auths, acl.Authorizations...)
			}
			if len(Verify(p.After, validOwner())) != 0 || !reflect.DeepEqual(auths, PlaintextAuthorizations[:]) {
				t.Fatal("release grants not replaced")
			}
			i.ReleaseACLs[len(i.ReleaseACLs)-1].AnyApplication = true
			if !slices.Contains(Inspect(i).Flags, "any_application") {
				t.Fatal("unrestricted release unflagged")
			}
		})
	}
	i := boundItem()
	i.ReleaseACLs = append(i.ReleaseACLs, ReleaseACL{Authorizations: []string{"sign"}, AnyApplication: true, Applications: []TrustedApplication{{"/usr/bin/security", ""}}})
	if len(Verify(i, validOwner())) != 0 || len(Inspect(i).Flags) != 0 {
		t.Fatal("non-plaintext control treated as plaintext")
	}
}

// Claim F3: Apple anchoring grants no implicit exception, generic readers stay generic, and both Apple partitions flag and are removed.
func TestClosedApplePolicy(t *testing.T) {
	if len(appleInternalIdentifiers) != 0 {
		t.Fatal("unreviewed Apple-internal identifier")
	}
	for _, path := range []string{"/usr/bin/security", "/usr/bin/osascript", "/bin/sh", "/bin/zsh", "/usr/bin/python3"} {
		a := TrustedApplication{path, `identifier "com.apple.` + filepath.Base(path) + `" and anchor apple`}
		if !IsGenericApplication(a) || AppleInternal(a) {
			t.Fatalf("Apple generic reader accepted: %s", path)
		}
		o := validOwner()
		o.Path = path
		if ValidateOwner(o) == nil {
			t.Fatal("generic reader accepted as primary owner")
		}
	}
	if AppleInternal(TrustedApplication{"/System/Library/fake", `identifier "com.apple.not-approved" and anchor apple`}) {
		t.Fatal("open-ended Apple exception")
	}
	for _, partition := range []string{"apple:", "apple-tool:"} {
		i := boundItem()
		i.Partitions = []string{partition}
		if !slices.Contains(Inspect(i).Flags, "partition_mismatch") {
			t.Fatal("Apple partition hidden")
		}
		p, e := PlanBind(i, validOwner(), BindOptions{})
		if e != nil || slices.Contains(p.After.Partitions, partition) {
			t.Fatal("Apple partition retained")
		}
	}
	if len(Inspect(boundItem()).Flags) != 0 {
		t.Fatal("clean partition control flagged")
	}
}

// Claim F4: every unsafe keep needs an explicit audited decision, while a certificate-pinned hardened keep passes without an override.
func TestKeepOwnerChecks(t *testing.T) {
	for _, kind := range []string{"valid", "generic", "ad-hoc", "cdhash", "identifier", "runtime", "get-task-allow", "allow-dyld-environment-variables", "disable-library-validation", "allow-unsigned-executable-memory"} {
		t.Run(kind, func(t *testing.T) {
			kept := validOwner()
			kept.Path = "/test/extra"
			kept.Requirement = strings.ReplaceAll(strongDR, "works.relux.test", "works.relux.extra")
			switch kind {
			case "generic":
				kept.Path = "/usr/bin/security"
			case "ad-hoc":
				kept.AdHoc = true
			case "cdhash":
				kept.Requirement = `cdhash H"abc"`
			case "identifier":
				kept.Requirement = `identifier "extra"`
			case "runtime":
				kept.HardenedRuntime = false
			default:
				for _, e := range ForbiddenEntitlements {
					if strings.HasSuffix(e, kind) && kind != "valid" {
						kept.Entitlements = []string{e}
					}
				}
			}
			i := boundItem()
			i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, OwnerApplication(kept))
			opts := BindOptions{Keep: []string{kept.Path}, KeepOwners: map[string]Owner{kept.Path: kept}}
			p, e := PlanBind(i, validOwner(), opts)
			if kind == "valid" {
				if e != nil || len(p.KeepOwners) != 1 {
					t.Fatal("safe keep refused", e)
				}
				return
			}
			if e == nil {
				t.Fatal("unsafe keep accepted")
			}
			opts.OwnerDecision = "decision:keeper-F4"
			p, e = PlanBind(i, validOwner(), opts)
			if e != nil || p.OwnerDecision != opts.OwnerDecision || len(p.KeepOwners) != 1 {
				t.Fatalf("explicit decision control failed: %v", e)
			}
		})
	}
}

// Claim F6: unreadable stored trust is unverified and fails inventory/verify/bind closed; a readable pinned owner is the paired control.
func TestUnverifiedStoredRequirement(t *testing.T) {
	i := boundItem()
	if len(Verify(i, validOwner())) != 0 {
		t.Fatal("verified control failed")
	}
	i.ReleaseACLs[0].Applications[0].Requirement = ""
	r := Inspect(i)
	if !r.Applications[0].Unverified || !slices.Contains(r.Flags, "unverified") || len(Verify(i, validOwner())) == 0 {
		t.Fatal("unreadable trust accepted")
	}
	if _, e := PlanBind(i, validOwner(), BindOptions{OwnerDecision: "decision:cannot-override-unverified"}); e == nil {
		t.Fatal("unknown trust override accepted")
	}
}

// Claim decision 75: Team-OU DRs, with/without identifier or quotes, are flagged and refused; leaf/root/anchor pins pass the same policy/CLI controls.
func TestCertificatePinDecision75(t *testing.T) {
	const hash = `H"0123456789012345678901234567890123456789"`
	for _, tc := range []struct {
		name, requirement string
		class             RequirementClass
		accepted          bool
	}{
		{"team-with-id", `identifier "owner" and anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM"`, TeamOUForgeable, false},
		{"team-without-id", `anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM"`, TeamOUForgeable, false},
		{"team-bare-with-id", `identifier owner and anchor apple generic and certificate leaf[subject.OU] = TESTTEAM`, TeamOUForgeable, false},
		{"team-bare-without-id", `anchor apple generic and certificate leaf[subject.OU] = TESTTEAM`, TeamOUForgeable, false},
		{"team-numeric-leaf", `anchor apple generic and certificate 0[subject.OU] = TESTTEAM`, TeamOUForgeable, false},
		{"leaf", `identifier owner and certificate leaf = ` + hash, Anchored, true},
		{"leaf-with-team", `identifier "owner" and anchor apple generic and certificate leaf[subject.OU] = TESTTEAM and certificate leaf = ` + hash, Anchored, true},
		{"root", `identifier owner and certificate root = ` + hash, Anchored, true},
		{"anchor", `identifier owner and anchor = ` + hash, Anchored, true},
		{"unscoped-apple", `identifier "owner" and anchor apple generic`, Anchored, false},
		{"identifier-only", `identifier "owner"`, IdentifierOnly, false},
		{"identifier-only-bare", `identifier owner`, IdentifierOnly, false},
		{"cdhash-only", `cdhash H"aabbcc"`, CDHashOnly, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := validOwner()
			o.Requirement = tc.requirement
			if ClassifyRequirement(o.Requirement) != tc.class || (ValidateOwner(o) == nil) != tc.accepted {
				t.Fatal("owner classification/policy differs")
			}
			i := boundItem()
			i.Service = "works.relux.decision75"
			i.ReleaseACLs[0].Applications = []TrustedApplication{OwnerApplication(o)}
			report := Inspect(i)
			if slices.Contains(report.Flags, "team_ou_forgeable") != (tc.class == TeamOUForgeable) {
				t.Fatal("team trust inventory differs")
			}
			reasons := Verify(i, o)
			if (len(reasons) == 0) != tc.accepted || (tc.class == TeamOUForgeable && !slices.Contains(reasons, string(TeamOUForgeable))) {
				t.Fatal("verification differs", reasons)
			}
			if _, e := PlanBind(i, o, BindOptions{OwnerDecision: "decision:cannot-override-owner"}); (e == nil) != tc.accepted {
				t.Fatal("bind policy differs", e)
			}
			f := newFake()
			f.owner = o
			f.items = []Item{i}
			c, out, _ := testCLI(t, f)
			if c.Run(context.Background(), []string{"inventory", "--json"}) != 0 {
				t.Fatal("inventory failed")
			}
			var inventory struct {
				Result []InventoryItem `json:"result"`
			}
			if json.Unmarshal(out.Bytes(), &inventory) != nil || len(inventory.Result) != 1 || slices.Contains(inventory.Result[0].Flags, "team_ou_forgeable") != (tc.class == TeamOUForgeable) {
				t.Fatal("CLI inventory classification differs")
			}
			want := 3
			if tc.accepted {
				want = 0
			}
			out.Reset()
			if c.Run(context.Background(), []string{"bind", "--dry-run", "--service", i.Service, "--account", i.Account, "--owner", o.Path, "--json"}) != want || f.applies != 0 {
				t.Fatal("CLI bind signing policy differs")
			}
			out.Reset()
			if c.Run(context.Background(), []string{"verify", "--service", i.Service, "--account", i.Account, "--owner", o.Path, "--json"}) != want {
				t.Fatal("CLI verify signing policy differs")
			}
		})
	}
}

// Claim F7: TMUX/STY, including empty-but-set variables, and every password flag are refused before any backend call.
func TestOwnerPresenceAndPasswordRefusals(t *testing.T) {
	for _, key := range []string{"TMUX", "STY"} {
		for _, value := range []string{"", "session"} {
			f := newFake()
			c, _, _ := testCLI(t, f)
			c.StdinTTY = true
			c.StdoutTTY = true
			c.LookupEnv = func(k string) (string, bool) { return value, k == key }
			if c.Run(context.Background(), bindArgs()) != 3 || f.startups != 0 {
				t.Fatal("multiplexer accepted")
			}
		}
	}
	for _, flag := range []string{"--password", "--keychain-password", "--password-file", "--password-stdin", "--cli-password"} {
		f := newFake()
		c, out, _ := testCLI(t, f)
		args := append(bindArgs(), flag, "synthetic-sentinel")
		if c.Run(context.Background(), args) != 2 || f.startups != 0 || strings.Contains(out.String(), "synthetic-sentinel") {
			t.Fatal("password path accepted or echoed")
		}
	}
	f := newFake()
	c, out, _ := testCLI(t, f)
	c.StdinTTY = true
	c.StdoutTTY = true
	if c.Run(context.Background(), bindArgs()) != 0 {
		t.Fatal("direct terminal control failed", out)
	}
	var out2 bytes.Buffer
	if Worker(strings.NewReader(`{"operation":"startup","password":"synthetic-sentinel"}`), &out2) == 0 || out2.Len() != 0 {
		t.Fatal("worker accepted a password path")
	}
}

// Claim F8: default inventory stays within known services; --all requires owner presence and writes full metadata only to a new 0600 local file.
func TestInventoryPrivacyScope(t *testing.T) {
	f := newFake()
	f.items = nil
	for _, s := range []string{"works.relux.test", "a2a.agent", "Claude Code-credentials", "unrelated.private"} {
		i := boundItem()
		i.Service = s
		f.items = append(f.items, i)
	}
	c, out, _ := testCLI(t, f)
	if c.Run(context.Background(), []string{"inventory", "--json"}) != 0 || strings.Contains(out.String(), "unrelated.private") {
		t.Fatal("default inventory leaked")
	}
	for _, s := range []string{"works.relux.test", "a2a.agent", "Claude Code-credentials"} {
		if !strings.Contains(out.String(), s) {
			t.Fatal("known service absent", s)
		}
	}
	out.Reset()
	if c.Run(context.Background(), []string{"inventory", "--service-prefix", "unrelated", "--json"}) != 0 || strings.Contains(out.String(), "unrelated.private") {
		t.Fatal("prefix widened scope")
	}
	path := filepath.Join(t.TempDir(), "full.json")
	out.Reset()
	c.StdinTTY = true
	c.StdoutTTY = true
	if c.Run(context.Background(), []string{"inventory", "--all", "--owner-sitting", "--out", path, "--json"}) != 0 || out.Len() != 0 {
		t.Fatal("full listing on stdout")
	}
	data, e := os.ReadFile(path)
	if e != nil || !bytes.Contains(data, []byte("unrelated.private")) {
		t.Fatal("local full listing absent", e)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal("full listing not private")
	}
	for _, args := range [][]string{{"inventory", "--all", "--json"}, {"inventory", "--all", "--owner-sitting", "--json"}, {"inventory", "--all", "--out", path, "--json"}} {
		f2 := newFake()
		c2, stdout, _ := testCLI(t, f2)
		c2.StdinTTY = true
		c2.StdoutTTY = true
		if c2.Run(context.Background(), args) != 3 || f2.startups != 0 || strings.Contains(stdout.String(), "test label") {
			t.Fatal("full listing gate bypassed")
		}
	}
	before := append([]byte{}, data...)
	if c.Run(context.Background(), []string{"inventory", "--all", "--owner-sitting", "--out", path, "--json"}) != 1 {
		t.Fatal("existing export overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing local file changed")
	}
}

func makeChainedAudit(t *testing.T) (string, AuditHead) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	f, e := OpenAudit(path)
	if e != nil {
		t.Fatal(e)
	}
	p, e := PlanBind(boundItem(), validOwner(), BindOptions{})
	if e != nil {
		t.Fatal(e)
	}
	for _, outcome := range []string{"intent", "applied"} {
		if e = AppendAudit(f, AuditRecord{Time: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC), Actor: "test", Outcome: outcome, Plan: p}); e != nil {
			t.Fatal(e)
		}
	}
	f.Close()
	h, e := VerifyAudit(path, "")
	if e != nil {
		t.Fatal(e)
	}
	return path, h
}

// Claim F9: append preserves prior bytes; verify-audit detects edited, truncated, reordered, rehashed or externally mismatched history.
func TestAuditHashChain(t *testing.T) {
	for _, kind := range []string{"valid", "edit", "crlf", "truncate", "reorder", "rehash", "external-pin"} {
		t.Run(kind, func(t *testing.T) {
			path, head := makeChainedAudit(t)
			data, _ := os.ReadFile(path)
			lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
			if kind == "valid" {
				f, e := OpenAudit(path)
				if e != nil {
					t.Fatal(e)
				}
				if e = AppendAudit(f, AuditRecord{Actor: "test", Outcome: "intent"}); e != nil {
					t.Fatal(e)
				}
				f.Close()
				now, _ := os.ReadFile(path)
				if !bytes.HasPrefix(now, data) {
					t.Fatal("append rewrote history")
				}
				if _, e = VerifyAudit(path, ""); e != nil {
					t.Fatal(e)
				}
				return
			}
			switch kind {
			case "edit":
				data = bytes.Replace(data, []byte(`"actor":"test"`), []byte(`"actor":"changed"`), 1)
			case "crlf":
				data = bytes.ReplaceAll(data, []byte("\n"), []byte("\r\n"))
			case "truncate":
				data = append(lines[0], '\n')
			case "reorder":
				data = append(append(append([]byte{}, lines[1]...), '\n'), append(lines[0], '\n')...)
			case "rehash", "external-pin":
				previous := genesisHash
				var b bytes.Buffer
				var changed AuditHead
				for _, line := range lines {
					var r AuditRecord
					json.Unmarshal(line, &r)
					r.Actor = "changed"
					r.PreviousHash = previous
					r.Hash, _ = recordHash(r)
					previous = r.Hash
					encoded, _ := json.Marshal(r)
					b.Write(encoded)
					b.WriteByte('\n')
					changed = AuditHead{r.Sequence, r.Hash}
				}
				data = b.Bytes()
				if kind == "external-pin" {
					raw, _ := json.Marshal(changed)
					if e := os.WriteFile(path+".head", raw, 0600); e != nil {
						t.Fatal(e)
					}
				}
			}
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
			if _, e := VerifyAudit(path, head.Hash); e == nil {
				t.Fatal("rewrite accepted")
			}
			if kind != "external-pin" {
				if f, e := OpenAudit(path); e == nil {
					f.Close()
					t.Fatal("append accepted broken history")
				}
			}
		})
	}
}

// Claim F9: verify-audit uses only local audit files, reports the chain head, and fails after a rewrite without touching the backend.
func TestVerifyAuditCLI(t *testing.T) {
	path, head := makeChainedAudit(t)
	f := newFake()
	c, out, _ := testCLI(t, f)
	c.AuditPath = path
	if c.Run(context.Background(), []string{"verify-audit", "--json", "--expected-head", head.Hash}) != 0 || f.startups != 0 || !strings.Contains(out.String(), head.Hash) {
		t.Fatal("audit verify control failed")
	}
	data, _ := os.ReadFile(path)
	data = bytes.Replace(data, []byte(`"actor":"test"`), []byte(`"actor":"changed"`), 1)
	os.WriteFile(path, data, 0600)
	out.Reset()
	if c.Run(context.Background(), []string{"verify-audit", "--json"}) != 1 || f.startups != 0 {
		t.Fatal("rewritten audit passed")
	}
}
