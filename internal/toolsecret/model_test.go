package toolsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const strongDR = `identifier "works.relux.test" and anchor apple generic and certificate leaf[subject.OU] = "TESTTEAM" and certificate leaf = H"0123456789012345678901234567890123456789"`

func validOwner() Owner {
	return Owner{Path: "/test/owner", Requirement: strongDR, HardenedRuntime: true, Partition: "teamid:TESTTEAM", Entitlements: []string{}}
}
func boundItem() Item {
	o := validOwner()
	return Item{Service: "test", Account: "account", Label: "test label", Creator: 123, ReleaseACLs: []ReleaseACL{{Authorizations: []string{"decrypt"}, Applications: []TrustedApplication{{o.Path, o.Requirement}}}}, Partitions: []string{o.Partition}}
}
func weakItem() Item {
	i := boundItem()
	i.ReleaseACLs = []ReleaseACL{{Authorizations: []string{"decrypt"}, Applications: []TrustedApplication{{"/usr/bin/security", `identifier "com.apple.security" and anchor apple`}, {"/test/stale", `cdhash H"abc123"`}, {"/test/old", `identifier "old"`}}}}
	i.Partitions = []string{"apple-tool:", "apple:"}
	return i
}

// Claim: only understood certificate-constrained conjunctions are anchored; stale/unknown/OR-spoof requirements fail closed.
func TestClassification(t *testing.T) {
	for _, tc := range []struct {
		r    string
		want RequirementClass
	}{
		{`cdhash H"aabbcc"`, CDHashOnly}, {`identifier "tool"`, IdentifierOnly}, {strongDR, Anchored},
		{`identifier "tool" and certificate leaf = H"0123456789012345678901234567890123456789"`, Anchored},
		{`identifier "com.apple.security" and anchor apple`, Anchored},
		{"", RequirementUnknown}, {`identifier "anchor apple"`, IdentifierOnly},
		{`identifier "x" or anchor apple`, RequirementUnknown}, {`anchor apple generic or true`, RequirementUnknown},
		{`! anchor apple`, RequirementUnknown}, {`certificate leaf[subject.OU] = "TEAM"`, TeamOUForgeable},
		{`identifier "x and anchor apple"`, IdentifierOnly}, {`anchor apple and nonsense`, RequirementUnknown},
	} {
		t.Run(tc.r, func(t *testing.T) {
			if got := ClassifyRequirement(tc.r); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
	for _, p := range []string{"/usr/bin/security", "/bin/sh", "/bin/zsh", "/usr/bin/python3.14", "/usr/bin/osascript", "/usr/local/bin/node"} {
		if !GenericReader(p) {
			t.Errorf("unflagged reader %s", p)
		}
	}
	if GenericReader("/test/owner") {
		t.Fatal("owner falsely flagged")
	}
	if !IsGenericApplication(TrustedApplication{"/renamed", `identifier "com.apple.security" and anchor apple`}) {
		t.Fatal("renamed security grant hidden")
	}
	if !IsGenericApplication(TrustedApplication{"/renamed", `identifier com.apple.security and anchor apple`}) {
		t.Fatal("bare identifier hid renamed security grant")
	}
}

// Claim: every bind signing refusal is paired with a valid hardened anchored control and never reaches mutation.
func TestOwnerRefusals(t *testing.T) {
	tests := []struct {
		name, code string
		change     func(*Owner)
	}{
		{"adhoc", "ad_hoc_owner", func(o *Owner) { o.AdHoc = true }},
		{"cdhash", "weak_owner_requirement", func(o *Owner) { o.Requirement = `cdhash H"aabb"` }},
		{"identifier", "weak_owner_requirement", func(o *Owner) { o.Requirement = `identifier "owner"` }},
		{"unknown", "weak_owner_requirement", func(o *Owner) { o.Requirement = "" }},
		{"runtime", "missing_hardened_runtime", func(o *Owner) { o.HardenedRuntime = false }},
		{"partition", "unknown_owner_partition", func(o *Owner) { o.Partition = "" }},
		{"bare-get-task-allow", "unsafe_entitlement", func(o *Owner) { o.Entitlements = []string{"get-task-allow"} }},
	}
	for _, e := range ForbiddenEntitlements {
		tests = append(tests, struct {
			name, code string
			change     func(*Owner)
		}{e, "unsafe_entitlement", func(o *Owner) { o.Entitlements = []string{e} }})
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			c, out, _ := testCLI(t, f)
			c.StdinTTY = true
			c.StdoutTTY = true
			if code := c.Run(context.Background(), bindArgs()); code != 0 || f.applies != 1 {
				t.Fatalf("valid control: %d %s", code, out)
			}
			f.applies = 0
			o := validOwner()
			tc.change(&o)
			f.owner = o
			out.Reset()
			if code := c.Run(context.Background(), bindArgs()); code != 3 || !strings.Contains(out.String(), tc.code) || f.applies != 0 {
				t.Fatalf("refusal: %d %s applies %d", code, out, f.applies)
			}
		})
	}
}

// Claim: inventory flags security, weak grants, any-application, rollback and mismatched partitions without a data method.
func TestInventory(t *testing.T) {
	i := weakItem()
	i.Service = "test.rollback"
	i.ReleaseACLs = append(i.ReleaseACLs, ReleaseACL{Authorizations: []string{"any"}, AnyApplication: true})
	i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, TrustedApplication{"/missing", ""}, TrustedApplication{validOwner().Path, strongDR})
	r := Inspect(i)
	for _, f := range []string{"generic_reader", "weak_requirement", "requirement_unknown", "any_application", "rollback_leftover", "partition_mismatch"} {
		if !slices.Contains(r.Flags, f) {
			t.Errorf("missing %s: %v", f, r.Flags)
		}
	}
	if got := Inspect(boundItem()).Flags; len(got) != 0 {
		t.Fatalf("bound control flags: %v", got)
	}
}

// Claim: binding drops every other decrypt grant, keeps Apple-internal entries and explicit exceptions, and preserves attributes.
func TestPlanAndKeep(t *testing.T) {
	i := weakItem()
	apple := TrustedApplication{"/System/Library/test", `identifier "com.apple.internal" and anchor apple`}
	i.ReleaseACLs = append(i.ReleaseACLs, ReleaseACL{Authorizations: []string{"decrypt"}, Applications: []TrustedApplication{apple}})
	p, err := PlanBind(i, validOwner(), BindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.After.ReleaseACLs) != 3 || !reflect.DeepEqual(p.After.ReleaseACLs[0].Applications, []TrustedApplication{{validOwner().Path, strongDR}}) {
		t.Fatalf("bad decrypt plan: %+v", p)
	}
	if p.After.Service != i.Service || p.After.Account != i.Account || p.After.Label != i.Label || p.After.Creator != i.Creator {
		t.Fatal("attributes changed")
	}
	if !reflect.DeepEqual(p.Before, i) {
		t.Fatal("before mutated")
	}
	p, err = PlanBind(i, validOwner(), BindOptions{Keep: []string{"/usr/bin/security", "/test/stale"}, OwnerDecision: "decision:test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.After.ReleaseACLs[0].Applications) != 3 || len(p.Keep) != 2 {
		t.Fatal("explicit exceptions missing")
	}
	if len(Verify(p.After, validOwner())) == 0 {
		t.Fatal("kept generic/weak ACL must fail strict verify")
	}
	if _, err = PlanBind(i, validOwner(), BindOptions{Keep: []string{"/absent"}}); err == nil {
		t.Fatal("missing keep accepted")
	}
	if AppleInternal(TrustedApplication{"/misleading", `anchor apple`}) {
		t.Fatal("unscoped Apple requirement grants generic readers")
	}
}

// Claim: option-B rebuild partitions are compared without replacing stale stored trust with the current DR.
func TestInventoryOwnerPartition(t *testing.T) {
	o := validOwner()
	o.Requirement = `identifier "test" and certificate leaf = H"0123456789012345678901234567890123456789"`
	o.Partition = "cdhash:new"
	i := boundItem()
	i.ReleaseACLs[0].Applications = []TrustedApplication{{o.Path, o.Requirement}}
	i.Partitions = []string{"cdhash:old"}
	if !slices.Contains(InspectForOwner(i, o).Flags, "partition_mismatch") {
		t.Fatal("rebuild partition mismatch hidden")
	}
	i.Partitions = []string{o.Partition}
	if len(InspectForOwner(i, o).Flags) != 0 {
		t.Fatal("valid option-B partition flagged")
	}
	i.ReleaseACLs[0].Applications[0].Requirement = `cdhash H"abc"`
	if InspectForOwner(i, o).Applications[0].Classification != CDHashOnly {
		t.Fatal("current DR replaced stale stored requirement")
	}
}

// Claim: unknown trust-time requirements and malformed partitions prevent bind and verify; an anchored bound item passes.
func TestUnknownAndVerify(t *testing.T) {
	if reasons := Verify(boundItem(), validOwner()); len(reasons) != 0 {
		t.Fatal(reasons)
	}
	for _, kind := range []string{"unknown", "partition", "security", "two-owners", "any-application", "no-owner", "duplicate-owner"} {
		t.Run(kind, func(t *testing.T) {
			i := boundItem()
			switch kind {
			case "unknown":
				i.ReleaseACLs[0].Applications[0].Requirement = ""
			case "partition":
				i.PartitionUnknown = true
			case "security":
				i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, weakItem().ReleaseACLs[0].Applications[0])
			case "two-owners":
				i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, TrustedApplication{"/other", `identifier "other" and anchor apple generic`})
			case "any-application":
				i.ReleaseACLs = append(i.ReleaseACLs, ReleaseACL{Authorizations: []string{"any"}, AnyApplication: true})
			case "no-owner":
				i.ReleaseACLs = nil
			case "duplicate-owner":
				i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, TrustedApplication{"/other", `identifier "other" and anchor apple generic`})
			}
			if len(Verify(i, validOwner())) == 0 {
				t.Fatal("unsafe ACL passed")
			}
			if kind == "unknown" || kind == "partition" {
				if _, err := PlanBind(i, validOwner(), BindOptions{}); err == nil {
					t.Fatal("unsafe bind accepted")
				}
			}
		})
	}
}

type fakeBackend struct {
	items                          []Item
	owner                          Owner
	startups, inventories, applies int
	err, errorApply                error
	plan                           Plan
	ui                             bool
}

func newFake() *fakeBackend                          { return &fakeBackend{items: []Item{weakItem()}, owner: validOwner()} }
func (f *fakeBackend) Startup(context.Context) error { f.startups++; return f.err }
func (f *fakeBackend) Inventory(context.Context, string) ([]Item, error) {
	f.inventories++
	return f.items, nil
}
func (f *fakeBackend) Owner(context.Context, string) (Owner, error) { return f.owner, nil }
func (f *fakeBackend) Apply(_ context.Context, _ string, p Plan, ui bool) error {
	f.applies++
	f.plan = p
	f.ui = ui
	return f.errorApply
}
func testCLI(t *testing.T, f *fakeBackend) (CLI, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errout := new(bytes.Buffer), new(bytes.Buffer)
	return CLI{Backend: f, Stdout: out, Stderr: errout, LookupEnv: func(string) (string, bool) { return "", false }, AuditPath: filepath.Join(t.TempDir(), "audit.jsonl"), Now: func() time.Time { return time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC) }, Actor: "test"}, out, errout
}
func bindArgs() []string {
	return []string{"bind", "--service", "test", "--account", "account", "--owner", "/test/owner", "--owner-sitting", "--json"}
}

// Claim: flag AND both terminal descriptors are necessary; all seven refused combinations cause zero backend calls and zero dialogs.
func TestDialogGate(t *testing.T) {
	for _, flag := range []bool{false, true} {
		for _, in := range []bool{false, true} {
			for _, outTTY := range []bool{false, true} {
				f := newFake()
				c, out, preview := testCLI(t, f)
				c.StdinTTY = in
				c.StdoutTTY = outTTY
				a := bindArgs()
				if !flag {
					a = slices.Delete(a, len(a)-2, len(a)-1)
				}
				code := c.Run(context.Background(), a)
				if flag && in && outTTY {
					if code != 0 || f.applies != 1 || !f.ui || !strings.Contains(preview.String(), strongDR[:10]) {
						t.Fatalf("valid gate: %d %s", code, out)
					}
				} else if code != 3 || f.applies != 0 || f.startups != 0 || preview.Len() != 0 {
					t.Fatalf("bad gate flag=%v in=%v out=%v code=%d calls=%d", flag, in, outTTY, code, f.applies)
				}
			}
		}
	}
}

// Claim: dry-run is metadata-only even without a terminal, and does not create an audit or call Apply.
func TestDryRun(t *testing.T) {
	f := newFake()
	c, out, _ := testCLI(t, f)
	before, _ := json.Marshal(f.items)
	a := append(bindArgs(), "--dry-run")
	if code := c.Run(context.Background(), a); code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	after, _ := json.Marshal(f.items)
	if f.applies != 0 || !bytes.Equal(before, after) {
		t.Fatal("dry-run mutated")
	}
	if _, err := os.Stat(c.AuditPath); !os.IsNotExist(err) {
		t.Fatal("dry-run created audit")
	}
}

// Claim: 0600 durable audit records intent/outcome, old/new grants, partitions, actor and --keep, with no secret/value fields.
func TestAudit(t *testing.T) {
	f := newFake()
	c, out, _ := testCLI(t, f)
	c.StdinTTY = true
	c.StdoutTTY = true
	if code := c.Run(context.Background(), append(bindArgs(), "--keep", "/usr/bin/security", "--owner-decision", "decision:test")); code != 0 {
		t.Fatalf("%d %s", code, out)
	}
	data, err := os.ReadFile(c.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(c.AuditPath)
	if st.Mode().Perm() != 0600 {
		t.Fatal("permissive audit")
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("audit records %d", len(lines))
	}
	for i, line := range lines {
		var r AuditRecord
		if json.Unmarshal(line, &r) != nil {
			t.Fatal("invalid audit")
		}
		if len(r.Keep) != 1 || r.OwnerDecision != "decision:test" || r.Actor != "test" || r.Before.Service != "test" || len(r.After.Partitions) != 1 {
			t.Fatalf("missing audit metadata: %+v", r)
		}
		if i == 0 && r.Outcome != "intent" || i == 1 && r.Outcome != "applied" {
			t.Fatal("bad outcome")
		}
		var doc any
		json.Unmarshal(line, &doc)
		assertNoValue(t, doc)
	}
	f.errorApply = errors.New("refused")
	if c.Run(context.Background(), bindArgs()) != 1 {
		t.Fatal("failed apply claimed success")
	}
	data, _ = os.ReadFile(c.AuditPath)
	if !bytes.Contains(data, []byte("failed_or_unknown")) {
		t.Fatal("missing failure audit")
	}
}
func assertNoValue(t *testing.T, v any) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if k == "value" || k == "data" || k == "password" || k == "secret" {
				t.Fatalf("forbidden audit key %s", k)
			}
			assertNoValue(t, v)
		}
	case []any:
		for _, v := range x {
			assertNoValue(t, v)
		}
	}
}

// Claim: unsafe audit destinations refuse before mutation, paired with a regular owner-only valid log.
func TestAuditRefusals(t *testing.T) {
	for _, kind := range []string{"symlink", "permissions", "directory", "busy"} {
		t.Run(kind, func(t *testing.T) {
			f := newFake()
			c, _, _ := testCLI(t, f)
			c.StdinTTY = true
			c.StdoutTTY = true
			if kind == "directory" {
				os.Mkdir(c.AuditPath, 0700)
			} else {
				os.WriteFile(c.AuditPath, []byte{}, 0600)
			}
			switch kind {
			case "symlink":
				target := c.AuditPath
				c.AuditPath += ".link"
				os.Symlink(target, c.AuditPath)
			case "permissions":
				os.Chmod(c.AuditPath, 0644)
			case "busy":
				file, e := OpenAudit(c.AuditPath)
				if e != nil {
					t.Fatal(e)
				}
				defer file.Close()
			}
			if c.Run(context.Background(), bindArgs()) != 1 || f.applies != 0 {
				t.Fatal("unsafe log accepted")
			}
		})
	}
}

// Claim: every command uses the JSON envelope, bad arguments are usage failures, and startup SPI failure cannot reach a query.
func TestCLI(t *testing.T) {
	for _, args := range [][]string{{"inventory", "--service-prefix", "test", "--json"}, {"bind", "--service", "test", "--account", "account", "--owner", "/test/owner", "--dry-run", "--json"}, {"verify", "--service", "test", "--account", "account", "--owner", "/test/owner", "--json"}, {"help", "--json"}} {
		f := newFake()
		f.items = []Item{boundItem()}
		c, out, _ := testCLI(t, f)
		if code := c.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: %d %s", args, code, out)
		}
		var e envelope
		if json.Unmarshal(out.Bytes(), &e) != nil || !e.OK || e.Result == nil || e.Error != nil {
			t.Fatalf("bad envelope %s", out)
		}
	}
	for _, args := range [][]string{{"--json"}, {"unknown", "--json"}, {"inventory", "--value", "--json"}, {"verify", "--json"}, {"bind", "--owner", "relative", "--json"}, {"inventory", "extra", "--json"}, {"inventory", "--keychain", "relative", "--json"}, {"bind", "--keep", "relative", "--json"}} {
		f := newFake()
		c, out, _ := testCLI(t, f)
		if code := c.Run(context.Background(), args); code != 2 || f.startups != 0 {
			t.Fatalf("usage %v: %d %s", args, code, out)
		}
		var e envelope
		json.Unmarshal(out.Bytes(), &e)
		if e.OK || e.Error == nil || e.Error.Code != "usage" {
			t.Fatal(out)
		}
	}
	f := newFake()
	f.err = refuse("spi_unavailable", "missing SPI")
	c, out, _ := testCLI(t, f)
	if c.Run(context.Background(), []string{"inventory", "--json"}) != 3 || f.inventories != 0 || !strings.Contains(out.String(), "spi_unavailable") {
		t.Fatal(out)
	}
	f = newFake()
	c, out, _ = testCLI(t, f)
	if c.Run(context.Background(), []string{"verify", "--service", "test", "--account", "account", "--owner", "/test/owner", "--json"}) != 3 || !strings.Contains(out.String(), "verification_failed") {
		t.Fatal(out)
	}
	for _, items := range [][]Item{nil, {weakItem(), weakItem()}} {
		f = newFake()
		f.items = items
		c, out, _ = testCLI(t, f)
		if c.Run(context.Background(), append(bindArgs(), "--dry-run")) != 3 || !strings.Contains(out.String(), "item_not_unique") {
			t.Fatal(out)
		}
	}
}

// Claim: the hidden worker cannot enable UI or accept a weak/arbitrary plan through its stdin protocol.
func TestWorkerGate(t *testing.T) {
	for _, r := range []nativeRequest{{Operation: "apply", AllowUI: true}, {Operation: "apply"}, {Operation: "read"}, {Operation: "inventory", AllowUI: true}} {
		b, _ := json.Marshal(r)
		var out bytes.Buffer
		if Worker(bytes.NewReader(b), &out) == 0 || out.Len() != 0 {
			t.Fatal("invalid native request accepted")
		}
	}
}
