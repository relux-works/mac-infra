package toolsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	rollbackSubject   = "/usr/bin/security"
	rollbackDecision  = "decision:d576-rollback"
	rollbackUntilText = "2026-10-30T00:00:00Z"
	securityDR        = rollbackSecurityRequirement
)

func rollbackApplication(path string) TrustedApplication {
	name := filepath.Base(path)
	return TrustedApplication{Path: path, Requirement: `identifier "com.apple.` + name + `" and anchor apple`}
}

func rollbackItem(writerACLs ...ReleaseACL) Item {
	i := boundItem()
	i.Service = "works.relux.fixture"
	i.Account = "rollback-account"
	i.ReleaseACLs[0].Applications = append(i.ReleaseACLs[0].Applications, rollbackApplication(rollbackSubject))
	i.WriterACLs = writerACLs
	return i
}

func modeledWriterFixture() Item {
	legacy := TrustedApplication{Path: "/test/previous-owner", Requirement: `identifier "works.relux.previous" and anchor apple generic`}
	return rollbackItem(
		ReleaseACL{Authorizations: []string{"derive", "mac", "sign"}, Applications: []TrustedApplication{legacy}},
		ReleaseACL{Authorizations: []string{integrityAuthorization}, AnyApplication: true, Applications: []TrustedApplication{}},
		ReleaseACL{Authorizations: []string{"change_acl"}, Applications: []TrustedApplication{}},
		ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true},
	)
}

func planModeledWriterFixture(t *testing.T) (Item, Plan) {
	t.Helper()
	before := modeledWriterFixture()
	keptOwners := map[string]Owner{
		rollbackSubject: {Path: rollbackSubject, Requirement: securityDR, Partition: validOwner().Partition},
	}
	plan, err := PlanBind(before, validOwner(), BindOptions{
		Keep:          []string{rollbackSubject},
		KeepOwners:    keptOwners,
		OwnerDecision: rollbackDecision,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.Keychain = "/test/keychain-a"
	return before, plan
}

func writerACLFor(t *testing.T, acls []ReleaseACL, authorization string) ReleaseACL {
	t.Helper()
	for _, acl := range acls {
		if slices.Contains(acl.Authorizations, authorization) {
			return acl
		}
	}
	t.Fatalf("missing writer authorization %q in %+v", authorization, acls)
	return ReleaseACL{}
}

func removeApplication(acls []ReleaseACL, path string) {
	for i := range acls {
		kept := make([]TrustedApplication, 0, len(acls[i].Applications))
		for _, app := range acls[i].Applications {
			if app.Path != path {
				kept = append(kept, app)
			}
		}
		acls[i].Applications = kept
	}
}

func rollbackPlan(t *testing.T, writerACLs ...ReleaseACL) (Item, Plan) {
	t.Helper()
	before := rollbackItem(writerACLs...)
	keptOwners := map[string]Owner{
		rollbackSubject: {Path: rollbackSubject, Requirement: securityDR, Partition: validOwner().Partition},
	}
	plan, err := PlanBind(before, validOwner(), BindOptions{
		Keep:          []string{rollbackSubject},
		KeepOwners:    keptOwners,
		OwnerDecision: rollbackDecision,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.Keychain = "/test/keychain-a"
	return before, plan
}

func appendPlanAudit(t *testing.T, path string, plan Plan, lastOutcome string) {
	t.Helper()
	f, err := OpenAudit(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, outcome := range []string{"intent", lastOutcome} {
		if err := AppendAudit(f, AuditRecord{
			Time:    time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC),
			Actor:   "test",
			Outcome: outcome,
			Plan:    plan,
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func rollbackVerifyArgs() []string {
	return rollbackVerifyArgsForKeychain("/test/keychain-a")
}

func rollbackVerifyArgsForKeychain(keychain string) []string {
	args := []string{
		"verify", "--service", "works.relux.fixture", "--account", "rollback-account", "--owner", validOwner().Path,
	}
	if keychain != "<missing>" {
		args = append(args, "--keychain", keychain)
	}
	return append(args, "--rollback-subject", rollbackSubject, "--rollback-until", rollbackUntilText, "--json")
}

func TestPlanBindNarrowsAnyApplicationEncrypt(t *testing.T) {
	wildcard := ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true}
	before := rollbackItem(wildcard)
	plan, err := PlanBind(before, validOwner(), BindOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !before.WriterACLs[0].AnyApplication || len(before.WriterACLs[0].Applications) != 0 {
		t.Fatal("plan changed the input item")
	}
	if len(plan.After.WriterACLs) != 1 || plan.After.WriterACLs[0].AnyApplication {
		t.Fatalf("encrypt:any was not narrowed: %+v", plan.After.WriterACLs)
	}
	if !slices.Equal(plan.After.WriterACLs[0].Authorizations, []string{"encrypt"}) ||
		len(plan.After.WriterACLs[0].Applications) != 1 ||
		plan.After.WriterACLs[0].Applications[0] != OwnerApplication(validOwner()) {
		t.Fatalf("default bind must retain only the owner: %+v", plan.After.WriterACLs[0])
	}

	_, rollback := rollbackPlan(t, wildcard)
	want := []TrustedApplication{OwnerApplication(validOwner()), rollbackApplication(rollbackSubject)}
	if len(rollback.After.WriterACLs) != 1 || rollback.After.WriterACLs[0].AnyApplication ||
		!slices.Equal(rollback.After.WriterACLs[0].Applications, want) {
		t.Fatalf("rollback plan must explicitly list owner and exact rollback subject: %+v", rollback.After.WriterACLs)
	}
	if rollback.OwnerDecision != rollbackDecision || !slices.Contains(rollback.Keep, rollbackSubject) {
		t.Fatalf("rollback authority missing from plan: %+v", rollback)
	}
}

// Claim: the exact four-entry fixture narrows Derive/MAC/Sign and encrypt:any to owner plus the approved rollback app, while preserving the special Integrity ACL and the prompt-only ChangeACL ACL.
func TestPlanBindModelsObservedWriterForms(t *testing.T) {
	for _, fixture := range []string{"synthetic-a", "synthetic-b"} {
		t.Run(fixture, func(t *testing.T) {
			before := modeledWriterFixture()
			before.Service = fixture
			snapshot, err := json.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			keptOwners := map[string]Owner{
				rollbackSubject: {Path: rollbackSubject, Requirement: securityDR, Partition: validOwner().Partition},
			}
			plan, err := PlanBind(before, validOwner(), BindOptions{
				Keep:          []string{rollbackSubject},
				KeepOwners:    keptOwners,
				OwnerDecision: rollbackDecision,
			})
			if err != nil {
				t.Fatal(err)
			}
			unchanged, err := json.Marshal(before)
			if err != nil || !bytes.Equal(snapshot, unchanged) {
				t.Fatalf("planning changed the source ACLs: err=%v", err)
			}
			if len(before.WriterACLs) != 4 || len(plan.After.WriterACLs) != 4 {
				t.Fatalf("writer entry count changed: before=%d after=%d", len(before.WriterACLs), len(plan.After.WriterACLs))
			}
			wantApps := []TrustedApplication{OwnerApplication(validOwner()), rollbackApplication(rollbackSubject)}
			secret := writerACLFor(t, plan.After.WriterACLs, "derive")
			if !slices.Equal(secret.Authorizations, []string{"derive", "mac", "sign"}) || secret.AnyApplication || !slices.Equal(secret.Applications, wantApps) {
				t.Fatalf("key-use ACL was not narrowed exactly: %+v", secret)
			}
			encrypt := writerACLFor(t, plan.After.WriterACLs, "encrypt")
			if encrypt.AnyApplication || !slices.Equal(encrypt.Applications, wantApps) {
				t.Fatalf("encrypt:any ACL was not narrowed exactly: %+v", encrypt)
			}
			integrity := writerACLFor(t, plan.After.WriterACLs, integrityAuthorization)
			if !integrityACL(integrity) {
				t.Fatalf("special Integrity ACL changed: %+v", integrity)
			}
			changeACL := writerACLFor(t, plan.After.WriterACLs, "change_acl")
			if changeACL.AnyApplication || len(changeACL.Applications) != 0 {
				t.Fatalf("prompt-only ChangeACL entry changed: %+v", changeACL)
			}

			f := newFake()
			f.items = []Item{before}
			c, out, _ := testCLI(t, f)
			args := []string{
				"bind", "--service", before.Service, "--account", before.Account,
				"--owner", validOwner().Path, "--keep", rollbackSubject,
				"--owner-decision", rollbackDecision, "--keychain", "/test/keychain-a",
				"--dry-run", "--json",
			}
			if code := c.Run(context.Background(), args); code != 0 {
				t.Fatalf("fake dry-run failed: %d %s", code, out.String())
			}
			var preview struct {
				Result Plan `json:"result"`
			}
			if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
				t.Fatalf("decode dry-run plan: %v", err)
			}
			if len(preview.Result.After.WriterACLs) != len(plan.After.WriterACLs) {
				t.Fatalf("dry-run omitted writer entries: got=%d want=%d", len(preview.Result.After.WriterACLs), len(plan.After.WriterACLs))
			}
			for i, expected := range plan.After.WriterACLs {
				if aclSignature(preview.Result.After.WriterACLs[i]) != aclSignature(expected) {
					t.Fatalf("dry-run writer entry %d differs: got=%+v want=%+v", i, preview.Result.After.WriterACLs[i], expected)
				}
			}
		})
	}
}

// Claim: an audited fake-backend plan passes rollback-aware verification with all modeled writer forms, and an unexpected key-use writer remains foreign.
func TestRollbackVerifyModelsSecretUsingWriters(t *testing.T) {
	_, plan := planModeledWriterFixture(t)
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 0 || !strings.Contains(out.String(), "rollback_retained") {
		t.Fatalf("planned ACLs did not pass rollback-aware verification: %d %s", code, out.String())
	}
	if strings.Count(out.String(), "rollback_retained") != 1 || strings.Contains(out.String(), "foreign_writer") || strings.Contains(out.String(), "integrity_acl_unsupported") {
		t.Fatalf("verification result contains an unexpected finding: %s", out.String())
	}

	foreign := plan.After
	foreign.WriterACLs = slices.Clone(foreign.WriterACLs)
	foreign.ReleaseACLs = slices.Clone(foreign.ReleaseACLs)
	for i := range foreign.WriterACLs {
		foreign.WriterACLs[i].Applications = slices.Clone(foreign.WriterACLs[i].Applications)
	}
	for i := range foreign.ReleaseACLs {
		foreign.ReleaseACLs[i].Applications = slices.Clone(foreign.ReleaseACLs[i].Applications)
	}
	removeApplication(foreign.ReleaseACLs, rollbackSubject)
	removeApplication(foreign.WriterACLs, rollbackSubject)
	if reasons := Verify(foreign, validOwner()); len(reasons) != 0 {
		t.Fatalf("strict control without rollback applications should pass before adding a foreign writer: %v", reasons)
	}
	secret := writerACLFor(t, foreign.WriterACLs, "derive")
	for i := range foreign.WriterACLs {
		if slices.Equal(foreign.WriterACLs[i].Authorizations, secret.Authorizations) {
			foreign.WriterACLs[i].Applications = append(foreign.WriterACLs[i].Applications, TrustedApplication{
				Path:        "/test/unapproved-writer",
				Requirement: `identifier "works.relux.unapproved" and anchor apple generic`,
			})
		}
	}
	if !slices.Contains(Verify(foreign, validOwner()), "foreign_writer") {
		t.Fatal("a foreign Derive/MAC/Sign application was not reported as foreign_writer")
	}
}

// Claim: rollback-aware verification fails if the audited rollback reader is dropped, even when the remaining ACLs would pass ordinary strict verification.
func TestRollbackVerifyRejectsDroppedRollbackReader(t *testing.T) {
	_, plan := planModeledWriterFixture(t)
	withoutRollback := plan.After
	withoutRollback.ReleaseACLs = slices.Clone(withoutRollback.ReleaseACLs)
	withoutRollback.WriterACLs = slices.Clone(withoutRollback.WriterACLs)
	removeApplication(withoutRollback.ReleaseACLs, rollbackSubject)
	removeApplication(withoutRollback.WriterACLs, rollbackSubject)
	if reasons := Verify(withoutRollback, validOwner()); len(reasons) != 0 {
		t.Fatalf("ordinary strict control should pass after all rollback grants are removed: %v", reasons)
	}
	f := newFake()
	f.items = []Item{withoutRollback}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || !strings.Contains(out.String(), "rollback_plan_mismatch") || strings.Contains(out.String(), "rollback_retained") {
		t.Fatalf("dropping the rollback reader did not fail the audited rollback check: %d %s", code, out.String())
	}
}

// Claim: unknown writer authorizations and malformed Integrity forms remain refused, paired with the exact supported Integrity control.
func TestPlanBindRefusesUnknownAndMalformedIntegrityWriters(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*Item)
		code string
	}{
		{
			name: "unknown authorization",
			edit: func(item *Item) { item.WriterACLs[0].UnmodeledAuthorizations = []string{"ACLAuthorizationUnknown"} },
			code: "writer_acl_unsupported",
		},
		{
			name: "integrity trusted application",
			edit: func(item *Item) { item.WriterACLs[1].AnyApplication = false },
			code: "integrity_acl_unsupported",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := modeledWriterFixture()
			tc.edit(&item)
			_, err := PlanBind(item, validOwner(), BindOptions{})
			refusal, ok := err.(*Refusal)
			if !ok || refusal.Code != tc.code {
				t.Fatalf("got refusal %v, want %s", err, tc.code)
			}
		})
	}
}

// Claim: team-OU-only owner requirements remain refused with the valid certificate-pinned fixture as the positive control.
func TestPlanBindStillRefusesTeamOUForgeableOwner(t *testing.T) {
	owner := validOwner()
	owner.Requirement = `identifier "works.relux.test" and certificate leaf[subject.OU] = "TESTTEAM"`
	if ClassifyRequirement(owner.Requirement) != TeamOUForgeable {
		t.Fatalf("fixture classification = %s, want %s", ClassifyRequirement(owner.Requirement), TeamOUForgeable)
	}
	if _, err := PlanBind(modeledWriterFixture(), validOwner(), BindOptions{}); err != nil {
		t.Fatalf("certificate-pinned owner control refused: %v", err)
	}
	if _, err := PlanBind(modeledWriterFixture(), owner, BindOptions{}); err == nil {
		t.Fatal("team-OU-only owner was accepted")
	}
}

func TestRollbackSubjectRequiresExactValidatedRequirementAndDecision(t *testing.T) {
	exact := TrustedApplication{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}
	for _, tc := range []struct {
		name       string
		apps       []TrustedApplication
		owner      Owner
		decision   string
		wantAccept bool
	}{
		{name: "exact-current-requirement", apps: []TrustedApplication{exact}, owner: Owner{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}, decision: rollbackDecision, wantAccept: true},
		{name: "path-only-anchor", apps: []TrustedApplication{{Path: rollbackSubject, Requirement: "anchor apple"}}, owner: Owner{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}, decision: rollbackDecision},
		{name: "stale-current-requirement", apps: []TrustedApplication{exact}, owner: Owner{Path: rollbackSubject, Requirement: "anchor apple"}, decision: rollbackDecision},
		{name: "missing-current-validation", apps: []TrustedApplication{exact}, decision: rollbackDecision},
		{name: "wrong-generic-override", apps: []TrustedApplication{exact}, owner: Owner{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}, decision: "decision:other"},
		{name: "missing-decision", apps: []TrustedApplication{exact}, owner: Owner{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}},
		{name: "ambiguous-subject", apps: []TrustedApplication{exact, {Path: rollbackSubject, Requirement: "anchor apple"}}, owner: Owner{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}, decision: rollbackDecision},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := rollbackItem(ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
			before.ReleaseACLs[0].Applications = append(before.ReleaseACLs[0].Applications, tc.apps...)
			owners := map[string]Owner{}
			if tc.owner.Path != "" {
				owners[rollbackSubject] = tc.owner
			}
			_, err := PlanBind(before, validOwner(), BindOptions{Keep: []string{rollbackSubject}, KeepOwners: owners, OwnerDecision: tc.decision})
			if tc.wantAccept && err != nil {
				t.Fatalf("exact validated rollback subject refused: %v", err)
			}
			if !tc.wantAccept && err == nil {
				t.Fatal("unvalidated or generically overridden rollback subject accepted")
			}
		})
	}
}

func rollbackBindArgsForKeychain(keychain string) []string {
	args := []string{
		"bind", "--service", "works.relux.fixture", "--account", "rollback-account",
		"--owner", validOwner().Path, "--keep", rollbackSubject,
		"--owner-decision", rollbackDecision, "--dry-run", "--json",
	}
	if keychain != "<missing>" {
		args = append(args, "--keychain", keychain)
	}
	return args
}

func TestRollbackOperationsRequireExplicitAbsoluteKeychainBeforeQueries(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "bind-missing", args: rollbackBindArgsForKeychain("<missing>")},
		{name: "bind-empty", args: rollbackBindArgsForKeychain("")},
		{name: "bind-relative", args: rollbackBindArgsForKeychain("relative.keychain")},
		{name: "verify-missing", args: rollbackVerifyArgsForKeychain("<missing>")},
		{name: "verify-empty", args: rollbackVerifyArgsForKeychain("")},
		{name: "verify-relative", args: rollbackVerifyArgsForKeychain("relative.keychain")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			c, out, _ := testCLI(t, f)
			if code := c.Run(context.Background(), tc.args); code != 2 || f.startups != 0 || f.inventories != 0 || len(f.ownerCalls) != 0 || f.applies != 0 {
				t.Fatalf("rollback operation queried or applied without explicit absolute keychain: exit=%d output=%s backend=%+v", code, out.String(), f)
			}
		})
	}
}

func TestRollbackBindDryRunAcceptsExplicitAbsoluteKeychain(t *testing.T) {
	wildcard := ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true}
	f := newFake()
	f.items = []Item{rollbackItem(wildcard)}
	c, out, _ := testCLI(t, f)
	if code := c.Run(context.Background(), rollbackBindArgsForKeychain("/test/explicit.keychain")); code != 0 || f.inventories != 1 || f.applies != 0 || !strings.Contains(out.String(), `"keychain":"/test/explicit.keychain"`) {
		t.Fatalf("absolute dry-run was not accepted as a query-only plan: exit=%d output=%s", code, out.String())
	}
}

func TestWorkerRejectsRollbackApplyWithoutAbsoluteKeychainBeforeDispatch(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	originalDispatch := nativeDispatch
	dispatches := 0
	nativeDispatch = func(string) (string, error) {
		dispatches++
		return `{"status":0}`, nil
	}
	t.Cleanup(func() { nativeDispatch = originalDispatch })
	for _, keychain := range []string{"", "relative.keychain"} {
		request, err := json.Marshal(nativeRequest{Operation: "apply", Keychain: keychain, Plan: &plan, AllowUI: true})
		if err != nil {
			t.Fatal(err)
		}
		if code := Worker(strings.NewReader(string(request)), &bytes.Buffer{}); code != 3 || dispatches != 0 {
			t.Fatalf("rollback apply reached native dispatch with keychain %q: exit=%d dispatches=%d", keychain, code, dispatches)
		}
	}
}

func TestRollbackVerificationRequiresCurrentExactDesignatedRequirement(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	for _, tc := range []struct {
		name string
		set  func(*fakeBackend)
	}{
		{name: "changed-current-requirement", set: func(f *fakeBackend) {
			f.owners[rollbackSubject] = Owner{Path: rollbackSubject, Requirement: "anchor apple", Partition: validOwner().Partition}
		}},
		{name: "current-validation-failed", set: func(f *fakeBackend) {
			f.ownerErrors[rollbackSubject] = fmt.Errorf("validation unavailable")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.items = []Item{plan.After}
			tc.set(f)
			c, out, _ := testCLI(t, f)
			appendPlanAudit(t, c.AuditPath, plan, "applied")
			code := c.Run(context.Background(), rollbackVerifyArgs())
			if code == 0 || f.inventories != 0 || !strings.Contains(out.String(), "rollback") {
				t.Fatalf("stale or unvalidated subject authorized rollback: exit=%d output=%s", code, out.String())
			}
		})
	}
}

func TestRollbackVerificationRequiresMatchingAppliedPlan(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")

	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 0 {
		t.Fatalf("active, matching rollback plan refused: %d %s", code, out.String())
	}
	var result struct {
		Result struct {
			Verified bool     `json:"verified"`
			Reasons  []string `json:"reasons"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Result.Verified || !slices.Equal(result.Result.Reasons, []string{"rollback_retained"}) || strings.Count(out.String(), "rollback_retained") != 1 {
		t.Fatalf("rollback subject must be reported exactly once: %s", out.String())
	}
}

func TestRollbackPlanIsBoundToKeychainSelection(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	plan.Keychain = "/test/keychain-a"
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")

	args := rollbackVerifyArgsForKeychain("/test/keychain-b")
	if code := c.Run(context.Background(), args); code != 3 || !strings.Contains(out.String(), "generic_reader") || !strings.Contains(out.String(), "foreign_writer") {
		t.Fatalf("plan from a different keychain authorized retention: %d %s", code, out.String())
	}

	out.Reset()
	args = rollbackVerifyArgsForKeychain("/test/keychain-a")
	if code := c.Run(context.Background(), args); code != 0 || !strings.Contains(out.String(), "rollback_retained") {
		t.Fatalf("matching keychain plan was refused: %d %s", code, out.String())
	}
}

func TestRollbackVerifyWithoutFlagsPreservesStrictBytes(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	args := []string{"verify", "--service", "works.relux.fixture", "--account", "rollback-account", "--owner", validOwner().Path, "--json"}
	if code := c.Run(context.Background(), args); code != 3 {
		t.Fatalf("flags-free verify must keep strict behavior: %d %s", code, out.String())
	}
	want := `{"ok":false,"command":"verify","result":{"verified":false,"reasons":["foreign_writer","generic_reader","unexpected decrypt owner: /usr/bin/security","generic_reader","unexpected decrypt owner: /usr/bin/security","generic_reader","unexpected decrypt owner: /usr/bin/security"]},"error":{"code":"verification_failed","message":"foreign_writer; generic_reader; unexpected decrypt owner: /usr/bin/security; generic_reader; unexpected decrypt owner: /usr/bin/security; generic_reader; unexpected decrypt owner: /usr/bin/security","hint":"mac-tool-secret [--json] inventory [--keychain PATH] [--service-prefix P] [--all --owner-sitting --out FILE] | bind --service S --account A --owner PATH [--keychain PATH] [--dry-run] [--owner-sitting] [--keep PATH]... [--owner-decision REF] | verify --service S --account A --owner PATH [--keychain PATH] | verify-audit [--audit-log FILE] [--expected-head SHA256]"}}` + "\n"
	if !bytes.Equal(out.Bytes(), []byte(want)) {
		t.Fatalf("flags-free output changed:\n got %s\nwant %s", out.Bytes(), want)
	}
}

func TestRollbackWindowExpiresAtBoundary(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	for _, now := range []time.Time{
		time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 30, 0, 0, 1, 0, time.UTC),
	} {
		c.Now = func() time.Time { return now }
		out.Reset()
		if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || strings.Contains(out.String(), `"verified":true`) || !strings.Contains(out.String(), "generic_reader") || !strings.Contains(out.String(), "foreign_writer") {
			t.Fatalf("rollback remained valid at/after expiry %s: %d %s", now, code, out.String())
		}
	}
}

func TestRollbackWithoutExactDecisionDoesNotSuppress(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	for _, decision := range []string{"", "decision:other"} {
		t.Run("decision="+decision, func(t *testing.T) {
			withoutDecision := plan
			withoutDecision.OwnerDecision = decision
			f := newFake()
			f.items = []Item{withoutDecision.After}
			c, out, _ := testCLI(t, f)
			appendPlanAudit(t, c.AuditPath, withoutDecision, "applied")
			if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || !strings.Contains(out.String(), "generic_reader") || !strings.Contains(out.String(), "foreign_writer") {
				t.Fatalf("plan without exact decision suppressed a finding: %d %s", code, out.String())
			}
		})
	}
}

func TestRollbackDoesNotHideOtherGenericReader(t *testing.T) {
	before := rollbackItem(ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	other := rollbackApplication("/bin/sh")
	before.ReleaseACLs[0].Applications = append(before.ReleaseACLs[0].Applications, other)
	keptOwners := map[string]Owner{
		rollbackSubject: {Path: rollbackSubject, Requirement: securityDR, Partition: validOwner().Partition},
		other.Path:      {Path: other.Path, Requirement: other.Requirement, Partition: validOwner().Partition},
	}
	plan, err := PlanBind(before, validOwner(), BindOptions{Keep: []string{rollbackSubject, other.Path}, KeepOwners: keptOwners, OwnerDecision: rollbackDecision})
	if err != nil {
		t.Fatal(err)
	}
	plan.Keychain = "/test/keychain-a"
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || !strings.Contains(out.String(), "generic_reader") || strings.Count(out.String(), "rollback_retained") != 1 {
		t.Fatalf("other generic reader was hidden or rollback not reported once: %d %s", code, out.String())
	}
}

func TestNullAndMixedWritersRemainForeign(t *testing.T) {
	wildcard := ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true}
	if !ForeignWriter(wildcard, validOwner().Requirement) {
		t.Fatal("NULL-list encrypt writer must remain foreign before bind")
	}
	if !slices.Contains(Verify(rollbackItem(wildcard), validOwner()), "foreign_writer") {
		t.Fatal("strict verify accepted NULL-list encrypt")
	}

	mixed := ReleaseACL{Authorizations: []string{"encrypt", "item_modify"}, AnyApplication: true}
	if !ForeignWriter(mixed, validOwner().Requirement) {
		t.Fatal("mixed encrypt plus item_modify remained classified as a foreign writer")
	}
	if _, err := PlanBind(rollbackItem(wildcard, mixed), validOwner(), BindOptions{}); err == nil {
		t.Fatal("mixed encrypt plus item_modify was preserved in a bind plan")
	}
}

func TestPlanBindRefusesUnsupportedAndOpaqueWriterACLsWithoutChangingInput(t *testing.T) {
	wildcard := ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true}
	for _, tc := range []struct {
		name string
		acl  ReleaseACL
	}{
		{name: "unmodeled-authorization", acl: ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true, UnmodeledAuthorizations: []string{"sign"}}},
		{name: "opaque-encrypt-contents", acl: ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true, ContentsUnverified: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := rollbackItem(wildcard, tc.acl)
			snapshot, _ := json.Marshal(before)
			_, err := PlanBind(before, validOwner(), BindOptions{})
			if err == nil {
				t.Fatal("unsupported writer ACL was accepted")
			}
			after, _ := json.Marshal(before)
			if !bytes.Equal(after, snapshot) {
				t.Fatal("refused plan changed its input item")
			}
		})
	}
	ownerACL := ReleaseACL{Authorizations: []string{"change_acl"}, ContentsUnverified: true}
	plan, err := PlanBind(rollbackItem(wildcard, ownerACL), validOwner(), BindOptions{})
	if err != nil || !slices.ContainsFunc(plan.After.WriterACLs, func(acl ReleaseACL) bool { return aclSignature(acl) == aclSignature(ownerACL) }) {
		t.Fatalf("unmodified opaque owner ACL should be preserved while target encrypt ACL is narrowed: plan=%+v err=%v", plan.After.WriterACLs, err)
	}
}

func TestRollbackDoesNotSuppressPreexistingExplicitEncryptWriter(t *testing.T) {
	wildcard := ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true}
	existing := ReleaseACL{Authorizations: []string{"encrypt"}, Applications: []TrustedApplication{
		OwnerApplication(validOwner()), rollbackApplication(rollbackSubject),
	}}
	_, plan := rollbackPlan(t, wildcard, existing)
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || !strings.Contains(out.String(), "foreign_writer") || strings.Count(out.String(), "rollback_retained") != 1 {
		t.Fatalf("rollback exception hid an unrelated explicit encrypt grant: %d %s", code, out.String())
	}
}

func TestRollbackFlagsRequireExactSubjectAndUTC(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "subject-only", args: []string{"--rollback-subject", rollbackSubject}},
		{name: "until-only", args: []string{"--rollback-until", rollbackUntilText}},
		{name: "other-subject", args: []string{"--rollback-subject", "/bin/sh", "--rollback-until", rollbackUntilText}},
		{name: "offset-not-utc", args: []string{"--rollback-subject", rollbackSubject, "--rollback-until", "2026-10-30T03:00:00+03:00"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			c, out, _ := testCLI(t, f)
			args := []string{"verify", "--service", "test", "--account", "account", "--owner", validOwner().Path, "--json"}
			args = append(args, tc.args...)
			if code := c.Run(context.Background(), args); code != 2 || f.startups != 0 || !strings.Contains(out.String(), "usage") {
				t.Fatalf("invalid rollback arguments reached backend: %d %s", code, out.String())
			}
		})
	}
}

func TestLaterFailedAuditOutcomeRevokesRollbackPlan(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	appendPlanAudit(t, c.AuditPath, plan, "failed_or_unknown")
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || !strings.Contains(out.String(), "generic_reader") || !strings.Contains(out.String(), "foreign_writer") {
		t.Fatalf("earlier applied plan survived a later unknown outcome: %d %s", code, out.String())
	}
}

func TestRollbackAuditPathMustBeVerified(t *testing.T) {
	_, plan := rollbackPlan(t, ReleaseACL{Authorizations: []string{"encrypt"}, AnyApplication: true})
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	if err := os.WriteFile(c.AuditPath, []byte(`{"bad":true}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 1 || !strings.Contains(out.String(), "audit") {
		t.Fatalf("unverified rollback audit was accepted: %d %s", code, out.String())
	}
}
