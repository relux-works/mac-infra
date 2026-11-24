package toolsecret

import (
	"bytes"
	"context"
	"encoding/json"
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
	securityDR        = `identifier "com.apple.security" and anchor apple`
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
	return []string{
		"verify", "--service", "works.relux.fixture", "--account", "rollback-account",
		"--owner", validOwner().Path, "--rollback-subject", rollbackSubject,
		"--rollback-until", rollbackUntilText, "--json",
	}
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

	args := rollbackVerifyArgs()
	args = append(args[:1], append([]string{"--keychain", "/test/keychain-b"}, args[1:]...)...)
	if code := c.Run(context.Background(), args); code != 3 || !strings.Contains(out.String(), "generic_reader") || !strings.Contains(out.String(), "foreign_writer") {
		t.Fatalf("plan from a different keychain authorized retention: %d %s", code, out.String())
	}

	out.Reset()
	args = rollbackVerifyArgs()
	args = append(args[:1], append([]string{"--keychain", "/test/keychain-a"}, args[1:]...)...)
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
	_, plan := rollbackPlan(t, wildcard, mixed)
	if len(plan.After.WriterACLs) != 2 || plan.After.WriterACLs[0].AnyApplication || !plan.After.WriterACLs[1].AnyApplication {
		t.Fatalf("mixed writer behavior changed unexpectedly: %+v", plan.After.WriterACLs)
	}
	f := newFake()
	f.items = []Item{plan.After}
	c, out, _ := testCLI(t, f)
	appendPlanAudit(t, c.AuditPath, plan, "applied")
	if code := c.Run(context.Background(), rollbackVerifyArgs()); code != 3 || !strings.Contains(out.String(), "foreign_writer") {
		t.Fatalf("encrypt plus item_modify any-application writer passed: %d %s", code, out.String())
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
