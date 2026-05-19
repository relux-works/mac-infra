package cleanup

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewPlanIncludesVersionedSchemaPolicyHashAndApplyContract(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)

	if plan.SchemaVersion != PlanSchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", plan.SchemaVersion, PlanSchemaVersion)
	}
	if plan.CategoryPolicyVersion != CategoryPolicyVersion {
		t.Fatalf("categoryPolicyVersion = %q, want %q", plan.CategoryPolicyVersion, CategoryPolicyVersion)
	}
	if !plan.GeneratedAt.Equal(generatedAt) {
		t.Fatalf("generatedAt = %s, want %s", plan.GeneratedAt, generatedAt)
	}
	if plan.StaleAfterSeconds != int64(DefaultPlanStaleAfter/time.Second) {
		t.Fatalf("staleAfterSeconds = %d, want %d", plan.StaleAfterSeconds, int64(DefaultPlanStaleAfter/time.Second))
	}
	if !strings.HasPrefix(plan.PlanHash, PlanHashAlgorithm+":") {
		t.Fatalf("planHash = %q, want %s prefix", plan.PlanHash, PlanHashAlgorithm+":")
	}
	if plan.Root.RealPath == "" || plan.Candidates[0].Identity.RootRealPath == "" {
		t.Fatalf("plan root real paths must be recorded: %#v %#v", plan.Root, plan.Candidates[0].Identity)
	}
	if plan.Apply.DirectCategoryApply != DirectApplyUnsupportedV1 {
		t.Fatalf("direct category apply = %q, want %q", plan.Apply.DirectCategoryApply, DirectApplyUnsupportedV1)
	}
	if !plan.Apply.CleanApplyRequiresPlan || !plan.Apply.Confirmation.Required || !plan.Apply.Revalidation.ReLstatBeforeDelete {
		t.Fatalf("apply contract missing required gates: %#v", plan.Apply)
	}
	for _, input := range []string{"schemaVersion", "categoryPolicyVersion", "generatedAt", "root", "candidates", "apply", "hashInputs"} {
		if !containsString(plan.HashInputs, input) {
			t.Fatalf("hashInputs = %#v, missing %q", plan.HashInputs, input)
		}
	}
	if plan.Totals.CandidateCount != 1 || plan.Totals.SelectedCount != 1 {
		t.Fatalf("totals = %#v, want one selected candidate", plan.Totals)
	}

	raw := map[string]any{}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatalf("marshal plan: %v", err)
	}
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal plan: %v", err)
	}
	for _, key := range []string{"schemaVersion", "categoryPolicyVersion", "generatedAt", "staleAfterSeconds", "root", "candidates", "totals", "apply", "hashInputs", "planHash"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("plan JSON missing %q: %s", key, encoded)
		}
	}
	candidate := raw["candidates"].([]any)[0].(map[string]any)
	identity := candidate["identity"].(map[string]any)
	for _, key := range []string{"path", "realPath", "rootPath", "rootRealPath", "kind", "mode", "logicalBytes", "diskBytes", "modTime", "uid", "gid"} {
		if _, ok := identity[key]; !ok {
			t.Fatalf("candidate identity JSON missing %q: %s", key, encoded)
		}
	}
}

func TestDefaultPolicyCarriesCategoryPolicyVersion(t *testing.T) {
	policy := DefaultPolicy()
	if policy.Version != CategoryPolicyVersion {
		t.Fatalf("policy version = %q, want %q", policy.Version, CategoryPolicyVersion)
	}
}

func TestPlanHashValidationRefusesTampering(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	plan := makeTestPlan(t, root, candidatePath, time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC))

	if err := ValidatePlanHash(plan); err != nil {
		t.Fatalf("ValidatePlanHash(valid) error = %v", err)
	}

	tampered := plan
	tampered.Candidates[0].LogicalBytes++
	if err := ValidatePlanHash(tampered); err == nil {
		t.Fatal("ValidatePlanHash(tampered) succeeded, want error")
	}
	result := ValidatePlanForApply(tampered, plan.GeneratedAt.Add(time.Hour))
	assertRefusal(t, result.Refusals, RefusalPlanHashMismatch)
}

func TestValidatePlanForApplyRefusesStalePlans(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)

	result := ValidatePlanForApply(plan, generatedAt.Add(DefaultPlanStaleAfter).Add(time.Second))
	if result.Allowed() {
		t.Fatal("stale plan was allowed")
	}
	assertRefusal(t, result.Refusals, RefusalPlanStale)
}

func TestValidateCleanApplyInvocationRequiresApplyPlanAndRejectsDirectCategoryApply(t *testing.T) {
	refusals := ValidateCleanApplyInvocation(CleanApplyInvocation{})
	assertRefusal(t, refusals, RefusalApplyFlagMissing)
	assertRefusal(t, refusals, RefusalPlanPathMissing)

	refusals = ValidateCleanApplyInvocation(CleanApplyInvocation{
		Apply:          true,
		PlanPath:       ".temp/cleanup-plan.json",
		DirectCategory: CategoryTargetGenerated,
	})
	if len(refusals) != 1 {
		t.Fatalf("direct category refusals = %#v, want one refusal", refusals)
	}
	assertRefusal(t, refusals, RefusalDirectCategoryApply)

	refusals = ValidateCleanApplyInvocation(CleanApplyInvocation{
		Apply:    true,
		PlanPath: ".temp/cleanup-plan.json",
	})
	if len(refusals) != 0 {
		t.Fatalf("clean --apply --plan refusals = %#v, want none", refusals)
	}
}

func TestRevalidatePlanCandidatesAllowsUnchangedSelectedCandidate(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)

	result := RevalidatePlanCandidates(plan, RevalidationOptions{
		CurrentUID:    uint32(os.Getuid()),
		CurrentUIDSet: true,
		SelectedOnly:  true,
		CheckedAt:     generatedAt.Add(time.Hour),
	})
	if !result.Allowed() {
		t.Fatalf("unchanged candidate refusals = %#v, want allowed", result.Refusals)
	}
	if result.CandidateCount != 1 || result.LogicalBytes == 0 {
		t.Fatalf("preflight totals = %#v, want selected candidate totals", result)
	}
}

func TestRevalidatePlanCandidatesRefusesChangedCandidateBeforeDeletion(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)

	if err := os.WriteFile(candidatePath, []byte("cache data changed after scan"), 0o600); err != nil {
		t.Fatalf("modify candidate: %v", err)
	}
	changedAt := generatedAt.Add(2 * time.Hour)
	if err := os.Chtimes(candidatePath, changedAt, changedAt); err != nil {
		t.Fatalf("chtimes candidate: %v", err)
	}

	result := RevalidatePlanCandidates(plan, RevalidationOptions{
		CurrentUID:    uint32(os.Getuid()),
		CurrentUIDSet: true,
		SelectedOnly:  true,
		CheckedAt:     generatedAt.Add(time.Hour),
	})
	if result.Allowed() {
		t.Fatal("changed candidate was allowed")
	}
	assertRefusal(t, result.Refusals, RefusalCandidateIdentityChanged)
}

func TestRevalidatePlanCandidatesRefusesSymlinkSwap(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)

	replacement := filepath.Join(root, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	if err := os.Remove(candidatePath); err != nil {
		t.Fatalf("remove candidate: %v", err)
	}
	if err := os.Symlink(replacement, candidatePath); err != nil {
		t.Fatalf("symlink swap: %v", err)
	}

	result := RevalidatePlanCandidates(plan, RevalidationOptions{
		CurrentUID:    uint32(os.Getuid()),
		CurrentUIDSet: true,
		SelectedOnly:  true,
		CheckedAt:     generatedAt.Add(time.Hour),
	})
	if result.Allowed() {
		t.Fatal("symlink-swapped candidate was allowed")
	}
	assertRefusal(t, result.Refusals, RefusalCandidateSymlink)
}

func TestRevalidatePlanCandidatesRefusesOutOfRootCandidate(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	outside := filepath.Join(t.TempDir(), "outside-cache")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside candidate: %v", err)
	}
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)
	outsideIdentity, err := SnapshotCandidateIdentity(outside, filepath.Dir(outside))
	if err != nil {
		t.Fatalf("snapshot outside identity: %v", err)
	}
	plan.Candidates[0].Identity = outsideIdentity
	plan.Candidates[0].Identity.RootPath = plan.Root.Path
	plan.Candidates[0].Identity.RootRealPath = plan.Root.RealPath
	plan.Candidates[0].Identity.RootDevice = plan.Root.Device
	plan.Candidates[0].Identity.RootInode = plan.Root.Inode
	plan.Candidates[0].Identity.RootUID = plan.Root.UID
	plan.Candidates[0].Identity.RootGID = plan.Root.GID
	plan.Candidates[0].LogicalBytes = outsideIdentity.LogicalBytes
	plan.Candidates[0].DiskBytes = outsideIdentity.DiskBytes
	plan.Candidates[0].ID = CandidateStableID(plan.Candidates[0])
	plan, err = SealPlan(plan)
	if err != nil {
		t.Fatalf("seal out-of-root plan: %v", err)
	}

	result := RevalidatePlanCandidates(plan, RevalidationOptions{
		CurrentUID:    uint32(os.Getuid()),
		CurrentUIDSet: true,
		SelectedOnly:  true,
		CheckedAt:     generatedAt.Add(time.Hour),
	})
	if result.Allowed() {
		t.Fatal("out-of-root candidate was allowed")
	}
	assertRefusal(t, result.Refusals, RefusalCandidateOutOfRoot)
}

func TestRevalidatePlanCandidatesRefusesOwnershipMismatch(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	generatedAt := time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC)
	plan := makeTestPlan(t, root, candidatePath, generatedAt)
	plan.Candidates[0].Identity.UID = uint32(os.Getuid()) + 1
	var err error
	plan, err = SealPlan(plan)
	if err != nil {
		t.Fatalf("seal ownership-mismatch plan: %v", err)
	}

	result := RevalidatePlanCandidates(plan, RevalidationOptions{
		CurrentUID:    uint32(os.Getuid()),
		CurrentUIDSet: true,
		SelectedOnly:  true,
		CheckedAt:     generatedAt.Add(time.Hour),
	})
	if result.Allowed() {
		t.Fatal("ownership-mismatched candidate was allowed")
	}
	assertRefusal(t, result.Refusals, RefusalCandidateOwnership)
}

func TestWriteAndReadPlanArtifactUsesRestrictivePermissions(t *testing.T) {
	root, candidatePath := makeCleanupFixture(t, "cache data")
	plan := makeTestPlan(t, root, candidatePath, time.Date(2026, 5, 19, 12, 30, 0, 0, time.UTC))
	artifactPath := filepath.Join(t.TempDir(), "nested", "plan.json")

	if err := WritePlanArtifact(artifactPath, plan); err != nil {
		t.Fatalf("write plan artifact: %v", err)
	}
	info, err := os.Stat(artifactPath)
	if err != nil {
		t.Fatalf("stat plan artifact: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("plan artifact mode = %o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(artifactPath))
	if err != nil {
		t.Fatalf("stat plan artifact dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("plan artifact dir mode = %o, want 0700", got)
	}
	readPlan, err := ReadPlanArtifact(artifactPath)
	if err != nil {
		t.Fatalf("read plan artifact: %v", err)
	}
	if readPlan.PlanHash != plan.PlanHash {
		t.Fatalf("read plan hash = %q, want %q", readPlan.PlanHash, plan.PlanHash)
	}
}

func makeCleanupFixture(t *testing.T, contents string) (string, string) {
	t.Helper()

	root := t.TempDir()
	candidatePath := filepath.Join(root, ".temp")
	if err := os.WriteFile(candidatePath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write candidate: %v", err)
	}
	return root, candidatePath
}

func makeTestPlan(t *testing.T, root string, candidatePath string, generatedAt time.Time) Plan {
	t.Helper()

	planRoot, err := SnapshotPlanRoot(root)
	if err != nil {
		t.Fatalf("snapshot root: %v", err)
	}
	candidate, err := NewCandidate(NewCandidateInput{
		Path:            candidatePath,
		RootPath:        root,
		CategoryID:      CategoryTargetGenerated,
		Reason:          "target-local generated fixture",
		Risk:            RiskSafeGenerated,
		DefaultSelected: true,
		Selected:        true,
	})
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	plan, err := NewPlan(NewPlanInput{
		GeneratedAt: generatedAt,
		Source:      PlanSourceTarget,
		Root:        planRoot,
		Categories: []PlanCategory{{
			ID:              CategoryTargetGenerated,
			Risk:            RiskSafeGenerated,
			DefaultSelected: true,
		}},
		Candidates: []Candidate{candidate},
	})
	if err != nil {
		t.Fatalf("new plan: %v", err)
	}
	return plan
}

func assertRefusal(t *testing.T, refusals []Refusal, code RefusalCode) {
	t.Helper()

	for _, refusal := range refusals {
		if refusal.Code == code {
			return
		}
	}
	t.Fatalf("refusals = %#v, missing %s", refusals, code)
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
