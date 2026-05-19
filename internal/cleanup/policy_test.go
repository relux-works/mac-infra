package cleanup

import (
	"slices"
	"strings"
	"testing"
)

func TestDefaultPolicySplitsCategoriesByRiskAndDefaultSelection(t *testing.T) {
	policy := DefaultPolicy()
	categories := categoriesByID(t, policy.Categories)

	for _, id := range []CategoryID{
		CategoryXcodeDerivedData,
		CategoryTargetGenerated,
		CategoryRotatedLogs,
	} {
		category := categories[id]
		if category.Risk != RiskSafeGenerated {
			t.Fatalf("%s risk = %s, want %s", id, category.Risk, RiskSafeGenerated)
		}
		if !category.DefaultSelected {
			t.Fatalf("%s DefaultSelected = false, want true", id)
		}
	}

	for _, category := range policy.Categories {
		if category.DefaultSelected && category.Risk != RiskSafeGenerated {
			t.Fatalf("%s is default-selected with risk %s", category.ID, category.Risk)
		}
		if category.Risk != RiskSafeGenerated && category.DefaultSelected {
			t.Fatalf("%s must not be default-selected", category.ID)
		}
	}
}

func TestReviewOnlyCategoriesExplainWhyTheyAreNotAutoSelected(t *testing.T) {
	categories := categoriesByID(t, DefaultCategories())
	required := []CategoryID{
		CategoryDownloads,
		CategoryLargeFiles,
		CategoryOldFiles,
		CategoryAppCaches,
		CategoryIOSBackups,
		CategoryXcodeArchives,
		CategoryXcodeDeviceSupport,
		CategoryXcodeSimulators,
	}

	for _, id := range required {
		category := categories[id]
		if category.Risk != RiskReviewOnly {
			t.Fatalf("%s risk = %s, want %s", id, category.Risk, RiskReviewOnly)
		}
		if category.DefaultSelected {
			t.Fatalf("%s DefaultSelected = true, want false", id)
		}
		if strings.TrimSpace(category.Reason) == "" {
			t.Fatalf("%s has empty review-only reason", id)
		}
	}
}

func TestDefaultSelectionExcludesUserDataAndRiskyCleanupRoots(t *testing.T) {
	for _, category := range DefaultCategories() {
		if !category.DefaultSelected {
			continue
		}

		for _, root := range category.Roots {
			for _, forbidden := range []string{
				"~/Downloads",
				"~/Library/Caches",
				"MobileSync/Backup",
				"Archives",
				"DeviceSupport",
				"CoreSimulator",
				"/Volumes",
			} {
				if strings.Contains(root.Path, forbidden) {
					t.Fatalf("%s default-selected forbidden root %q", category.ID, root.Path)
				}
			}
		}
	}

	categories := categoriesByID(t, DefaultCategories())
	for _, id := range []CategoryID{
		CategoryDownloads,
		CategoryLargeFiles,
		CategoryOldFiles,
		CategoryAppCaches,
		CategoryIOSBackups,
		CategoryXcodeArchives,
		CategoryXcodeDeviceSupport,
		CategoryXcodeSimulators,
	} {
		if categories[id].DefaultSelected {
			t.Fatalf("%s must never be default-selected", id)
		}
	}
}

func TestTargetGeneratedDataRequiresExplicitTarget(t *testing.T) {
	categories := categoriesByID(t, DefaultCategories())
	category := categories[CategoryTargetGenerated]

	if len(category.Roots) != 1 {
		t.Fatalf("%s roots = %d, want 1", category.ID, len(category.Roots))
	}
	if category.Roots[0].Scope != RootScopeExplicitTarget || !category.Roots[0].RequiresExplicitTarget {
		t.Fatalf("%s root = %#v, want explicit target root", category.ID, category.Roots[0])
	}

	for _, pattern := range []string{
		".temp",
		".build",
		"build",
		"dist",
		".dart_tool",
		"node_modules/.cache",
		".pytest_cache",
		".mypy_cache",
		".ruff_cache",
		"coverage",
		"DerivedData",
	} {
		if !slices.Contains(category.Patterns, pattern) {
			t.Fatalf("%s patterns missing %q", category.ID, pattern)
		}
	}
}

func TestOutOfScopeCategoriesCoverV1NonGoals(t *testing.T) {
	categories := categoriesByID(t, DefaultCategories())
	required := []CategoryID{
		CategoryMalwareScanning,
		CategoryRAMCleaning,
		CategoryForcedPurgeableCleanup,
		CategoryAppUninstallLeftovers,
		CategoryBrowserPrivacyCleanup,
		CategoryAttachmentCleanup,
		CategoryLanguageStripping,
		CategoryBinaryThinning,
	}

	for _, id := range required {
		category := categories[id]
		if category.Risk != RiskOutOfScope {
			t.Fatalf("%s risk = %s, want %s", id, category.Risk, RiskOutOfScope)
		}
		if category.DefaultSelected {
			t.Fatalf("%s DefaultSelected = true, want false", id)
		}
		if strings.TrimSpace(category.Reason) == "" {
			t.Fatalf("%s has empty out-of-scope reason", id)
		}
	}
}

func TestRootSafetyPolicyRejectsDangerousRoots(t *testing.T) {
	safety := DefaultRootSafetyPolicy()
	home := "/Users/alexis"

	for _, path := range []string{
		"/",
		home,
		"/Users",
		"/System",
		"/Library",
		"/Applications",
		"/bin",
		"/sbin",
		"/usr",
		"/private",
		"/var",
		"/Volumes",
	} {
		decision := safety.EvaluateRoot(path, home)
		if decision.Allowed || !decision.Dangerous {
			t.Fatalf("EvaluateRoot(%q) = %#v, want refused dangerous root", path, decision)
		}
		if decision.Reason == "" {
			t.Fatalf("EvaluateRoot(%q) has empty refusal reason", path)
		}
	}
}

func TestRootSafetyPolicyRejectsSystemRootDescendants(t *testing.T) {
	safety := DefaultRootSafetyPolicy()
	home := "/Users/alexis"

	for _, path := range []string{
		"/System/Library",
		"/Library/Caches",
		"/Applications/Example.app",
		"/bin/tool",
		"/sbin/tool",
		"/usr/local",
		"/private/tmp",
		"/var/tmp",
	} {
		decision := safety.EvaluateRoot(path, home)
		if decision.Allowed || !decision.Dangerous {
			t.Fatalf("EvaluateRoot(%q) = %#v, want refused dangerous descendant", path, decision)
		}
	}
}

func TestHomeChildRootIsAllowedSubjectToSafetyChecks(t *testing.T) {
	safety := DefaultRootSafetyPolicy()

	decision := safety.EvaluateRoot("/Users/alexis/project", "/Users/alexis")
	if !decision.Allowed || decision.Dangerous {
		t.Fatalf("home child decision = %#v, want allowed with checks", decision)
	}
	if !decision.RequiresOwnershipCheck || !decision.RequiresSymlinkCheck || !decision.RequiresRealpathContainment {
		t.Fatalf("home child decision = %#v, want ownership, symlink, and containment checks", decision)
	}
}

func TestExternalVolumeRulesRejectRootsButAllowExplicitChildPaths(t *testing.T) {
	safety := DefaultRootSafetyPolicy()

	volumeRoot := safety.EvaluateRoot("/Volumes/ExternalSSD", "/Users/alexis")
	if volumeRoot.Allowed || !volumeRoot.Dangerous {
		t.Fatalf("volume root decision = %#v, want refused", volumeRoot)
	}

	child := safety.EvaluateRoot("/Volumes/ExternalSSD/projects/mac-infra", "/Users/alexis")
	if !child.Allowed || child.Dangerous {
		t.Fatalf("volume child decision = %#v, want allowed with checks", child)
	}
	if !child.ExternalVolumeChild || !child.RequiresExplicitTarget {
		t.Fatalf("volume child decision = %#v, want explicit external child target", child)
	}
	if !child.RequiresOwnershipCheck || !child.RequiresSymlinkCheck || !child.RequiresRealpathContainment {
		t.Fatalf("volume child decision = %#v, want ownership, symlink, and containment checks", child)
	}
}

func TestSafetyPolicyRequiresSymlinkOwnershipAndContainmentChecks(t *testing.T) {
	safety := DefaultRootSafetyPolicy()

	if !safety.RefuseSymlinkRoots {
		t.Fatal("RefuseSymlinkRoots = false, want true")
	}
	if !safety.RefuseSymlinkCandidates {
		t.Fatal("RefuseSymlinkCandidates = false, want true")
	}
	if !safety.RequireUserOwnedRoots {
		t.Fatal("RequireUserOwnedRoots = false, want true")
	}
	if !safety.RequireUserOwnedCandidates {
		t.Fatal("RequireUserOwnedCandidates = false, want true")
	}
	if !safety.RequireRealpathContainment {
		t.Fatal("RequireRealpathContainment = false, want true")
	}
}

func TestCategoryIDsAreUnique(t *testing.T) {
	seen := map[CategoryID]bool{}
	for _, category := range DefaultCategories() {
		if seen[category.ID] {
			t.Fatalf("duplicate category ID %s", category.ID)
		}
		seen[category.ID] = true
	}
}

func categoriesByID(t *testing.T, categories []Category) map[CategoryID]Category {
	t.Helper()

	index := make(map[CategoryID]Category, len(categories))
	for _, category := range categories {
		if category.ID == "" {
			t.Fatal("category has empty ID")
		}
		index[category.ID] = category
	}
	return index
}
