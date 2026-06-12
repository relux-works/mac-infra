package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/cleanup"
)

func TestRunTargetWritesDefaultPlanJSONAndTable(t *testing.T) {
	workspace := localCLITempDir(t)
	t.Chdir(workspace)
	target := filepath.Join(workspace, "repo")
	mustMkdirAll(t, filepath.Join(target, ".temp"))
	mustWriteFile(t, filepath.Join(target, ".temp", "cache.bin"), "generated")

	var stdout, stderr bytes.Buffer
	code := run([]string{"target", "--json", "--", target}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"json: .temp/mac-cleanup/target-plan.json", "category", "target-generated-data", "safe_generated", "yes", "totals: candidates=1 selected=1"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}

	jsonPath := filepath.Join(workspace, ".temp", "mac-cleanup", "target-plan.json")
	info, err := os.Stat(jsonPath)
	if err != nil {
		t.Fatalf("stat plan json: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("plan json mode = %o, want 0600", got)
	}
	dirInfo, err := os.Stat(filepath.Dir(jsonPath))
	if err != nil {
		t.Fatalf("stat plan dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("plan dir mode = %o, want 0700", got)
	}

	plan := readPlan(t, jsonPath)
	if plan.SchemaVersion != cleanup.PlanSchemaVersion || plan.CategoryPolicyVersion != cleanup.CategoryPolicyVersion {
		t.Fatalf("plan versions = schema %d policy %q", plan.SchemaVersion, plan.CategoryPolicyVersion)
	}
	if plan.Source != cleanup.PlanSourceTarget || plan.PlanHash == "" {
		t.Fatalf("plan source/hash = %s %q", plan.Source, plan.PlanHash)
	}
}

func TestRunTargetRefusesDangerousRootAndDoesNotWriteJSON(t *testing.T) {
	workspace := localCLITempDir(t)
	jsonPath := filepath.Join(workspace, "plan.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"target", "--json", jsonPath, "/"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run succeeded, stdout = %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "refusing cleanup root") {
		t.Fatalf("stderr missing refusal: %s", stderr.String())
	}
	if _, err := os.Stat(jsonPath); !os.IsNotExist(err) {
		t.Fatalf("plan json exists or stat errored: %v", err)
	}
}

func TestRunXcodeMarksArchiveReviewOnly(t *testing.T) {
	home := localCLITempDir(t)
	t.Setenv("HOME", home)
	derived := filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData", "App-abc")
	archive := filepath.Join(home, "Library", "Developer", "Xcode", "Archives", "2026-05-19", "App.xcarchive")
	mustMkdirAll(t, derived)
	mustWriteFile(t, filepath.Join(derived, "index"), "index")
	mustMkdirAll(t, archive)
	mustWriteFile(t, filepath.Join(archive, "Info.plist"), "archive")
	jsonPath := filepath.Join(localCLITempDir(t), "xcode-plan.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{"xcode", "--json", jsonPath}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"xcode-derived-data", "safe_generated", "xcode-archives", "review_only"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}

	plan := readPlan(t, jsonPath)
	byCategory := map[cleanup.CategoryID][]cleanup.Candidate{}
	for _, candidate := range plan.Candidates {
		byCategory[candidate.CategoryID] = append(byCategory[candidate.CategoryID], candidate)
	}
	if got := byCategory[cleanup.CategoryXcodeDerivedData]; len(got) != 1 || !got[0].Selected {
		t.Fatalf("derived candidates = %#v, want one selected candidate", got)
	}
	if got := byCategory[cleanup.CategoryXcodeArchives]; len(got) != 1 || got[0].Selected || got[0].Risk != cleanup.RiskReviewOnly {
		t.Fatalf("archive candidates = %#v, want one unselected review-only candidate", got)
	}
}

func TestRunHasNoCleanDeletionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"clean", "--apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want usage error", code)
	}
	if !strings.Contains(stderr.String(), "unknown command \"clean\"") {
		t.Fatalf("stderr missing unknown command: %s", stderr.String())
	}
}

func TestRunXcodeRuntimesDryRunDoesNotDelete(t *testing.T) {
	workspace := localCLITempDir(t)
	fakeXcrun, deleteLog := writeFakeXcrun(t, workspace)

	var stdout, stderr bytes.Buffer
	code := run([]string{"xcode-runtimes", "--xcrun", fakeXcrun}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"xcode-simulator-runtimes", "iOS", "13.5", "dry-run", "pass --delete"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}
	if _, err := os.Stat(deleteLog); !os.IsNotExist(err) {
		t.Fatalf("delete log exists after dry-run or stat errored: %v", err)
	}
}

func TestRunXcodeRuntimesDeleteCallsSimctlRuntimeDelete(t *testing.T) {
	workspace := localCLITempDir(t)
	fakeXcrun, deleteLog := writeFakeXcrun(t, workspace)

	var stdout, stderr bytes.Buffer
	code := run([]string{"xcode-runtimes", "--delete", "--xcrun", fakeXcrun}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "deleted: iOS 13.5") {
		t.Fatalf("stdout missing delete confirmation: %s", stdout.String())
	}
	data, err := os.ReadFile(deleteLog)
	if err != nil {
		t.Fatalf("read delete log: %v", err)
	}
	if !strings.Contains(string(data), "simctl runtime delete C20712BB-6F3A-4658-9C37-114C434C8CC5") {
		t.Fatalf("delete log = %s", string(data))
	}
}

func TestRunPermissionsPrintsFullDiskAccessGuide(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"permissions"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"Full Disk Access", "Terminal", "not implemented"} {
		if !strings.Contains(out, want) {
			t.Fatalf("stdout missing %q: %s", want, out)
		}
	}
}

func TestRunPermissionsOpenReturnsNotImplemented(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"permissions", "--open"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run code = %d, want 1; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	errOut := stderr.String()
	for _, want := range []string{"not implemented", "Terminal", "too risky"} {
		if !strings.Contains(errOut, want) {
			t.Fatalf("stderr missing %q: %s", want, errOut)
		}
	}
}

func readPlan(t *testing.T, path string) cleanup.Plan {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var plan cleanup.Plan
	if err := json.Unmarshal(data, &plan); err != nil {
		t.Fatal(err)
	}
	return plan
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func localCLITempDir(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp(".", ".cleanup-cli-test-*")
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(abs); err != nil {
			t.Errorf("cleanup temp dir %s: %v", abs, err)
		}
	})
	return abs
}

func writeFakeXcrun(t *testing.T, workspace string) (string, string) {
	t.Helper()
	deleteLog := filepath.Join(workspace, "delete.log")
	scriptPath := filepath.Join(workspace, "xcrun")
	script := `#!/bin/sh
case "$*" in
  "simctl runtime list --json")
    cat <<'JSON'
{
  "C20712BB-6F3A-4658-9C37-114C434C8CC5" : {
    "build" : "17F61",
    "deletable" : true,
    "identifier" : "C20712BB-6F3A-4658-9C37-114C434C8CC5",
    "kind" : "Legacy Download",
    "path" : "/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 13.5.simruntime",
    "platformIdentifier" : "com.apple.platform.iphonesimulator",
    "runtimeIdentifier" : "com.apple.CoreSimulator.SimRuntime.iOS-13-5",
    "sizeBytes" : 6568505344,
    "state" : "Ready",
    "version" : "13.5"
  },
  "63DFA8B0-4C1D-41FC-B7AB-9F3C93C47234" : {
    "build" : "23E244",
    "deletable" : true,
    "identifier" : "63DFA8B0-4C1D-41FC-B7AB-9F3C93C47234",
    "kind" : "Patchable Cryptex Disk Image",
    "path" : "/System/Library/AssetsV2/current/Restore/current.dmg",
    "platformIdentifier" : "com.apple.platform.iphonesimulator",
    "runtimeIdentifier" : "com.apple.CoreSimulator.SimRuntime.iOS-26-4",
    "sizeBytes" : 8485747282,
    "state" : "Ready",
    "version" : "26.4"
  }
}
JSON
    ;;
  "simctl list runtimes")
    cat <<'TEXT'
== Runtimes ==
iOS 13.5 (13.5 - 17F61) - com.apple.CoreSimulator.SimRuntime.iOS-13-5 (unavailable, The iOS 13.5 simulator runtime is not supported on this host.)
iOS 26.4 (26.4 - 23E244) - com.apple.CoreSimulator.SimRuntime.iOS-26-4
TEXT
    ;;
  "simctl runtime delete C20712BB-6F3A-4658-9C37-114C434C8CC5")
    echo "$*" >> "` + deleteLog + `"
    ;;
  *)
    echo "unexpected args: $*" >&2
    exit 99
    ;;
esac
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return scriptPath, deleteLog
}
