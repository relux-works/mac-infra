package simcleanup

import (
	"testing"
	"time"
)

const runtimeListJSONFixture = `{
  "C20712BB-6F3A-4658-9C37-114C434C8CC5" : {
    "build" : "17F61",
    "deletable" : true,
    "identifier" : "C20712BB-6F3A-4658-9C37-114C434C8CC5",
    "kind" : "Legacy Download",
    "path" : "/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 13.5.simruntime",
    "platformIdentifier" : "com.apple.platform.iphonesimulator",
    "runtimeBundlePath" : "/Library/Developer/CoreSimulator/Profiles/Runtimes/iOS 13.5.simruntime",
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
}`

const simctlRuntimesTextFixture = `== Runtimes ==
iOS 13.5 (13.5 - 17F61) - com.apple.CoreSimulator.SimRuntime.iOS-13-5 (unavailable, The iOS 13.5 simulator runtime is not supported on this host.)
iOS 26.4 (26.4 - 23E244) - com.apple.CoreSimulator.SimRuntime.iOS-26-4
`

func TestBuildRuntimeCleanupReportFindsOnlyUnavailableDeletableRuntimes(t *testing.T) {
	now := time.Date(2026, 5, 21, 8, 30, 0, 0, time.UTC)
	report, err := BuildRuntimeCleanupReport([]byte(runtimeListJSONFixture), []byte(simctlRuntimesTextFixture), "/usr/bin/xcrun", now)
	if err != nil {
		t.Fatalf("BuildRuntimeCleanupReport: %v", err)
	}
	if !report.GeneratedAt.Equal(now) {
		t.Fatalf("GeneratedAt = %s, want %s", report.GeneratedAt, now)
	}
	if report.Totals.CandidateCount != 1 || report.Totals.Bytes != 6568505344 {
		t.Fatalf("totals = %#v, want one iOS 13.5 candidate", report.Totals)
	}
	candidate := report.Candidates[0]
	if candidate.Identifier != "C20712BB-6F3A-4658-9C37-114C434C8CC5" {
		t.Fatalf("candidate identifier = %q", candidate.Identifier)
	}
	if candidate.Platform != "iOS" || candidate.Version != "13.5" || candidate.Build != "17F61" {
		t.Fatalf("candidate display fields = %#v", candidate)
	}
	if candidate.DeleteCommand[len(candidate.DeleteCommand)-1] != candidate.Identifier {
		t.Fatalf("delete command = %#v, want identifier suffix", candidate.DeleteCommand)
	}
}

func TestParseUnavailableRuntimeReasons(t *testing.T) {
	reasons := ParseUnavailableRuntimeReasons(simctlRuntimesTextFixture)
	if len(reasons) != 1 {
		t.Fatalf("reasons = %#v, want one unavailable runtime", reasons)
	}
	got := reasons["com.apple.CoreSimulator.SimRuntime.iOS-13-5"]
	if got != "The iOS 13.5 simulator runtime is not supported on this host." {
		t.Fatalf("reason = %q", got)
	}
}
