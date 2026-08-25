package browsersession

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testHeartbeatManager(t *testing.T) HeartbeatManager {
	t.Helper()
	m := HeartbeatManager{
		HomeDir:   t.TempDir(),
		Launchctl: "/bin/launchctl",
		UID:       501,
		Now:       func() time.Time { return time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC) },
		WaitForFirstOutcome: func(context.Context, HeartbeatConfig) error {
			return nil
		},
		RunCommand: func(_ context.Context, _ string, args ...string) error {
			if len(args) > 0 && args[0] == "print" {
				return nil
			}
			return nil
		},
	}
	if err := os.MkdirAll(filepath.Dir(m.LauncherPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.LauncherPath(), []byte("stable test launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestStartRequiresSuccessfulBackgroundOutcomeFromProductionWaitPath(t *testing.T) {
	m := testHeartbeatManager(t)
	m.WaitForFirstOutcome = nil
	cfg, err := m.NewConfig("background-ready", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m.RunCommand = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 0 && args[0] == "bootstrap" {
			return appendHeartbeatOutcome(cfg.LogPath, HeartbeatOutcome{Timestamp: time.Now().UTC().Format(time.RFC3339), Outcome: "ok", Origin: cfg.Origin, ReadyState: "complete"})
		}
		return nil
	}
	if _, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin, ReadyState: "complete"}, nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStartRefusesFailedBackgroundOutcomeAndRemovesManagedArtifacts(t *testing.T) {
	m := testHeartbeatManager(t)
	m.WaitForFirstOutcome = nil
	cfg, err := m.NewConfig("background-failed", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	m.RunCommand = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 0 && args[0] == "bootstrap" {
			return appendHeartbeatOutcome(cfg.LogPath, HeartbeatOutcome{Timestamp: time.Now().UTC().Format(time.RFC3339), Outcome: "error", ErrorKind: "automation-disabled"})
		}
		return nil
	}
	if _, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin, ReadyState: "complete"}, nil
	}); err == nil || !strings.Contains(err.Error(), "background heartbeat outcome: automation-disabled") {
		t.Fatalf("error = %v, want background automation refusal", err)
	}
	for _, path := range []string{cfg.StatePath, cfg.PlistPath, cfg.LogPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("failed background preflight left %s (err=%v)", path, err)
		}
	}
	if _, err := os.Stat(m.LauncherPath()); err != nil {
		t.Fatalf("failed background preflight removed stable launcher: %v", err)
	}
}

func TestNewConfigRejectsUnsafeNamesIntervalsAndSafariTabIDs(t *testing.T) {
	m := testHeartbeatManager(t)
	for _, name := range []string{"../bad", "UPPER", strings.Repeat("a", 49)} {
		if _, err := m.NewConfig(name, BrowserChrome, "1", "2", "https://example.com", 30*time.Second, m.now().Add(time.Hour)); err == nil {
			t.Fatalf("unsafe name %q accepted", name)
		}
	}
	if _, err := m.NewConfig("safe", BrowserChrome, "1", "2", "https://example.com", 14*time.Second, m.now().Add(time.Hour)); err == nil {
		t.Fatal("sub-15s heartbeat accepted")
	}
	if _, err := m.NewConfig("safe", BrowserSafari, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour)); err == nil {
		t.Fatal("Safari tab id accepted even though Safari is window-scoped")
	}
}

func TestDeadlineGateRejectsMissingAmbiguousAndExpiredInputs(t *testing.T) {
	m := testHeartbeatManager(t)
	for name, check := range map[string]func() error{
		"missing": func() error {
			_, err := m.ResolveDeadline(0, "")
			return err
		},
		"ambiguous": func() error {
			_, err := m.ResolveDeadline(time.Hour, m.now().Add(2*time.Hour).Format(time.RFC3339))
			return err
		},
		"expired": func() error {
			_, err := m.ResolveDeadline(0, m.now().Add(-time.Second).Format(time.RFC3339))
			return err
		},
		"malformed": func() error {
			_, err := m.ResolveDeadline(0, "tomorrow")
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err == nil {
				t.Fatal("deadline gate admitted invalid input")
			}
		})
	}
	if _, err := m.NewConfig("missing-deadline", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, time.Time{}); err == nil {
		t.Fatal("NewConfig production call admitted a missing deadline")
	}
}

func TestHeartbeatPayloadIsBoundedAndSecretFree(t *testing.T) {
	source := HeartbeatJavaScript()
	if err := GuardJavaScript(source); err != nil {
		t.Fatalf("heartbeat payload violates page-context guard: %v", err)
	}
	for _, forbidden := range append(BlockedJavaScriptTokens(), "document.title", "innerText", "textContent") {
		if strings.Contains(strings.ToLower(source), strings.ToLower(forbidden)) {
			t.Fatalf("heartbeat payload contains private/secret token %q: %s", forbidden, source)
		}
	}
	for _, want := range []string{"mousemove", "pointermove", "ShiftLeft", "location.origin", "document.readyState"} {
		if !strings.Contains(source, want) {
			t.Fatalf("heartbeat payload missing %q: %s", want, source)
		}
	}
}

func TestHeartbeatProbeTimeoutIsBoundedIndependentlyOfInterval(t *testing.T) {
	if heartbeatProbeTimeout != 10*time.Second {
		t.Fatalf("probe timeout = %s, want 10s", heartbeatProbeTimeout)
	}
}

func TestHeartbeatRetriesTransientFailuresButNotGuardFailures(t *testing.T) {
	m := testHeartbeatManager(t)
	m.WaitRetry = func(context.Context, time.Duration) error { return nil }
	cfg := HeartbeatConfig{}
	calls := 0
	result, err := m.runProbeWithRetry(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		calls++
		if calls < heartbeatProbeAttempts {
			return ExecutionResult{}, context.DeadlineExceeded
		}
		return ExecutionResult{Origin: "https://example.com"}, nil
	})
	if err != nil || calls != heartbeatProbeAttempts || result.Origin != "https://example.com" {
		t.Fatalf("transient retry result=%#v calls=%d err=%v", result, calls, err)
	}

	calls = 0
	_, err = m.runProbeWithRetry(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		calls++
		return ExecutionResult{}, &OriginMismatchError{Expected: "https://expected.example", Observed: "https://wrong.example"}
	})
	if err == nil || calls != 1 {
		t.Fatalf("origin refusal calls=%d err=%v, want one call and refusal", calls, err)
	}
}

func TestHeartbeatOutcomeFreshnessIncludesIntervalButExpires(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 30, 0, 0, time.UTC)
	interval := 20 * time.Minute
	if !heartbeatOutcomeIsFresh(now, interval, now.Add(-20*time.Minute).Format(time.RFC3339)) {
		t.Fatal("outcome at the scheduled interval boundary reported stale")
	}
	if heartbeatOutcomeIsFresh(now, interval, now.Add(-21*time.Minute).Format(time.RFC3339)) {
		t.Fatal("old successful outcome still reported fresh")
	}
	if heartbeatOutcomeIsFresh(now, interval, "not-a-time") {
		t.Fatal("invalid timestamp reported fresh")
	}
}

func TestHeartbeatErrorKindStaysBoundedAndActionable(t *testing.T) {
	cases := map[string]error{
		"timeout":             context.DeadlineExceeded,
		"unreadable-response": ErrUnreadableResponse,
		"guard-refusal":       ErrSensitiveJavaScript,
		"automation-disabled": errors.New("JavaScript from Apple Events is turned off"),
		"unavailable":         errors.New("opaque failure with PRIVATE PAGE TITLE"),
	}
	for want, err := range cases {
		if got := heartbeatErrorKind(err); got != want {
			t.Fatalf("heartbeatErrorKind(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestStartUsesOneStableInstalledLauncherIdentity(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("stable-launcher", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: "https://example.com", ReadyState: "complete"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if started.Executable != m.LauncherPath() {
		t.Fatalf("launcher = %q, want stable path %q", started.Executable, m.LauncherPath())
	}
	plist, err := os.ReadFile(started.PlistPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plist), started.Executable) {
		t.Fatalf("plist does not use stable launcher:\n%s", plist)
	}
}

func TestStartPreflightRefusalInstallsNothing(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("refused", BrowserChrome, "1", "2", "https://expected.example", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{}, &OriginMismatchError{Expected: cfg.Origin, Observed: "https://wrong.example"}
	})
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("error = %v, want origin refusal", err)
	}
	for _, path := range []string{cfg.StatePath, cfg.PlistPath, cfg.LogPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("preflight refusal installed %s (err=%v)", path, err)
		}
	}
	if _, err := os.Stat(m.LauncherPath()); err != nil {
		t.Fatalf("preflight refusal removed stable launcher: %v", err)
	}
}

func TestStartRefusesMissingStableLauncherBeforeBrowserPreflight(t *testing.T) {
	m := testHeartbeatManager(t)
	if err := os.Remove(m.LauncherPath()); err != nil {
		t.Fatal(err)
	}
	cfg, err := m.NewConfig("missing-launcher", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	probes := 0
	if _, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		probes++
		return ExecutionResult{Origin: cfg.Origin}, nil
	}); err == nil || !strings.Contains(err.Error(), "rerun scripts/setup.sh") {
		t.Fatalf("error = %v, want stable-launcher refusal", err)
	}
	if probes != 0 {
		t.Fatalf("missing launcher reached browser preflight %d times", probes)
	}
}

func TestStartRefusesNonExecutableOrNonRegularStableLauncherBeforeBrowserPreflight(t *testing.T) {
	for _, tc := range []struct {
		name    string
		install func(*testing.T, string)
	}{
		{
			name: "non-executable",
			install: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Chmod(path, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "directory",
			install: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := testHeartbeatManager(t)
			tc.install(t, m.LauncherPath())
			cfg, err := m.NewConfig("invalid-launcher", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			probes := 0
			_, err = m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
				probes++
				return ExecutionResult{Origin: cfg.Origin}, nil
			})
			if err == nil || !strings.Contains(err.Error(), "not an executable regular file") {
				t.Fatalf("error = %v, want executable regular-file refusal", err)
			}
			if probes != 0 {
				t.Fatalf("invalid launcher reached browser preflight %d times", probes)
			}
		})
	}
}

func TestRenderLaunchAgentRejectsTemporaryExecutable(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("bad-exec", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Executable = "/tmp/mac-chrome-session"
	if _, err := RenderHeartbeatLaunchAgent(cfg); err == nil {
		t.Fatal("non-stable executable rendered into LaunchAgent")
	}
}

func TestRenderLaunchAgentRejectsLegacyContentAddressedExecutable(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("legacy-exec", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Executable = filepath.Join(m.binDir(), "mac-browser-session-deadbeef")
	if _, err := RenderHeartbeatLaunchAgent(cfg); err == nil {
		t.Fatal("legacy content-addressed executable rendered into LaunchAgent")
	}
}

func TestRunHeartbeatLogsOnlyBoundedOutcomeAndMode0600(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("private-log", BrowserChrome, "1", "2", "https://example.com", 15*time.Millisecond, m.now().Add(time.Hour))
	if err == nil {
		t.Fatal("test setup unexpectedly bypassed minimum interval")
	}
	// Build valid managed state, then shorten only the in-test persisted interval
	// so the production Run loop can exercise multiple ticks without sleeping.
	cfg, err = m.NewConfig("private-log", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := jsonMarshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	probeCalls := 0
	err = m.Run(ctx, cfg.Name, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		probeCalls++
		cancel()
		return ExecutionResult{Value: "PRIVATE PAGE TITLE", Origin: cfg.Origin, ReadyState: "complete"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if probeCalls != 1 {
		t.Fatalf("probe calls = %d, want 1", probeCalls)
	}
	logData, err := os.ReadFile(cfg.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logData), "PRIVATE PAGE TITLE") {
		t.Fatalf("heartbeat log leaked page text: %s", logData)
	}
	for _, want := range []string{`"outcome":"ok"`, `"origin":"https://example.com"`, `"readyState":"complete"`} {
		if !strings.Contains(string(logData), want) {
			t.Fatalf("heartbeat log missing %q: %s", want, logData)
		}
	}
	info, err := os.Stat(cfg.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("log mode = %o, want 600", info.Mode().Perm())
	}
}

func TestRunHeartbeatOriginMismatchLogsRefusalWithoutPayloadEvidence(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("drift", BrowserChrome, "1", "2", "https://expected.example", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	state, err := jsonMarshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	err = m.Run(ctx, cfg.Name, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		cancel()
		return ExecutionResult{}, &OriginMismatchError{Expected: cfg.Origin, Observed: "https://wrong.example"}
	})
	if err != nil {
		t.Fatal(err)
	}
	last, ok, err := readLastHeartbeatOutcome(cfg.LogPath)
	if err != nil || !ok {
		t.Fatalf("read outcome: ok=%v err=%v", ok, err)
	}
	if last.Outcome != "refused" || last.Origin != "https://wrong.example" {
		t.Fatalf("outcome = %#v", last)
	}
	status, err := m.Inspect(context.Background(), cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "drifted" {
		t.Fatalf("status = %q, want drifted", status.State)
	}
}

func TestStopRemovesPerHeartbeatStateButKeepsStableLauncher(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("cleanup", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(context.Background(), cfg.Name); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{started.StatePath, started.PlistPath, started.LogPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed artifact survived stop: %s (err=%v)", path, err)
		}
	}
	if _, err := os.Stat(started.Executable); err != nil {
		t.Fatalf("stable installed launcher removed by stop: %v", err)
	}
}

func TestMultipleNamedHeartbeatsShareStableLauncherAndStopIndependently(t *testing.T) {
	m := testHeartbeatManager(t)
	started := make([]HeartbeatConfig, 0, 2)
	for _, name := range []string{"first", "second"} {
		cfg, err := m.NewConfig(name, BrowserChrome, "1", name, "https://example.com", 15*time.Second, m.now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err = m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
			return ExecutionResult{Origin: "https://example.com"}, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		started = append(started, cfg)
	}
	if started[0].Executable != started[1].Executable {
		t.Fatalf("stable launcher paths differ: %q vs %q", started[0].Executable, started[1].Executable)
	}
	if started[0].Label == started[1].Label || started[0].StatePath == started[1].StatePath {
		t.Fatalf("named heartbeat identity collided: %#v", started)
	}
	if err := m.Stop(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(started[0].Executable); err != nil {
		t.Fatalf("stable launcher removed with one heartbeat: %v", err)
	}
	if _, err := os.Stat(started[1].StatePath); err != nil {
		t.Fatalf("second heartbeat state removed with first: %v", err)
	}
	if err := m.Stop(context.Background(), "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(started[0].Executable); err != nil {
		t.Fatalf("stable installed launcher removed after final stop: %v", err)
	}
}

func TestLauncherPathRemainsStableAcrossInstalledRebuild(t *testing.T) {
	m := testHeartbeatManager(t)
	first, err := m.NewConfig("before-rebuild", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.LauncherPath(), []byte("rebuilt launcher bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	second, err := m.NewConfig("after-rebuild", BrowserSafari, "3", "", "https://example.com", 15*time.Second, m.now().Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.Executable != second.Executable || first.Executable != m.LauncherPath() {
		t.Fatalf("launcher identity changed across rebuild: first=%q second=%q stable=%q", first.Executable, second.Executable, m.LauncherPath())
	}
}

func TestInspectExpiresHeartbeatAndCleansManagedArtifactsWithoutBrowserProbe(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	m := testHeartbeatManager(t)
	m.Now = func() time.Time { return now }
	bootouts := 0
	m.RunCommand = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 0 && args[0] == "bootout" {
			bootouts++
		}
		return nil
	}
	deadline := now.Add(time.Minute)
	cfg, err := m.NewConfig("expires-on-status", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, deadline)
	if err != nil {
		t.Fatal(err)
	}
	probes := 0
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		probes++
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now = deadline
	status, err := m.Inspect(context.Background(), cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "expired" || !status.Expired || status.Deadline != deadline.Format(time.RFC3339) || status.ErrorKind != "deadline-expired" {
		t.Fatalf("expired status = %#v", status)
	}
	if probes != 1 {
		t.Fatalf("expiry cleanup dispatched an extra browser probe: %d", probes)
	}
	if bootouts != 1 {
		t.Fatalf("expiry bootout calls = %d, want 1", bootouts)
	}
	for _, path := range []string{started.StatePath, started.PlistPath, started.LogPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expired artifact survived: %s (err=%v)", path, err)
		}
	}
}

func TestInspectExpiredHeartbeatDoesNotLaunderBootoutFailureWhenIdentityContains113(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	m := testHeartbeatManager(t)
	m.UID = 113
	m.Now = func() time.Time { return now }
	deadline := now.Add(time.Minute)
	cfg, err := m.NewConfig("hb113", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	}); err != nil {
		t.Fatal(err)
	}

	fakeLaunchctl := filepath.Join(t.TempDir(), "launchctl")
	if err := os.WriteFile(fakeLaunchctl, []byte("#!/bin/sh\necho 'Operation not permitted' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.Launchctl = fakeLaunchctl
	m.RunCommand = nil
	now = deadline

	status, err := m.Inspect(context.Background(), cfg.Name)
	if err == nil {
		t.Fatalf("Inspect laundered bootout failure as status %#v", status)
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("Inspect error = %v, want genuine launchctl failure", err)
	}
}

func TestInspectExpiredHeartbeatAcceptsStructuredMissingBootout(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	m := testHeartbeatManager(t)
	m.Now = func() time.Time { return now }
	deadline := now.Add(time.Minute)
	cfg, err := m.NewConfig("missing-at-expiry", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, deadline)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	}); err != nil {
		t.Fatal(err)
	}

	fakeLaunchctl := filepath.Join(t.TempDir(), "launchctl")
	if err := os.WriteFile(fakeLaunchctl, []byte("#!/bin/sh\necho 'Boot-out failed: 3: No such process' >&2\nexit 3\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	m.Launchctl = fakeLaunchctl
	m.RunCommand = nil
	now = deadline

	status, err := m.Inspect(context.Background(), cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "expired" || !status.Expired {
		t.Fatalf("expired missing-service status = %#v", status)
	}
}

func TestInspectUsesStructuredLaunchctlPrintEvidence(t *testing.T) {
	tests := []struct {
		name       string
		output     string
		wantStatus string
	}{
		{name: "missing service", output: "Bad request.\nCould not find service \"test\" in domain for user gui: 501", wantStatus: "configured-not-loaded"},
		{name: "same exit with genuine failure", output: "Operation not permitted", wantStatus: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := testHeartbeatManager(t)
			cfg, err := m.NewConfig("print-evidence", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
				return ExecutionResult{Origin: cfg.Origin}, nil
			}); err != nil {
				t.Fatal(err)
			}

			fakeLaunchctl := filepath.Join(t.TempDir(), "launchctl")
			script := "#!/bin/sh\nprintf '%s\\n' '" + tt.output + "' >&2\nexit 113\n"
			if err := os.WriteFile(fakeLaunchctl, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			m.Launchctl = fakeLaunchctl
			m.RunCommand = nil

			status, err := m.Inspect(context.Background(), cfg.Name)
			if err != nil {
				t.Fatal(err)
			}
			if status.State != tt.wantStatus {
				t.Fatalf("status = %#v, want %q", status, tt.wantStatus)
			}
		})
	}
}

func TestRunRefusesExpiredHeartbeatBeforeBrowserProbeAndCleansState(t *testing.T) {
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	m := testHeartbeatManager(t)
	m.Now = func() time.Time { return now }
	deadline := now.Add(time.Minute)
	cfg, err := m.NewConfig("expires-on-run", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, deadline)
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	now = deadline
	probes := 0
	if err := m.Run(context.Background(), cfg.Name, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		probes++
		return ExecutionResult{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if probes != 0 {
		t.Fatalf("expired Run production call reached browser %d times", probes)
	}
	for _, path := range []string{started.StatePath, started.PlistPath, started.LogPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expired Run left %s (err=%v)", path, err)
		}
	}
}

func TestRunExpiresDuringProbeAtRealDeadlineAndCleansManagedState(t *testing.T) {
	m := testHeartbeatManager(t)
	m.Now = nil
	bootouts := 0
	m.RunCommand = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 0 && args[0] == "bootout" {
			bootouts++
		}
		return nil
	}
	cfg, err := m.NewConfig("expires-mid-probe", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	setRuntimeHeartbeatDeadline(t, &started, 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	startedAt := time.Now()
	probes := 0
	err = m.Run(ctx, started.Name, func(probeCtx context.Context, _ HeartbeatConfig) (ExecutionResult, error) {
		probes++
		<-probeCtx.Done()
		return ExecutionResult{}, probeCtx.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed >= 1500*time.Millisecond {
		t.Fatalf("Run waited %s instead of enforcing the heartbeat deadline during the probe", elapsed)
	}
	if probes != 1 || bootouts != 1 {
		t.Fatalf("mid-probe expiry probes=%d bootouts=%d, want 1/1", probes, bootouts)
	}
	assertHeartbeatArtifactsRemoved(t, started)
}

func TestRunExpiresDuringIntervalSleepAtRealDeadlineAndCleansManagedState(t *testing.T) {
	m := testHeartbeatManager(t)
	m.Now = nil
	bootouts := 0
	m.RunCommand = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 0 && args[0] == "bootout" {
			bootouts++
		}
		return nil
	}
	cfg, err := m.NewConfig("expires-mid-sleep", BrowserChrome, "1", "2", "https://example.com", 20*time.Minute, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	setRuntimeHeartbeatDeadline(t, &started, 500*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	startedAt := time.Now()
	probes := 0
	err = m.Run(ctx, started.Name, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		probes++
		return ExecutionResult{Origin: started.Origin, ReadyState: "complete"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedAt); elapsed >= 1500*time.Millisecond {
		t.Fatalf("Run waited %s for a %s interval instead of enforcing the heartbeat deadline", elapsed, started.Interval)
	}
	if probes != 1 || bootouts != 1 {
		t.Fatalf("sleep-window expiry probes=%d bootouts=%d, want 1/1", probes, bootouts)
	}
	assertHeartbeatArtifactsRemoved(t, started)
}

func setRuntimeHeartbeatDeadline(t *testing.T, cfg *HeartbeatConfig, after time.Duration) {
	t.Helper()
	cfg.Deadline = time.Now().Add(after).UTC().Format(time.RFC3339Nano)
	state, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(cfg.StatePath, append(state, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertHeartbeatArtifactsRemoved(t *testing.T, cfg HeartbeatConfig) {
	t.Helper()
	for _, path := range []string{cfg.StatePath, cfg.PlistPath, cfg.LogPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("expired heartbeat left %s (err=%v)", path, err)
		}
	}
}

func TestLegacyHeartbeatReportsMigrationAndRestartUsesStableLauncherAndDeadline(t *testing.T) {
	m := testHeartbeatManager(t)
	legacy, err := m.NewConfig("legacy", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	legacy.Deadline = ""
	legacy.Executable = filepath.Join(m.binDir(), "mac-browser-session-legacy")
	if err := os.WriteFile(legacy.Executable, []byte("legacy launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	state, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy.StatePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(legacy.PlistPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy.PlistPath, []byte("legacy plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := m.Inspect(context.Background(), legacy.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "migration-required" || !status.MigrationRequired || status.ErrorKind != "missing-deadline" {
		t.Fatalf("legacy status = %#v", status)
	}
	deadline := m.now().Add(2 * time.Hour)
	probes := 0
	restarted, err := m.Restart(context.Background(), legacy.Name, deadline, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		probes++
		return ExecutionResult{Origin: legacy.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if probes != 2 {
		t.Fatalf("restart preflight calls = %d, want direct safety check plus Start check", probes)
	}
	if restarted.Executable != m.LauncherPath() || restarted.Deadline != deadline.Format(time.RFC3339) {
		t.Fatalf("restarted config = %#v", restarted)
	}
	if _, err := os.Stat(legacy.Executable); !os.IsNotExist(err) {
		t.Fatalf("legacy content-addressed launcher survived migration: %v", err)
	}
	if _, err := m.Load(legacy.Name); err != nil {
		t.Fatalf("strict load after restart: %v", err)
	}
}

func TestStableLauncherHeartbeatWithoutDeadlineRequiresMigration(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("deadline-migration", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Deadline = ""
	state, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, state, 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := m.Inspect(context.Background(), cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "migration-required" || !status.MigrationRequired || status.ErrorKind != "missing-deadline" {
		t.Fatalf("deadline-free stable-launcher status = %#v", status)
	}
	if _, err := m.Load(cfg.Name); err == nil || !strings.Contains(err.Error(), "requires restart with a deadline") {
		t.Fatalf("strict Load admitted deadline-free stable state: %v", err)
	}
}

func TestRestartPreflightRefusalPreservesExistingHeartbeat(t *testing.T) {
	m := testHeartbeatManager(t)
	bootouts := 0
	m.RunCommand = func(_ context.Context, _ string, args ...string) error {
		if len(args) > 0 && args[0] == "bootout" {
			bootouts++
		}
		return nil
	}
	cfg, err := m.NewConfig("restart-refused", BrowserChrome, "1", "2", "https://expected.example", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Restart(context.Background(), cfg.Name, m.now().Add(2*time.Hour), func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{}, &OriginMismatchError{Expected: cfg.Origin, Observed: "https://wrong.example"}
	})
	if !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("restart error = %v, want origin refusal", err)
	}
	if bootouts != 0 {
		t.Fatalf("refused restart booted out existing heartbeat %d times", bootouts)
	}
	preserved, err := m.Load(cfg.Name)
	if err != nil {
		t.Fatalf("existing heartbeat was not preserved: %v", err)
	}
	if preserved.Deadline != started.Deadline || preserved.Executable != started.Executable {
		t.Fatalf("existing heartbeat changed after refused restart: before=%#v after=%#v", started, preserved)
	}
	for _, path := range []string{started.StatePath, started.PlistPath, started.LogPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("refused restart removed %s: %v", path, err)
		}
	}
}

func TestInspectDistinguishesNotConfiguredNotLoadedTargetMissingAndUnavailable(t *testing.T) {
	m := testHeartbeatManager(t)
	status, err := m.Inspect(context.Background(), "absent")
	if err != nil || status.State != "not-configured" {
		t.Fatalf("absent status=%#v err=%v", status, err)
	}
	cfg, err := m.NewConfig("states", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	m.RunCommand = func(context.Context, string, ...string) error { return errors.New("service not found") }
	status, err = m.Inspect(context.Background(), cfg.Name)
	if err != nil || status.State != "configured-not-loaded" {
		t.Fatalf("not-loaded status=%#v err=%v", status, err)
	}
	m.RunCommand = func(context.Context, string, ...string) error { return nil }
	status, err = m.Inspect(context.Background(), cfg.Name)
	if err != nil || status.State != "unavailable" {
		t.Fatalf("no-outcome status=%#v err=%v", status, err)
	}
	if err := appendHeartbeatOutcome(started.LogPath, HeartbeatOutcome{Timestamp: m.now().UTC().Format(time.RFC3339), Outcome: "error", ErrorKind: "target-missing"}); err != nil {
		t.Fatal(err)
	}
	status, err = m.Inspect(context.Background(), cfg.Name)
	if err != nil || status.State != "target-missing" {
		t.Fatalf("target-missing status=%#v err=%v", status, err)
	}
	if err := appendHeartbeatOutcome(started.LogPath, HeartbeatOutcome{Timestamp: m.now().UTC().Format(time.RFC3339), Outcome: "error", ErrorKind: "unavailable"}); err != nil {
		t.Fatal(err)
	}
	status, err = m.Inspect(context.Background(), cfg.Name)
	if err != nil || status.State != "unavailable" {
		t.Fatalf("unavailable status=%#v err=%v", status, err)
	}
}

func TestInspectDoesNotReportStaleSuccessAsRunning(t *testing.T) {
	m := testHeartbeatManager(t)
	cfg, err := m.NewConfig("stale", BrowserChrome, "1", "2", "https://example.com", 20*time.Minute, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	started, err := m.Start(context.Background(), cfg, func(context.Context, HeartbeatConfig) (ExecutionResult, error) {
		return ExecutionResult{Origin: cfg.Origin}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	old := m.now().Add(-21 * time.Minute).UTC().Format(time.RFC3339)
	if err := appendHeartbeatOutcome(started.LogPath, HeartbeatOutcome{Timestamp: old, Outcome: "ok", Origin: cfg.Origin, ReadyState: "complete"}); err != nil {
		t.Fatal(err)
	}
	status, err := m.Inspect(context.Background(), cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "unavailable" || status.ErrorKind != "stale-outcome" || status.LastOutcomeAt != old {
		t.Fatalf("stale status = %#v", status)
	}
}

func TestInspectDoesNotTreatLaunchctlReadFailureAsStopped(t *testing.T) {
	m := testHeartbeatManager(t)
	m.RunCommand = func(context.Context, string, ...string) error { return errors.New("permission denied") }
	cfg, err := m.NewConfig("unknown", BrowserChrome, "1", "2", "https://example.com", 15*time.Second, m.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	state, err := jsonMarshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.StatePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.StatePath, state, 0o600); err != nil {
		t.Fatal(err)
	}
	status, err := m.Inspect(context.Background(), cfg.Name)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != "unknown" {
		t.Fatalf("status = %q, want unknown", status.State)
	}
}

func jsonMarshal(value any) ([]byte, error) {
	return json.Marshal(value)
}
