package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/maccore"
)

func withInspectFSEventsDaemon(t *testing.T, fn func() (maccore.FSEventsDaemonState, maccore.CommandResult, error)) {
	t.Helper()
	original := inspectFSEventsDaemon
	inspectFSEventsDaemon = fn
	t.Cleanup(func() { inspectFSEventsDaemon = original })
}

func withRestartFSEvents(t *testing.T, fn func(maccore.ServiceConfig, bool, int64) (maccore.Response, error)) {
	t.Helper()
	original := restartFSEvents
	restartFSEvents = fn
	t.Cleanup(func() { restartFSEvents = original })
}

func withWatchdogStubs(t *testing.T, cfg maccore.FSEventsWatchdogConfig) (enabled *maccore.FSEventsWatchdogSettings, disabled *bool) {
	t.Helper()
	enabled = &maccore.FSEventsWatchdogSettings{}
	disabled = new(bool)
	originalConfig, originalEnable, originalDisable, originalInspect := defaultFSEventsWatchdogConfig, enableFSEventsWatchdog, disableFSEventsWatchdog, inspectFSEventsWatchdog
	defaultFSEventsWatchdogConfig = func(binary string) (maccore.FSEventsWatchdogConfig, error) {
		cfg.BinaryPath = binary
		return cfg, nil
	}
	enableFSEventsWatchdog = func(_ maccore.FSEventsWatchdogConfig, settings maccore.FSEventsWatchdogSettings) ([]maccore.CommandResult, error) {
		*enabled = settings
		return []maccore.CommandResult{{Command: "/bin/launchctl bootstrap gui/501 " + cfg.PlistPath}}, nil
	}
	disableFSEventsWatchdog = func(maccore.FSEventsWatchdogConfig) ([]maccore.CommandResult, error) {
		*disabled = true
		return nil, nil
	}
	inspectFSEventsWatchdog = func(maccore.FSEventsWatchdogConfig) (maccore.FSEventsWatchdogStatus, error) {
		state := maccore.FSEventsWatchdogDisabled
		if enabled.RSSThresholdBytes > 0 && !*disabled {
			state = maccore.FSEventsWatchdogEnabled
		}
		return maccore.FSEventsWatchdogStatus{State: state, Label: cfg.Label, PlistPath: cfg.PlistPath, StatePath: cfg.StatePath, UserDomain: "gui/501"}, nil
	}
	t.Cleanup(func() {
		defaultFSEventsWatchdogConfig, enableFSEventsWatchdog, disableFSEventsWatchdog, inspectFSEventsWatchdog = originalConfig, originalEnable, originalDisable, originalInspect
	})
	return enabled, disabled
}

// The CLI refuses below the threshold locally and never contacts the daemon;
// --force skips the local guard and forwards force to the daemon.
func TestFSEventsRestartRefusesBelowThresholdAndForceForwards(t *testing.T) {
	withInspectFSEventsDaemon(t, func() (maccore.FSEventsDaemonState, maccore.CommandResult, error) {
		return maccore.FSEventsDaemonState{Found: true, PID: 368, RSSBytes: 512 * 1024 * 1024}, maccore.CommandResult{}, nil
	})
	called := false
	var gotForce bool
	var gotThreshold int64
	withRestartFSEvents(t, func(_ maccore.ServiceConfig, force bool, threshold int64) (maccore.Response, error) {
		called = true
		gotForce = force
		gotThreshold = threshold
		return maccore.Response{OK: true, Commands: []maccore.CommandResult{{Command: "fseventsd after", Output: "pid=999"}}}, nil
	})

	var stdout, stderr bytes.Buffer
	if code := run([]string{"fseventsd-restart"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code = %d, want 1; stderr = %q", code, stderr.String())
	}
	if called || !strings.Contains(stderr.String(), "below threshold") {
		t.Fatalf("daemon called = %t stderr = %q", called, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"fseventsd-restart", "--force", "--threshold-gb", "2"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d; stderr = %q", code, stderr.String())
	}
	if !called || !gotForce || gotThreshold != 2*1024*1024*1024 {
		t.Fatalf("called = %t force = %t threshold = %d", called, gotForce, gotThreshold)
	}
	if !strings.Contains(stdout.String(), "fseventsd-restart: applied") || !strings.Contains(stdout.String(), "pid=999") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

// Invalid threshold is a usage error before any inspection.
func TestFSEventsRestartRejectsNonPositiveThreshold(t *testing.T) {
	inspected := false
	withInspectFSEventsDaemon(t, func() (maccore.FSEventsDaemonState, maccore.CommandResult, error) {
		inspected = true
		return maccore.FSEventsDaemonState{}, maccore.CommandResult{}, nil
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fseventsd-restart", "--threshold-gb", "0"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code = %d", code)
	}
	if inspected {
		t.Fatal("inspect ran despite invalid threshold")
	}
}

// Over the threshold the daemon error is surfaced with its command trail.
func TestFSEventsRestartReportsDaemonFailure(t *testing.T) {
	withInspectFSEventsDaemon(t, func() (maccore.FSEventsDaemonState, maccore.CommandResult, error) {
		return maccore.FSEventsDaemonState{Found: true, PID: 368, RSSBytes: 8 * 1024 * 1024 * 1024}, maccore.CommandResult{}, nil
	})
	withRestartFSEvents(t, func(maccore.ServiceConfig, bool, int64) (maccore.Response, error) {
		return maccore.Response{Commands: []maccore.CommandResult{{Command: "fseventsd before", Output: "pid=368"}}}, errors.New("daemon unreachable")
	})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fseventsd-restart"}, &stdout, &stderr); code != 1 {
		t.Fatalf("code = %d", code)
	}
	if !strings.Contains(stderr.String(), "daemon unreachable") || !strings.Contains(stderr.String(), "fseventsd before") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

// enable parses threshold/interval/auto-restart into settings, and
// auto-restart is refused when the root daemon is not installed.
func TestFSEventsWatchdogEnableParsesSettings(t *testing.T) {
	cfg := maccore.FSEventsWatchdogConfig{Label: "works.relux.test", PlistPath: filepath.Join(t.TempDir(), "p.plist"), StatePath: filepath.Join(t.TempDir(), "s.json"), UID: 501}
	enabled, _ := withWatchdogStubs(t, cfg)
	originalAvailable := coreAvailable
	coreAvailable = func(maccore.ServiceConfig) bool { return true }
	t.Cleanup(func() { coreAvailable = originalAvailable })

	var stdout, stderr bytes.Buffer
	code := run([]string{"fseventsd-watchdog", "enable", "--threshold-gb", "3", "--interval", "15m"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("code = %d stderr = %q", code, stderr.String())
	}
	if enabled.RSSThresholdBytes != 3*1024*1024*1024 || enabled.Interval != 15*time.Minute || enabled.AutoRestart {
		t.Fatalf("settings = %+v", *enabled)
	}
	if !strings.Contains(stdout.String(), "fseventsd_watchdog: enabled") {
		t.Fatalf("stdout = %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"fseventsd-watchdog", "enable", "--threshold-gb", "-1"}, &stdout, &stderr); code != 2 {
		t.Fatalf("negative threshold code = %d", code)
	}
}

// --auto-restart without a reachable daemon is refused before enabling.
func TestFSEventsWatchdogEnableAutoRestartNeedsDaemon(t *testing.T) {
	cfg := maccore.FSEventsWatchdogConfig{Label: "works.relux.test", PlistPath: "/tmp/p.plist", StatePath: "/tmp/s.json", UID: 501}
	enabled, _ := withWatchdogStubs(t, cfg)
	originalAvailable := coreAvailable
	coreAvailable = func(maccore.ServiceConfig) bool { return false }
	t.Cleanup(func() { coreAvailable = originalAvailable })
	var stdout, stderr bytes.Buffer
	code := run([]string{"fseventsd-watchdog", "enable", "--auto-restart"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "--auto-restart needs the mac-infra-core daemon") {
		t.Fatalf("code = %d stderr = %q", code, stderr.String())
	}
	if enabled.RSSThresholdBytes != 0 {
		t.Fatalf("enable must not run: %+v", *enabled)
	}
}

// disable and status route through the stubs; unknown verbs are usage errors.
func TestFSEventsWatchdogDisableStatusAndUnknown(t *testing.T) {
	cfg := maccore.FSEventsWatchdogConfig{Label: "works.relux.test", PlistPath: "/tmp/p.plist", StatePath: "/tmp/s.json", UID: 501}
	_, disabled := withWatchdogStubs(t, cfg)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fseventsd-watchdog", "disable"}, &stdout, &stderr); code != 0 || !*disabled {
		t.Fatalf("code = %d disabled = %t stderr = %q", code, *disabled, stderr.String())
	}
	if !strings.Contains(stdout.String(), "fseventsd_watchdog: disabled") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"fseventsd-watchdog", "status"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "last_check: none") {
		t.Fatalf("code = %d stdout = %q", code, stdout.String())
	}
	stderr.Reset()
	if code := run([]string{"fseventsd-watchdog", "bogus"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("code = %d stderr = %q", code, stderr.String())
	}
}

// The hidden check verb reports a recorded check error through its exit code
// so launchd logs show a failing tick.
func TestFSEventsCheckExitsNonZeroOnCheckError(t *testing.T) {
	cfg := maccore.FSEventsWatchdogConfig{Label: "works.relux.test", PlistPath: "/tmp/p.plist", StatePath: "/tmp/s.json", UID: 501}
	withWatchdogStubs(t, cfg)
	original := runFSEventsWatchdogCheck
	var gotState string
	runFSEventsWatchdogCheck = func(cfg maccore.FSEventsWatchdogConfig, _ maccore.ServiceConfig, _ time.Time) (maccore.FSEventsWatchdogCheck, error) {
		gotState = cfg.StatePath
		return maccore.FSEventsWatchdogCheck{Found: true, PID: 1, OverLimit: true, Error: "notify: boom"}, nil
	}
	t.Cleanup(func() { runFSEventsWatchdogCheck = original })

	var stdout, stderr bytes.Buffer
	code := run([]string{"_fseventsd-check", "--state", "/custom/state.json"}, &stdout, &stderr)
	if code != 1 || gotState != "/custom/state.json" {
		t.Fatalf("code = %d state = %q", code, gotState)
	}
	if !strings.Contains(stdout.String(), "check_error: notify: boom") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
