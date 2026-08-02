package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/maccore"
)

func TestDisplaySleepPreventionStatusReportsIndependentAssertion(t *testing.T) {
	withInspectDisplaySleepPrevention(t, func() (maccore.DisplaySleepPreventionStatus, error) {
		return maccore.DisplaySleepPreventionStatus{
			State:     maccore.DisplaySleepPreventionStateDisabled,
			AppliesTo: maccore.DisplaySleepPreventionAppliesTo,
		}, nil
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"display-sleep-prevention", "status"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"display_sleep_prevention: disabled",
		"applies_to: AC,battery",
		"assertion: PreventUserIdleDisplaySleep",
		"session_scope: current-user",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestDisplaySleepPreventionEnableUsesDedicatedLaunchAgent(t *testing.T) {
	called := false
	withEnableDisplaySleepPrevention(t, func() ([]maccore.CommandResult, error) {
		called = true
		return []maccore.CommandResult{
			{Command: "/bin/launchctl bootstrap gui/501 /Users/test/Library/LaunchAgents/display.plist"},
		}, nil
	})
	withInspectDisplaySleepPrevention(t, func() (maccore.DisplaySleepPreventionStatus, error) {
		return maccore.DisplaySleepPreventionStatus{
			State: maccore.DisplaySleepPreventionStateEnabled, AppliesTo: maccore.DisplaySleepPreventionAppliesTo,
		}, nil
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"display-sleep-prevention", "enable"}, &stdout, &stderr)

	if code != 0 || !called {
		t.Fatalf("code = %d called = %v stderr = %q", code, called, stderr.String())
	}
	for _, want := range []string{
		"display_sleep_prevention: enabled",
		"command: /bin/launchctl bootstrap gui/501 /Users/test/Library/LaunchAgents/display.plist",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestDisplaySleepPreventionMutationReportsFailure(t *testing.T) {
	withDisableDisplaySleepPrevention(t, func() ([]maccore.CommandResult, error) {
		return nil, errors.New("launchctl unavailable")
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"display-sleep-prevention", "disable"}, &stdout, &stderr)

	if code != 1 || !strings.Contains(stderr.String(), "display-sleep-prevention disable failed") {
		t.Fatalf("code = %d stderr = %q", code, stderr.String())
	}
}

func TestIdleLockPreventionStatusPreservesManualLockPassword(t *testing.T) {
	withInspectIdleLockPrevention(t, func() (maccore.IdleLockPreventionStatus, error) {
		return maccore.IdleLockPreventionStatus{
			State: maccore.IdleLockPreventionStateDisabled, IdleTimePresent: true, IdleTimeSeconds: 3600,
		}, nil
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"idle-lock-prevention", "status"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("code = %d stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"idle_lock_prevention: disabled",
		"idle_time_seconds: 3600",
		"prevents: automatic-screen-saver-lock",
		"display_sleep_policy: separate",
		"manual_lock_password: unchanged",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestIdleLockPreventionEnableUsesUserScopedDefaults(t *testing.T) {
	called := false
	withEnableIdleLockPrevention(t, func() ([]maccore.CommandResult, error) {
		called = true
		return []maccore.CommandResult{{
			Command: "/usr/bin/defaults -currentHost write com.apple.screensaver idleTime -int 0",
		}}, nil
	})
	withInspectIdleLockPrevention(t, func() (maccore.IdleLockPreventionStatus, error) {
		return maccore.IdleLockPreventionStatus{
			State: maccore.IdleLockPreventionStateEnabled, IdleTimePresent: true, IdleTimeSeconds: 0,
		}, nil
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"idle-lock-prevention", "enable"}, &stdout, &stderr)

	if code != 0 || !called {
		t.Fatalf("code = %d called = %v stderr = %q", code, called, stderr.String())
	}
	for _, want := range []string{
		"idle_lock_prevention: enabled",
		"idle_time_seconds: 0",
		"manual_lock_password: unchanged",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestPowerPreventionCommandsRejectCombinedValueArguments(t *testing.T) {
	for _, command := range []string{"display-sleep-prevention", "idle-lock-prevention"} {
		t.Run(command, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := run([]string{command, "enable", "--all"}, &stdout, &stderr)
			if code != 2 || !strings.Contains(stderr.String(), command+" enable") {
				t.Fatalf("code = %d stderr = %q", code, stderr.String())
			}
		})
	}
}

func withInspectDisplaySleepPrevention(t *testing.T, fn func() (maccore.DisplaySleepPreventionStatus, error)) {
	t.Helper()
	original := inspectDisplaySleepPrevention
	inspectDisplaySleepPrevention = fn
	t.Cleanup(func() { inspectDisplaySleepPrevention = original })
}

func withEnableDisplaySleepPrevention(t *testing.T, fn func() ([]maccore.CommandResult, error)) {
	t.Helper()
	original := enableDisplaySleepPrevention
	enableDisplaySleepPrevention = fn
	t.Cleanup(func() { enableDisplaySleepPrevention = original })
}

func withDisableDisplaySleepPrevention(t *testing.T, fn func() ([]maccore.CommandResult, error)) {
	t.Helper()
	original := disableDisplaySleepPrevention
	disableDisplaySleepPrevention = fn
	t.Cleanup(func() { disableDisplaySleepPrevention = original })
}

func withInspectIdleLockPrevention(t *testing.T, fn func() (maccore.IdleLockPreventionStatus, error)) {
	t.Helper()
	original := inspectIdleLockPrevention
	inspectIdleLockPrevention = fn
	t.Cleanup(func() { inspectIdleLockPrevention = original })
}

func withEnableIdleLockPrevention(t *testing.T, fn func() ([]maccore.CommandResult, error)) {
	t.Helper()
	original := enableIdleLockPrevention
	enableIdleLockPrevention = fn
	t.Cleanup(func() { enableIdleLockPrevention = original })
}
