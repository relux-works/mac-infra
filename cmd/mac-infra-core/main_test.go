package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/maccore"
)

func TestRequestPermissionsRequiresPermissionKind(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withRequestSudoCredentials(t, func() error {
		called = true
		return nil
	})

	code := run([]string{"request-permissions"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run code = %d, want 2", code)
	}
	if called {
		t.Fatal("requestSudoCredentials called, want no sudo request without permission kind")
	}
	for _, want := range []string{"Usage:", "request-permissions sudo", "Available permissions:"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestRequestPermissionsRejectsUnknownPermissionKind(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withRequestSudoCredentials(t, func() error {
		called = true
		return nil
	})

	code := run([]string{"request-permissions", "full-disk-access"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run code = %d, want 2", code)
	}
	if called {
		t.Fatal("requestSudoCredentials called, want no sudo request for unknown permission kind")
	}
	for _, want := range []string{`unknown permission "full-disk-access"`, "request-permissions sudo"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
}

func TestRequestPermissionsSudoRequestsSudoThroughCoreTool(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withRequestSudoCredentials(t, func() error {
		called = true
		return nil
	})
	withInspectService(t, func(cfg maccore.ServiceConfig) (maccore.ServiceStatus, error) {
		return maccore.ServiceStatus{
			Label:      cfg.Label,
			PlistPath:  cfg.PlistPath,
			SocketPath: cfg.SocketPath,
			Reachable:  true,
			DaemonPID:  1234,
		}, nil
	})

	code := run([]string{"request-permissions", "sudo"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !called {
		t.Fatal("requestSudoCredentials was not called")
	}
	for _, want := range []string{
		"sudo: ready",
		"permission: sudo",
		"does not grant Full Disk Access",
		"state: reachable",
		"daemon_pid: 1234",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestRequestPermissionsSudoReportsSudoFailure(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	withRequestSudoCredentials(t, func() error {
		return errors.New("sudo denied")
	})

	code := run([]string{"request-permissions", "sudo"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "request-permissions sudo failed: sudo denied") {
		t.Fatalf("stderr = %q, want sudo failure", stderr.String())
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestAnyConnectCleanupDryRunDoesNotCallCore(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withCleanupAnyConnect(t, func(cfg maccore.ServiceConfig, force bool) (maccore.Response, error) {
		called = true
		return maccore.Response{}, nil
	})

	code := run([]string{"anyconnect-cleanup"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if called {
		t.Fatal("cleanupAnyConnect called during dry-run")
	}
	for _, want := range []string{
		"mode: dry-run",
		"refuse_if_connected: true",
		"/usr/bin/pkill -TERM -f com[.]cisco[.]anyconnect[.]macos[.]acsockext",
		"/bin/launchctl kickstart -k system/com.cisco.anyconnect.vpnagentd",
		"apply: mac-infra-core anyconnect-cleanup --apply",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestAnyConnectCleanupApplyCallsCore(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withCleanupAnyConnect(t, func(cfg maccore.ServiceConfig, force bool) (maccore.Response, error) {
		called = true
		if !force {
			t.Fatal("force = false, want true")
		}
		return maccore.Response{
			OK: true,
			Commands: []maccore.CommandResult{
				{Command: "/opt/cisco/anyconnect/bin/vpn status", Output: "state: Disconnected"},
				{Command: "/usr/bin/pkill -TERM -f com[.]cisco[.]anyconnect[.]macos[.]acsockext"},
			},
		}, nil
	})

	code := run([]string{"anyconnect-cleanup", "--apply", "--force"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !called {
		t.Fatal("cleanupAnyConnect was not called")
	}
	for _, want := range []string{
		"anyconnect-cleanup: applied",
		"command: /opt/cisco/anyconnect/bin/vpn status",
		"output: state: Disconnected",
		"command: /usr/bin/pkill -TERM -f com[.]cisco[.]anyconnect[.]macos[.]acsockext",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestAnyConnectCleanupApplyReportsCoreFailure(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	withCleanupAnyConnect(t, func(cfg maccore.ServiceConfig, force bool) (maccore.Response, error) {
		return maccore.Response{
			Commands: []maccore.CommandResult{
				{Command: "/opt/cisco/anyconnect/bin/vpn status", Output: "state: Connected"},
			},
		}, errors.New("refusing AnyConnect cleanup while vpn state is connected")
	})

	code := run([]string{"anyconnect-cleanup", "--apply"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run code = %d, want 1", code)
	}
	for _, want := range []string{
		"anyconnect-cleanup failed: refusing AnyConnect cleanup",
		"command: /opt/cisco/anyconnect/bin/vpn status",
		"output: state: Connected",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSleepPreventionEnableCallsFixedCoreAction(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withEnableSleepPrevention(t, func(cfg maccore.ServiceConfig) (maccore.Response, error) {
		called = true
		return maccore.Response{
			OK: true,
			Commands: []maccore.CommandResult{
				{Command: "/usr/bin/pmset -a disablesleep 1"},
			},
		}, nil
	})

	code := run([]string{"sleep-prevention", "enable"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !called {
		t.Fatal("enableSleepPrevention was not called")
	}
	for _, want := range []string{
		"sleep_prevention: enabled",
		"applies_to: AC,battery",
		"command: /usr/bin/pmset -a disablesleep 1",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSleepPreventionDisableCallsFixedCoreAction(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withDisableSleepPrevention(t, func(cfg maccore.ServiceConfig) (maccore.Response, error) {
		called = true
		return maccore.Response{
			OK: true,
			Commands: []maccore.CommandResult{
				{Command: "/usr/bin/pmset -a disablesleep 0"},
			},
		}, nil
	})

	code := run([]string{"sleep-prevention", "disable"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !called {
		t.Fatal("disableSleepPrevention was not called")
	}
	for _, want := range []string{
		"sleep_prevention: disabled",
		"applies_to: AC,battery",
		"command: /usr/bin/pmset -a disablesleep 0",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
}

func TestSleepPreventionEnableReportsCoreCommandFailure(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	withEnableSleepPrevention(t, func(cfg maccore.ServiceConfig) (maccore.Response, error) {
		return maccore.Response{
			Commands: []maccore.CommandResult{
				{
					Command: "/usr/bin/pmset -a disablesleep 1",
					Output:  "operation not permitted",
				},
			},
		}, errors.New("pmset failed")
	})

	code := run([]string{"sleep-prevention", "enable"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run code = %d, want 1", code)
	}
	for _, want := range []string{
		"sleep-prevention enable failed: pmset failed",
		"command: /usr/bin/pmset -a disablesleep 1",
		"output: operation not permitted",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr = %q, want %q", stderr.String(), want)
		}
	}
	if stdout.String() != "" {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
}

func TestSleepPreventionStatusPrintsGlobalStateAndCoverage(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	withInspectSleepPrevention(t, func() (maccore.SleepPreventionStatus, error) {
		return maccore.SleepPreventionStatus{
			State:     maccore.SleepPreventionStateDisabled,
			AppliesTo: maccore.SleepPreventionAppliesTo,
		}, nil
	})

	code := run([]string{"sleep-prevention", "status"}, &stdout, &stderr)

	if code != 0 {
		t.Fatalf("run code = %d, want 0; stderr = %q", code, stderr.String())
	}
	for _, want := range []string{
		"sleep_prevention: disabled",
		"applies_to: AC,battery",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if stderr.String() != "" {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
}

func TestSleepPreventionStatusReportsUnavailableAndError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	withInspectSleepPrevention(t, func() (maccore.SleepPreventionStatus, error) {
		return maccore.SleepPreventionStatus{
			State:     maccore.SleepPreventionStateUnavailable,
			AppliesTo: maccore.SleepPreventionAppliesTo,
		}, errors.New("missing system-wide SleepDisabled value")
	})

	code := run([]string{"sleep-prevention", "status"}, &stdout, &stderr)

	if code != 1 {
		t.Fatalf("run code = %d, want 1", code)
	}
	for _, want := range []string{
		"sleep_prevention: unavailable",
		"applies_to: AC,battery",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout = %q, want %q", stdout.String(), want)
		}
	}
	if !strings.Contains(stderr.String(), "sleep-prevention status failed: missing system-wide SleepDisabled value") {
		t.Fatalf("stderr = %q, want explicit status error", stderr.String())
	}
}

func TestSleepPreventionRejectsMissingOperation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run([]string{"sleep-prevention"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "mac-infra-core sleep-prevention enable") {
		t.Fatalf("stderr = %q, want sleep-prevention usage", stderr.String())
	}
}

func TestSleepPreventionRejectsValueArguments(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	called := false
	withEnableSleepPrevention(t, func(cfg maccore.ServiceConfig) (maccore.Response, error) {
		called = true
		return maccore.Response{}, nil
	})

	code := run([]string{"sleep-prevention", "enable", "0; arbitrary"}, &stdout, &stderr)

	if code != 2 {
		t.Fatalf("run code = %d, want 2", code)
	}
	if called {
		t.Fatal("enableSleepPrevention called with a value argument, want no daemon request")
	}
	if !strings.Contains(stderr.String(), "mac-infra-core sleep-prevention enable") {
		t.Fatalf("stderr = %q, want sleep-prevention usage", stderr.String())
	}
}

func TestSleepPreventionHelpAndUnknownOperation(t *testing.T) {
	t.Run("help", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := run([]string{"sleep-prevention", "--help"}, &stdout, &stderr)

		if code != 0 {
			t.Fatalf("run code = %d, want 0", code)
		}
		if !strings.Contains(stdout.String(), "mac-infra-core sleep-prevention status") {
			t.Fatalf("stdout = %q, want sleep-prevention usage", stdout.String())
		}
		if stderr.String() != "" {
			t.Fatalf("stderr = %q, want empty", stderr.String())
		}
	})

	t.Run("unknown", func(t *testing.T) {
		var stdout bytes.Buffer
		var stderr bytes.Buffer

		code := run([]string{"sleep-prevention", "set"}, &stdout, &stderr)

		if code != 2 {
			t.Fatalf("run code = %d, want 2", code)
		}
		if !strings.Contains(stderr.String(), "mac-infra-core sleep-prevention enable") {
			t.Fatalf("stderr = %q, want sleep-prevention usage", stderr.String())
		}
		if !strings.Contains(stderr.String(), `unknown sleep-prevention command "set"`) {
			t.Fatalf("stderr = %q, want unknown-command error", stderr.String())
		}
		if stdout.String() != "" {
			t.Fatalf("stdout = %q, want empty", stdout.String())
		}
	})
}

func withRequestSudoCredentials(t *testing.T, fn func() error) {
	t.Helper()
	original := requestSudoCredentials
	requestSudoCredentials = fn
	t.Cleanup(func() {
		requestSudoCredentials = original
	})
}

func withInspectService(t *testing.T, fn func(maccore.ServiceConfig) (maccore.ServiceStatus, error)) {
	t.Helper()
	original := inspectService
	inspectService = fn
	t.Cleanup(func() {
		inspectService = original
	})
}

func withCleanupAnyConnect(t *testing.T, fn func(maccore.ServiceConfig, bool) (maccore.Response, error)) {
	t.Helper()
	original := cleanupAnyConnect
	cleanupAnyConnect = fn
	t.Cleanup(func() {
		cleanupAnyConnect = original
	})
}

func withEnableSleepPrevention(t *testing.T, fn func(maccore.ServiceConfig) (maccore.Response, error)) {
	t.Helper()
	original := enableSleepPrevention
	enableSleepPrevention = fn
	t.Cleanup(func() {
		enableSleepPrevention = original
	})
}

func withDisableSleepPrevention(t *testing.T, fn func(maccore.ServiceConfig) (maccore.Response, error)) {
	t.Helper()
	original := disableSleepPrevention
	disableSleepPrevention = fn
	t.Cleanup(func() {
		disableSleepPrevention = original
	})
}

func withInspectSleepPrevention(t *testing.T, fn func() (maccore.SleepPreventionStatus, error)) {
	t.Helper()
	original := inspectSleepPrevention
	inspectSleepPrevention = fn
	t.Cleanup(func() {
		inspectSleepPrevention = original
	})
}
