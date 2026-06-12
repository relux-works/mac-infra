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
