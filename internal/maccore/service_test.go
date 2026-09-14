package maccore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRenderServicePlistContainsDaemonArguments(t *testing.T) {
	cfg := ServiceConfig{
		Label:      "works.relux.test-core",
		PlistPath:  "/Library/LaunchDaemons/works.relux.test-core.plist",
		SocketPath: "/var/run/works.relux.test-core.sock",
	}

	plist := string(RenderServicePlist(cfg, "/tmp/mac-infra-core", 501, 20))

	for _, want := range []string{
		"<string>works.relux.test-core</string>",
		"<string>/tmp/mac-infra-core</string>",
		"<string>_daemon</string>",
		"<string>/var/run/works.relux.test-core.sock</string>",
		"<string>501</string>",
		"<string>20</string>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
}

func TestDaemonPing(t *testing.T) {
	socketPath := tempSocketPath(t, "mac-infra-core")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	resp, err := Call(cfg, Request{Action: "ping"})
	if err != nil {
		t.Fatalf("Call ping error = %v", err)
	}
	if !resp.OK || resp.DaemonPID <= 0 {
		t.Fatalf("ping response = %#v, want ok with daemon pid", resp)
	}
}

func TestDaemonRejectsUnsupportedAction(t *testing.T) {
	socketPath := tempSocketPath(t, "mac-infra-core-unsupported")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	_, err := Call(cfg, Request{Action: "run_arbitrary_command"})
	if err == nil {
		t.Fatal("Call unsupported action error = nil, want error")
	}
	if !strings.Contains(err.Error(), "unsupported mac-infra-core action") {
		t.Fatalf("unsupported action error = %q", err)
	}
}

func TestDaemonSleepPreventionActionsRunOnlyFixedPMSetCommands(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	socketPath := tempSocketPath(t, "mic-sp")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	enableResponse, err := EnableSleepPrevention(cfg)
	if err != nil {
		t.Fatalf("EnableSleepPrevention error = %v", err)
	}
	disableResponse, err := DisableSleepPrevention(cfg)
	if err != nil {
		t.Fatalf("DisableSleepPrevention error = %v", err)
	}

	if got, want := len(enableResponse.Commands), 1; got != want {
		t.Fatalf("len(enableResponse.Commands) = %d, want %d", got, want)
	}
	if got, want := enableResponse.Commands[0].Command, "/usr/bin/pmset -a disablesleep 1"; got != want {
		t.Fatalf("enable command = %q, want %q", got, want)
	}
	if got, want := len(disableResponse.Commands), 1; got != want {
		t.Fatalf("len(disableResponse.Commands) = %d, want %d", got, want)
	}
	if got, want := disableResponse.Commands[0].Command, "/usr/bin/pmset -a disablesleep 0"; got != want {
		t.Fatalf("disable command = %q, want %q", got, want)
	}
	wantCalls := "/usr/bin/pmset -a disablesleep 1\n/usr/bin/pmset -a disablesleep 0\n"
	if calls := readCommandLog(t, logPath); calls != wantCalls {
		t.Fatalf("calls = %q, want %q", calls, wantCalls)
	}
}

func TestDaemonSleepPreventionReturnsCommandFailure(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PMSET_FAIL_COMMAND", "/usr/bin/pmset -a disablesleep 1")
	t.Setenv("MAC_INFRA_TEST_PMSET_FAILURE", "operation not permitted")
	socketPath := tempSocketPath(t, "mic-sp-fail")
	cfg := ServiceConfig{Label: "works.relux.test-core", SocketPath: socketPath}
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunDaemon(cfg, os.Getuid(), os.Getgid())
	}()
	waitForSocket(t, cfg, errCh)

	response, err := EnableSleepPrevention(cfg)

	if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("EnableSleepPrevention error = %v, want command failure", err)
	}
	if response.OK {
		t.Fatalf("response.OK = true, want false")
	}
	if got, want := len(response.Commands), 1; got != want {
		t.Fatalf("len(response.Commands) = %d, want %d", got, want)
	}
	if got, want := response.Commands[0].Command, "/usr/bin/pmset -a disablesleep 1"; got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestCleanupAnyConnectRefusesConnectedVPN(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_VPN_STATUS", ">> state: Connected")

	results, err := cleanupAnyConnect(false)

	if err == nil {
		t.Fatal("cleanupAnyConnect error = nil, want refusal")
	}
	if !strings.Contains(err.Error(), "refusing AnyConnect cleanup") {
		t.Fatalf("error = %q, want refusal", err)
	}
	if got, want := len(results), 1; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if calls := readCommandLog(t, logPath); calls != "/opt/cisco/anyconnect/bin/vpn status\n" {
		t.Fatalf("calls = %q, want only vpn status", calls)
	}
}

func TestCleanupAnyConnectRunsAllowlistedCommandsWhenDisconnected(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_VPN_STATUS", ">> state: Disconnected")

	results, err := cleanupAnyConnect(false)

	if err != nil {
		t.Fatalf("cleanupAnyConnect error = %v", err)
	}
	if got, want := len(results), 3; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	wantCalls := strings.Join([]string{
		"/opt/cisco/anyconnect/bin/vpn status",
		"/usr/bin/pkill -TERM -f com[.]cisco[.]anyconnect[.]macos[.]acsockext",
		"/bin/launchctl kickstart -k system/com.cisco.anyconnect.vpnagentd",
		"",
	}, "\n")
	if calls := readCommandLog(t, logPath); calls != wantCalls {
		t.Fatalf("calls = %q, want %q", calls, wantCalls)
	}
}

func tempSocketPath(t *testing.T, prefix string) string {
	t.Helper()
	path := filepath.Join(os.TempDir(), fmt.Sprintf("%s-%d.sock", prefix, time.Now().UnixNano()))
	_ = os.Remove(path)
	t.Cleanup(func() {
		_ = os.Remove(path)
	})
	return path
}

func waitForSocket(t *testing.T, cfg ServiceConfig, errCh <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			t.Fatalf("daemon exited early: %v", err)
		default:
		}
		status, err := InspectService(cfg)
		if err != nil {
			t.Fatalf("InspectService error = %v", err)
		}
		if status.Reachable {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become reachable", cfg.SocketPath)
}

func withFakeCoreCommand(t *testing.T, logPath string) {
	t.Helper()
	original := execCommandContextCore
	execCommandContextCore = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		helperArgs := []string{"-test.run=TestCoreCommandHelperProcess", "--", name}
		helperArgs = append(helperArgs, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], helperArgs...)
		cmd.Env = append(os.Environ(),
			"GO_WANT_CORE_COMMAND_HELPER=1",
			"MAC_INFRA_TEST_COMMAND_LOG="+logPath,
		)
		return cmd
	}
	t.Cleanup(func() {
		execCommandContextCore = original
	})
}

func bytesReadOrEmpty(path string) []byte {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return raw
}

func readCommandLog(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read command log: %v", err)
	}
	return string(raw)
}

func TestCoreCommandHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CORE_COMMAND_HELPER") != "1" {
		return
	}
	args := os.Args
	separator := -1
	for idx, arg := range args {
		if arg == "--" {
			separator = idx
			break
		}
	}
	if separator < 0 || separator+1 >= len(args) {
		os.Exit(2)
	}
	command := strings.Join(args[separator+1:], " ")
	if logPath := os.Getenv("MAC_INFRA_TEST_COMMAND_LOG"); logPath != "" {
		file, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			os.Exit(2)
		}
		_, _ = fmt.Fprintln(file, command)
		_ = file.Close()
	}
	switch args[separator+1] {
	case "/opt/cisco/anyconnect/bin/vpn":
		fmt.Fprintln(os.Stdout, os.Getenv("MAC_INFRA_TEST_VPN_STATUS"))
	case "/usr/bin/pkill":
	case "/bin/launchctl":
		if strings.Contains(command, "/bin/launchctl print ") {
			switch os.Getenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT") {
			case "enabled":
				fmt.Fprintln(os.Stdout, "service = enabled")
			case "failure":
				fmt.Fprintln(os.Stderr, "launchctl unavailable")
				os.Exit(9)
			default:
				fmt.Fprintln(os.Stderr, "service not found")
				os.Exit(113)
			}
		}
		if strings.Contains(command, "/bin/launchctl bootout ") && os.Getenv("MAC_INFRA_TEST_LAUNCHCTL_BOOTOUT") == "missing" {
			fmt.Fprintln(os.Stderr, "service not found")
			os.Exit(3)
		}
	case "/bin/ps":
		if os.Getenv("MAC_INFRA_TEST_PS_FAIL") == "1" {
			fmt.Fprintln(os.Stderr, "ps unavailable")
			os.Exit(9)
		}
		// Sequenced outputs let a test observe before/after restart states.
		outputs := strings.Split(os.Getenv("MAC_INFRA_TEST_PS_OUTPUTS"), "|")
		counterPath := os.Getenv("MAC_INFRA_TEST_PS_COUNTER")
		index := 0
		if counterPath != "" {
			if raw, err := os.ReadFile(counterPath); err == nil {
				index = len(raw)
			}
			_ = os.WriteFile(counterPath, append(bytesReadOrEmpty(counterPath), '.'), 0o600)
		}
		if index >= len(outputs) {
			index = len(outputs) - 1
		}
		fmt.Fprintln(os.Stdout, strings.ReplaceAll(outputs[index], ";", "\n"))
	case "/usr/bin/osascript":
		if os.Getenv("MAC_INFRA_TEST_OSASCRIPT_FAIL") == "1" {
			fmt.Fprintln(os.Stderr, "osascript unavailable")
			os.Exit(9)
		}
	case "/usr/bin/pmset":
		if os.Getenv("MAC_INFRA_TEST_PMSET_FAIL_COMMAND") == command {
			fmt.Fprintln(os.Stderr, os.Getenv("MAC_INFRA_TEST_PMSET_FAILURE"))
			os.Exit(9)
		}
		if command == "/usr/bin/pmset -g" {
			fmt.Fprintln(os.Stdout, os.Getenv("MAC_INFRA_TEST_PMSET_OUTPUT"))
		}
	case "/usr/bin/defaults":
		if os.Getenv("MAC_INFRA_TEST_DEFAULTS_FAIL_COMMAND") == command {
			fmt.Fprintln(os.Stderr, os.Getenv("MAC_INFRA_TEST_DEFAULTS_FAILURE"))
			os.Exit(9)
		}
		if command == "/usr/bin/defaults -currentHost export com.apple.screensaver -" {
			fmt.Fprintln(os.Stdout, os.Getenv("MAC_INFRA_TEST_SCREENSAVER_OUTPUT"))
		}
	default:
		os.Exit(127)
	}
	os.Exit(0)
}
