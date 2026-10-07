package maccore

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Proves the installer observes exact-target removal before bootstrap.
// Commands are isolated helpers; no launchd or privileged mutation occurs.
func TestInstallServiceWaitsForRemovalBeforeBootstrap(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeInstallCommand(t, logPath)
	cfg := ServiceConfig{Label: "works.relux.test-install", PlistPath: filepath.Join(t.TempDir(), "core.plist"), SocketPath: tempSocketPath(t, "install")}
	errs := make(chan error, 1)
	go func() { errs <- RunDaemon(cfg, os.Getuid(), os.Getgid()) }()
	waitForSocket(t, cfg, errs)
	t.Setenv("MAC_INFRA_INSTALL_SEQUENCE", "present,missing")
	t.Setenv("MAC_INFRA_INSTALL_COUNTER", filepath.Join(t.TempDir(), "counter"))
	if err := InstallService(cfg, "/fixture/core", os.Getuid(), os.Getgid()); err != nil {
		t.Fatal(err)
	}
	calls := readCommandLog(t, logPath)
	first := strings.Index(calls, "launchctl print system/"+cfg.Label)
	last := strings.LastIndex(calls, "launchctl print system/"+cfg.Label)
	boot := strings.Index(calls, "launchctl bootstrap system ")
	if first < 0 || last <= first || boot <= last {
		t.Fatalf("bootstrap must follow present then missing observations; calls:\n%s", calls)
	}
}

func withFakeInstallCommand(t *testing.T, logPath string) {
	t.Helper()
	old, oldCtx := execCommandCore, execCommandContextCore
	build := func(ctx context.Context, name string, args ...string) *exec.Cmd {
		argv := append([]string{"-test.run=TestInstallCommandHelper", "--", name}, args...)
		cmd := exec.CommandContext(ctx, os.Args[0], argv...)
		cmd.Env = append(os.Environ(), "GO_WANT_INSTALL_HELPER=1", "MAC_INFRA_INSTALL_LOG="+logPath)
		return cmd
	}
	execCommandCore = func(name string, args ...string) *exec.Cmd { return build(context.Background(), name, args...) }
	execCommandContextCore = build
	t.Cleanup(func() { execCommandCore = old; execCommandContextCore = oldCtx })
}

func TestInstallCommandHelper(t *testing.T) {
	if os.Getenv("GO_WANT_INSTALL_HELPER") != "1" {
		return
	}
	args := os.Args
	for len(args) > 0 && args[0] != "--" {
		args = args[1:]
	}
	if len(args) < 2 {
		os.Exit(2)
	}
	args = args[1:]
	f, err := os.OpenFile(os.Getenv("MAC_INFRA_INSTALL_LOG"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		os.Exit(2)
	}
	_, _ = f.WriteString(strings.Join(args, " ") + "\n")
	_ = f.Close()
	if args[0] == "sudo" || args[0] == "/usr/bin/sudo" {
		args = args[1:]
		if len(args) > 0 && args[0] == "-n" {
			args = args[1:]
			if len(args) > 0 && args[0] == "true" {
				os.Exit(0)
			}
		}
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	if !strings.HasSuffix(args[0], "launchctl") {
		os.Exit(0)
	}
	if len(args) < 3 {
		os.Exit(2)
	}
	switch args[1] {
	case "bootout":
		if os.Getenv("MAC_INFRA_INSTALL_BOOTOUT_FAIL") != "" {
			switch os.Getenv("MAC_INFRA_INSTALL_BOOTOUT_FAIL") {
			case "ambiguous3":
				println("Boot-out failed: 3: unrelated failure")
				os.Exit(3)
			case "ambiguous113":
				println("Could not find service \"unrelated\" in domain for system")
				os.Exit(113)
			}
			println("Boot-out failed")
			os.Exit(9)
		}
		if os.Getenv("MAC_INFRA_INSTALL_BOOTOUT_MISSING") == "1" {
			println("Boot-out failed: 3: No such process")
			os.Exit(3)
		}
	case "bootstrap":
		if os.Getenv("MAC_INFRA_INSTALL_BOOTSTRAP_FAIL") == "1" {
			println("Bootstrap failed: 5: Input/output error")
			os.Exit(5)
		}
	case "print":
		if os.Getenv("MAC_INFRA_INSTALL_PRINT_DELAY") == "1" {
			time.Sleep(2 * time.Second)
		}
		counter := os.Getenv("MAC_INFRA_INSTALL_COUNTER")
		raw, _ := os.ReadFile(counter)
		_ = os.WriteFile(counter, append(raw, '.'), 0o600)
		seq := strings.Split(os.Getenv("MAC_INFRA_INSTALL_SEQUENCE"), ",")
		idx := len(raw)
		if idx >= len(seq) {
			idx = len(seq) - 1
		}
		switch seq[idx] {
		case "present":
			println("state = running")
		case "missing":
			label := strings.TrimPrefix(args[2], "system/")
			println("Could not find service \"" + label + "\" in domain for system")
			os.Exit(113)
		case "wrong-target":
			println("Could not find service \"unrelated\" in domain for system")
			os.Exit(113)
		case "wrong-domain":
			label := strings.TrimPrefix(args[2], "system/")
			println("Could not find service \"" + label + "\" in domain for system-other")
			os.Exit(113)
		case "extra-error":
			label := strings.TrimPrefix(args[2], "system/")
			println("Could not find service \"" + label + "\" in domain for system\nPermission denied")
			os.Exit(113)
		case "missing-with-prefix":
			label := strings.TrimPrefix(args[2], "system/")
			println("Bad request.\nCould not find service \"" + label + "\" in domain for system")
			os.Exit(113)
		case "denied":
			println("Permission denied")
			os.Exit(9)
		default:
			println("Unexpected launchctl result")
			os.Exit(113)
		}
	}
	os.Exit(0)
}

// Checks fresh installation and already-removed replacement controls, and
// refuses retained/ambiguous/error states without any bootstrap command.
func TestReplaceLaunchServiceAdmission(t *testing.T) {
	cases := []struct {
		name, sequence, bootoutFail, bootoutMissing, bootstrapFail, wantError string
		wantBootstrap                                                         bool
	}{
		{name: "fresh", sequence: "missing", bootoutMissing: "1", wantBootstrap: true},
		{name: "removed", sequence: "missing", wantBootstrap: true},
		{name: "missing diagnostic observed on host", sequence: "missing-with-prefix", wantBootstrap: true},
		{name: "still present", sequence: "present", wantError: "did not leave"},
		{name: "print denied", sequence: "denied", wantError: "verify service removal"},
		{name: "unrelated missing", sequence: "wrong-target", wantError: "verify service removal"},
		{name: "wrong domain", sequence: "wrong-domain", wantError: "verify service removal"},
		{name: "additional error", sequence: "extra-error", wantError: "verify service removal"},
		{name: "ambiguous missing", sequence: "unknown", wantError: "verify service removal"},
		{name: "bootout failure", sequence: "missing", bootoutFail: "1", wantError: "bootout service"},
		{name: "ambiguous bootout3", sequence: "missing", bootoutFail: "ambiguous3", wantError: "bootout service"},
		{name: "ambiguous bootout113", sequence: "missing", bootoutFail: "ambiguous113", wantError: "bootout service"},
		{name: "bootstrap failure is not retried", sequence: "missing", bootstrapFail: "1", wantError: "Input/output error", wantBootstrap: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "commands.log")
			withFakeInstallCommand(t, logPath)
			t.Setenv("MAC_INFRA_INSTALL_SEQUENCE", tc.sequence)
			t.Setenv("MAC_INFRA_INSTALL_COUNTER", filepath.Join(t.TempDir(), "counter"))
			t.Setenv("MAC_INFRA_INSTALL_BOOTOUT_FAIL", tc.bootoutFail)
			t.Setenv("MAC_INFRA_INSTALL_BOOTOUT_MISSING", tc.bootoutMissing)
			t.Setenv("MAC_INFRA_INSTALL_BOOTSTRAP_FAIL", tc.bootstrapFail)
			cfg := ServiceConfig{Label: "works.relux.test-install", PlistPath: "/fixture/core.plist"}
			err := replaceLaunchService(cfg, time.Second)
			if tc.wantError == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("error=%v, want %s", err, tc.wantError)
			}
			calls := readCommandLog(t, logPath)
			count := strings.Count(calls, "launchctl bootstrap system /fixture/core.plist")
			want := 0
			if tc.wantBootstrap {
				want = 1
			}
			if count != want {
				t.Fatalf("bootstrap count=%d, want%d; calls:\n%s", count, want, calls)
			}
			if tc.bootstrapFail != "" && exitCode(err) != 5 {
				t.Fatalf("bootstrap exit=%d, want5", exitCode(err))
			}
			if tc.bootoutFail != "" && strings.Contains(calls, "launchctl print") {
				t.Fatalf("inspection after real bootout failure: %s", calls)
			}
		})
	}
}

// A stalled launchctl query cannot exceed its remaining removal budget or
// authorize bootstrap. This fixture proves deadline cancellation, not load-independent timing.
func TestReplaceLaunchServiceSlowInspection(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeInstallCommand(t, logPath)
	t.Setenv("MAC_INFRA_INSTALL_SEQUENCE", "missing")
	t.Setenv("MAC_INFRA_INSTALL_COUNTER", filepath.Join(t.TempDir(), "counter"))
	t.Setenv("MAC_INFRA_INSTALL_PRINT_DELAY", "1")
	err := replaceLaunchService(ServiceConfig{Label: "works.relux.test-install", PlistPath: "/fixture/core.plist"}, 100*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v, want deadline exceeded", err)
	}
	if strings.Contains(readCommandLog(t, logPath), "launchctl bootstrap") {
		t.Fatal("bootstrap after stalled inspection")
	}
}
