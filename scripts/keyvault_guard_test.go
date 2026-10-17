package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func runKeyvaultGuard(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("./keyvault-build-guard.sh", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(stdout.String()), stderr.String(), code
}

// Claim: setup.sh's keyvault guard builds when no binary exists, keeps an
// existing binary unless a rebuild is requested, allows a requested rebuild
// of an idle binary, and refuses one that a process runs, also when the
// process was started through a symlink. Malformed arguments are usage
// errors. Limit: "running" is what lsof reports for the file.
func TestKeyvaultBuildGuard(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "mac-keyvault")

	if out, _, code := runKeyvaultGuard(t, binary, "0"); code != 0 || out != "build" {
		t.Fatalf("absent binary: %q %d", out, code)
	}
	// A copy of this test binary stands in for mac-keyvault; started through
	// the symlink below it sleeps in TestKeyvaultGuardSleepHelper.
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, self, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, _, code := runKeyvaultGuard(t, binary, "0"); code != 0 || out != "keep" {
		t.Fatalf("existing binary without rebuild: %q %d", out, code)
	}
	if out, _, code := runKeyvaultGuard(t, binary, "1"); code != 0 || out != "build" {
		t.Fatalf("idle binary with rebuild (control): %q %d", out, code)
	}

	link := filepath.Join(dir, "link-to-mac-keyvault")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	running := exec.Command(link, "-test.run=^TestKeyvaultGuardSleepHelper$")
	running.Env = append(os.Environ(), "MAC_INFRA_GUARD_SLEEP_HELPER=1")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { running.Process.Kill(); running.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	var out, stderr string
	var code int
	for time.Now().Before(deadline) {
		if out, stderr, code = runKeyvaultGuard(t, binary, "1"); code == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != 1 || out != "" || !strings.Contains(stderr, "a running process uses it") {
		t.Fatalf("running binary with rebuild: %q %q %d", out, stderr, code)
	}
	if out, _, code := runKeyvaultGuard(t, binary, "0"); code != 0 || out != "keep" {
		t.Fatalf("running binary without rebuild: %q %d", out, code)
	}

	for _, args := range [][]string{{binary}, {binary, "yes"}, {binary, "1", "extra"}} {
		if _, _, code := runKeyvaultGuard(t, args...); code != 2 {
			t.Errorf("args %v: exit %d", args, code)
		}
	}
}

// TestKeyvaultGuardSleepHelper is the long-running stand-in process; it does
// nothing unless started by TestKeyvaultBuildGuard.
func TestKeyvaultGuardSleepHelper(t *testing.T) {
	if os.Getenv("MAC_INFRA_GUARD_SLEEP_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}
