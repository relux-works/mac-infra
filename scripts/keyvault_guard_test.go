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

// fakeTool writes an executable shell script that stands in for a system
// tool in the guard.
func fakeTool(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func runKeyvaultGuard(t *testing.T, env []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("./keyvault-build-guard.sh", args...)
	cmd.Env = append(os.Environ(), env...)
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

// startStandIn runs a copy of this test binary from path until the test
// ends; it sleeps in TestKeyvaultGuardSleepHelper.
func startStandIn(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command(path, "-test.run=^TestKeyvaultGuardSleepHelper$")
	cmd.Env = append(os.Environ(), "MAC_INFRA_GUARD_SLEEP_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
}

// scopedPS lists only processes whose arguments mention dir, so the live
// keyvault agents of this host do not decide the test.
func scopedPS(t *testing.T, tools, dir string) string {
	t.Helper()
	return "KEYVAULT_GUARD_PS=" + fakeTool(t, tools, "ps-scoped", "/bin/ps -axo args= | /usr/bin/grep -F -- '"+dir+"' || true")
}

func waitRefusal(t *testing.T, env []string, binary, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var out, stderr string
	var code int
	for time.Now().Before(deadline) {
		if out, stderr, code = runKeyvaultGuard(t, env, binary, "1"); code == 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if code != 1 || out != "" || !strings.Contains(stderr, want) {
		t.Fatalf("want refusal %q: out %q, stderr %q, exit %d", want, out, stderr, code)
	}
}

// Claim: setup.sh's keyvault guard builds when no binary exists, keeps an
// existing binary unless a rebuild is requested, and allows a requested
// rebuild only when nothing uses the binary (control). It refuses a
// requested rebuild when a process has the file open (also when started
// through a symlink), when a process was started from the path and the file
// was replaced since, when a keyvault LaunchAgent is loaded, and when any of
// lsof, ps or launchctl cannot answer. Malformed arguments are usage errors.
// Limit: it sees what lsof, ps and launchctl report for the current user.
func TestKeyvaultBuildGuard(t *testing.T) {
	dir := t.TempDir()
	tools := t.TempDir()
	binary := filepath.Join(dir, "mac-keyvault")
	noJobs := "KEYVAULT_GUARD_LAUNCHCTL=" + fakeTool(t, tools, "launchctl-none", `echo "PID	Status	Label"; echo "-	0	com.example.other"`)
	ps := scopedPS(t, tools, dir)
	env := []string{noJobs, ps}

	if out, _, code := runKeyvaultGuard(t, env, binary, "0"); code != 0 || out != "build" {
		t.Fatalf("absent binary: %q %d", out, code)
	}
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, self, 0o755); err != nil {
		t.Fatal(err)
	}
	if out, _, code := runKeyvaultGuard(t, env, binary, "0"); code != 0 || out != "keep" {
		t.Fatalf("existing binary without rebuild: %q %d", out, code)
	}
	if out, stderr, code := runKeyvaultGuard(t, env, binary, "1"); code != 0 || out != "build" {
		t.Fatalf("idle binary with rebuild (control): %q %q %d", out, stderr, code)
	}

	for name, extra := range map[string]string{
		"lsof diagnostics": "KEYVAULT_GUARD_LSOF=" + fakeTool(t, tools, "lsof-denied", `echo "lsof: permission denied" >&2; exit 1`),
		"lsof failure":     "KEYVAULT_GUARD_LSOF=" + fakeTool(t, tools, "lsof-broken", `exit 2`),
		"ps failure":       "KEYVAULT_GUARD_PS=" + fakeTool(t, tools, "ps-broken", `exit 1`),
		"launchctl fails":  "KEYVAULT_GUARD_LAUNCHCTL=" + fakeTool(t, tools, "launchctl-broken", `exit 1`),
		"agent loaded":     "KEYVAULT_GUARD_LAUNCHCTL=" + fakeTool(t, tools, "launchctl-agent", `echo "-	0	works.relux.mac-keyvault.relux-release"`),
	} {
		if out, _, code := runKeyvaultGuard(t, append([]string{noJobs, ps}, extra), binary, "1"); code != 1 || out != "" {
			t.Errorf("%s: %q exit %d", name, out, code)
		}
	}

	link := filepath.Join(dir, "link-to-mac-keyvault")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	startStandIn(t, link)
	waitRefusal(t, env, binary, "a running process uses it")
	if out, _, code := runKeyvaultGuard(t, env, binary, "0"); code != 0 || out != "keep" {
		t.Fatalf("running binary without rebuild: %q %d", out, code)
	}

	for _, args := range [][]string{{binary}, {binary, "yes"}, {binary, "1", "extra"}} {
		if _, _, code := runKeyvaultGuard(t, env, args...); code != 2 {
			t.Errorf("args %v: exit %d", args, code)
		}
	}
}

// Claim: a mac-keyvault process still blocks a rebuild after the file it was
// started from was replaced, although lsof now sees a different file:
// started by the path itself, or through an installed alias named
// mac-keyvault (like ~/.local/bin). Control: lsof alone no longer reports it.
func TestKeyvaultBuildGuardReplacedBinary(t *testing.T) {
	self, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, viaAlias := range []bool{false, true} {
		dir := t.TempDir()
		tools := t.TempDir()
		binary := filepath.Join(dir, "mac-keyvault")
		env := []string{"KEYVAULT_GUARD_LAUNCHCTL=" + fakeTool(t, tools, "launchctl-none", `echo "PID	Status	Label"`), scopedPS(t, tools, dir)}
		if err := os.WriteFile(binary, self, 0o755); err != nil {
			t.Fatal(err)
		}
		start := binary
		if viaAlias {
			start = filepath.Join(dir, "alias", "mac-keyvault")
			os.Mkdir(filepath.Dir(start), 0o700)
			if err := os.Symlink(binary, start); err != nil {
				t.Fatal(err)
			}
		}
		startStandIn(t, start)
		waitRefusal(t, env, binary, "a running process uses it")
		replacement := filepath.Join(dir, "next")
		if err := os.WriteFile(replacement, self, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(replacement, binary); err != nil {
			t.Fatal(err)
		}
		if out, _ := exec.Command("/usr/sbin/lsof", "-t", "--", binary).Output(); len(out) != 0 {
			t.Fatalf("control: lsof still sees a process on the replaced file: %s", out)
		}
		waitRefusal(t, env, binary, "a mac-keyvault process is running")
	}
}

// TestKeyvaultGuardSleepHelper is the long-running stand-in process; it does
// nothing unless started by the guard tests.
func TestKeyvaultGuardSleepHelper(t *testing.T) {
	if os.Getenv("MAC_INFRA_GUARD_SLEEP_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
}
