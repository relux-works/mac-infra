//go:build darwin && cgo

package firewallwatch

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// printedName is the name nettop prints for pid: the kernel name cut at 15
// bytes.
func printedName(t *testing.T, pid int) string {
	t.Helper()
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		t.Fatal(err)
	}
	n := comm(kp)
	if len(n) > nettopNameLen {
		n = n[:nettopNameLen]
	}
	return n
}

func realPath(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The real resolver confirms this process by its printed name and returns
// its executable; a name that is not its own, or a pid that has exited,
// gives "" (not confirmed).
func TestResolveProcessPathOwnAndExited(t *testing.T) {
	exe, _ := os.Executable()
	got := resolveProcessPath(os.Getpid(), printedName(t, os.Getpid()))
	if got == "" || realPath(t, got) != realPath(t, exe) {
		t.Fatalf("own process: %q, want %q", got, exe)
	}
	if p := resolveProcessPath(os.Getpid(), "notmyname"); p != "" {
		t.Fatalf("a wrong name was confirmed: %q", p)
	}
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if p := resolveProcessPath(cmd.Process.Pid, "true"); p != "" {
		t.Fatalf("an exited pid was confirmed: %q", p)
	}
}

// TestHelperSleep is not a test: run as a renamed copy of the test binary
// with procpathSleepEnv set, it just stays alive for the long-name case. (A
// renamed copy of a platform binary such as /bin/sleep is killed at exec.)
func TestHelperSleep(t *testing.T) {
	if os.Getenv(procpathSleepEnv) == "" {
		t.Skip("helper process only")
	}
	time.Sleep(5 * time.Second)
}

const procpathSleepEnv = "FIREWALLWATCH_PROCPATH_SLEEP"

// A process whose name is longer than nettop prints is confirmed by its
// 15-byte cut, and its executable (a renamed copy of this test binary) is
// returned; a shorter printed name is not accepted as a prefix.
func TestResolveProcessPathLongName(t *testing.T) {
	dir := t.TempDir()
	long := filepath.Join(dir, "averyveryverylongprocessname")
	exe, _ := os.Executable()
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(long, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(long, "-test.run=^TestHelperSleep$")
	cmd.Env = append(os.Environ(), procpathSleepEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	time.Sleep(200 * time.Millisecond)
	printed := printedName(t, cmd.Process.Pid)
	if len(printed) != nettopNameLen {
		t.Fatalf("printed name %q is not cut", printed)
	}
	got := resolveProcessPath(cmd.Process.Pid, printed)
	if got == "" || realPath(t, got) != realPath(t, long) {
		t.Fatalf("long name: %q, want %q", got, long)
	}
	if p := resolveProcessPath(cmd.Process.Pid, printed[:10]); p != "" {
		t.Fatalf("a shorter printed name was confirmed by prefix: %q", p)
	}
}

// Another non-root user's process (a per-user service account) resolves
// like any other; skipped when no such process runs on this host.
func TestResolveProcessPathOtherNonRootUser(t *testing.T) {
	out, err := exec.Command("/bin/ps", "-axo", "pid=,uid=").Output()
	if err != nil {
		t.Fatal(err)
	}
	me := os.Getuid()
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		pid, _ := strconv.Atoi(f[0])
		uid, _ := strconv.Atoi(f[1])
		if pid <= 1 || uid == 0 || uid == me {
			continue
		}
		kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
		if err != nil || kp.Proc.P_pid != int32(pid) {
			continue
		}
		name := comm(kp)
		if len(name) > nettopNameLen {
			name = name[:nettopNameLen]
		}
		if got := resolveProcessPath(pid, name); got == "" || !filepath.IsAbs(got) {
			t.Fatalf("uid %d pid %d (%s): %q", uid, pid, name, got)
		}
		return
	}
	t.Skip("no process of another non-root user runs here")
}
