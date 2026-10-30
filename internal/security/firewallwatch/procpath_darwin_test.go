//go:build darwin && cgo

package firewallwatch

import (
	"context"
	"debug/macho"
	"encoding/binary"
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
// its executable and a running image hash; a name that is not its own, or a
// pid that has exited, gives the zero value (not confirmed).
func TestResolveProcessImageOwnAndExited(t *testing.T) {
	exe, _ := os.Executable()
	got := resolveProcessImage(os.Getpid(), printedName(t, os.Getpid()))
	if got.Path == "" || realPath(t, got.Path) != realPath(t, exe) || !validCDHash(got.CDHash) {
		t.Fatalf("own process: %q, want %q", got, exe)
	}
	if p := resolveProcessImage(os.Getpid(), "notmyname"); p != (processImage{}) {
		t.Fatalf("a wrong name was confirmed: %q", p)
	}
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if p := resolveProcessImage(cmd.Process.Pid, "true"); p != (processImage{}) {
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
func TestResolveProcessImageLongName(t *testing.T) {
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
	got := resolveProcessImage(cmd.Process.Pid, printed)
	if got.Path == "" || realPath(t, got.Path) != realPath(t, long) {
		t.Fatalf("long name: %q, want %q", got, long)
	}
	if p := resolveProcessImage(cmd.Process.Pid, printed[:10]); p != (processImage{}) {
		t.Fatalf("a shorter printed name was confirmed by prefix: %q", p)
	}
}

// Another non-root user's process (a per-user service account) resolves
// like any other; skipped when no such process runs on this host.
func TestResolveProcessImageOtherNonRootUser(t *testing.T) {
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
		if got := resolveProcessImage(pid, name); got.Path == "" || !filepath.IsAbs(got.Path) {
			t.Fatalf("uid %d pid %d (%s): %q", uid, pid, name, got)
		}
		return
	}
	t.Skip("no process of another non-root user runs here")
}

// startHelper runs a copy of this test binary at path as a sleeping helper and
// returns its pid; the process is killed and reaped at the end of the test.
func startHelper(t *testing.T, path string) int {
	t.Helper()
	exe, _ := os.Executable()
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(path, "-test.run=^TestHelperSleep$")
	cmd.Env = append(os.Environ(), procpathSleepEnv+"=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	time.Sleep(200 * time.Millisecond)
	return cmd.Process.Pid
}

// The kernel's image hash for a running process equals the hash in the
// signature of the file it runs, so the real resolver and the real signature
// inspector agree and the file's signer (ad-hoc, the linker's) is attested
// (control for the cases below).
func TestRunningImageHashMatchesSignature(t *testing.T) {
	path := filepath.Join(t.TempDir(), "imagehelper")
	pid := startHelper(t, path)
	img := resolveProcessImage(pid, printedName(t, pid))
	if img.Path == "" || !validCDHash(img.CDHash) {
		t.Fatalf("helper not resolved: %+v", img)
	}
	s, _ := journalStore(t)
	if got := s.runningSigner(context.Background(), img.Path, img.CDHash); got != "ad-hoc" {
		t.Fatalf("the helper's own file was attested as %q", got)
	}
}

// A file replaced after its process started does not lend its signer to the
// process: the path still resolves, the kernel keeps the running image's
// hash, and the Apple-signed replacement's hash differs, so the signer is
// "unknown" (PR81 review r1 got "Apple" here).
func TestReplacedExecutableNotAttested(t *testing.T) {
	path := filepath.Join(t.TempDir(), "com.apple.probe")
	pid := startHelper(t, path)
	before := resolveProcessImage(pid, printedName(t, pid))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	apple, err := os.ReadFile("/bin/ls")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, apple, 0o755); err != nil {
		t.Fatal(err)
	}
	after := resolveProcessImage(pid, printedName(t, pid))
	if after.Path == "" || after.CDHash != before.CDHash {
		t.Fatalf("resolution changed: %+v -> %+v", before, after)
	}
	s, _ := journalStore(t)
	ctx := context.Background()
	if got := s.signer(ctx, after.Path); got != "Apple" {
		t.Fatalf("fixture: the replacement file is %q, not Apple", got)
	}
	if got := s.runningSigner(ctx, after.Path, after.CDHash); got != "unknown" {
		t.Fatalf("replaced file attested the process as %q", got)
	}
}

// unsignedCopy returns this test binary's bytes with the ad-hoc flag cleared
// in its code directory: a code directory without a CMS signature that the
// kernel still runs, which codesign reports as "no signature".
func unsignedCopy(t *testing.T) []byte {
	t.Helper()
	exe, _ := os.Executable()
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := macho.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	for _, l := range mf.Loads {
		r := l.Raw()
		if mf.ByteOrder.Uint32(r[:4]) != 0x1d { // LC_CODE_SIGNATURE
			continue
		}
		sig := int(mf.ByteOrder.Uint32(r[8:12]))
		count := int(binary.BigEndian.Uint32(data[sig+8 : sig+12]))
		for i := 0; i < count; i++ {
			idx := sig + 12 + i*8
			if binary.BigEndian.Uint32(data[idx:idx+4]) != 0 { // CSSLOT_CODEDIRECTORY
				continue
			}
			cd := sig + int(binary.BigEndian.Uint32(data[idx+4:idx+8]))
			flags := binary.BigEndian.Uint32(data[cd+12 : cd+16])
			binary.BigEndian.PutUint32(data[cd+12:cd+16], flags&^2)
			return data
		}
	}
	t.Fatal("code directory missing")
	return nil
}

// A file whose name carries codesign text (PR81 review r2) does not borrow
// that text as its signer: a running copy named with Apple authority lines, or
// with a newline-injected Developer ID line, is attested as what its signature
// says, "no designated requirement", the same as the same bytes under an
// ordinary name (control). Its event is not Apple noise, and the injected
// name reaches neither the signer nor the classifier's rendering.
func TestForgedNameNotAttested(t *testing.T) {
	data := unsignedCopy(t)
	ctx := context.Background()
	for _, name := range []string{"ordinary-probe", "com.apple.probe Authority=Software Signing Authority=Apple Root CA", "probe\nAuthority=Developer ID Application: PRIVATE_PATH_MARKER\n"} {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, data, 0o755); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(path, "-test.run=^TestHelperSleep$")
		cmd.Env = append(os.Environ(), procpathSleepEnv+"=1")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
		time.Sleep(200 * time.Millisecond)
		img := resolveProcessImage(cmd.Process.Pid, printedName(t, cmd.Process.Pid))
		if img.Path == "" || !validCDHash(img.CDHash) {
			t.Fatalf("%q: not resolved: %+v", name, img)
		}
		s, _ := journalStore(t)
		got := s.runningSigner(ctx, img.Path, img.CDHash)
		if got != "no designated requirement" {
			t.Fatalf("%q attested as %q", name, got)
		}
		port := 443
		it := Item{Source: "nettop", Kind: "outbound", App: printedName(t, cmd.Process.Pid), Verdict: "observed", Remote: "lan", RemotePort: &port, Count: 1, Path: img.Path, ImageCDHash: img.CDHash}
		if !s.collect(ctx, &Classifier{}, it) {
			t.Fatalf("%q: no event", name)
		}
		e := s.State.Events[len(s.State.Events)-1]
		it.Signer = e.Signer
		if e.Signer != got || e.Label == "noise" || strings.Contains(Render(it), "PRIVATE_PATH_MARKER") {
			t.Fatalf("%q: event signer %q label %q rendering %s", name, e.Signer, e.Label, Render(it))
		}
	}
}

// The signature inspector agrees with codesign's text on files whose names
// carry no text: Apple binaries, this ad-hoc test binary, an unsigned file and
// the applications installed here (Developer ID and App Store when present),
// and it reports a missing file as an error. Limit: the applications vary by
// host.
func TestStaticCodeFactsMatchText(t *testing.T) {
	exe, _ := os.Executable()
	want := map[string]string{"/bin/ls": "Apple", "/sbin/launchd": "Apple", exe: "ad-hoc", "/etc/hosts": "unsigned"}
	apps, _ := filepath.Glob("/Applications/*.app")
	seen := map[string]bool{}
	for _, p := range append([]string{"/bin/ls", "/sbin/launchd", exe, "/etc/hosts"}, apps...) {
		if strings.ContainsAny(p, "\n=") {
			continue
		}
		f, err := staticCodeFacts(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		text, err := inspectSigner(context.Background(), p)
		if err != nil {
			continue
		}
		if f.Signer != text.Signer || (want[p] != "" && f.Signer != want[p]) {
			t.Fatalf("%s: signature %q, text %q, want %q", p, f.Signer, text.Signer, want[p])
		}
		if f.Signer != "unsigned" && !validCDHash(f.CDHash) {
			t.Fatalf("%s: hash %q", p, f.CDHash)
		}
		seen[strings.SplitN(f.Signer, ":", 2)[0]] = true
	}
	t.Logf("kinds seen: %v", seen)
	if _, err := staticCodeFacts(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing file had facts")
	}
}
