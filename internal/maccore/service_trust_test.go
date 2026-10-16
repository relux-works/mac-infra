//go:build darwin && cgo

package maccore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type trustFixture struct {
	root               *os.File
	dir, binary, plist string
	cfg                ServiceConfig
	trust              DaemonTrust
}

func newTrustFixture(t *testing.T) trustFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "helpers"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	f := trustFixture{root: root, dir: dir, binary: filepath.Join(dir, "helpers", "core"), plist: filepath.Join(dir, "core.plist"), cfg: DefaultServiceConfig()}
	writeTrustFixture(t, f.binary, []byte("reviewed executable fixture"), 0o755)
	writeTrustFixture(t, f.plist, nil, 0o644)
	hash := sha256.Sum256([]byte("reviewed executable fixture"))
	binaryInfo, _ := os.Stat(f.binary)
	plistInfo, _ := os.Stat(f.plist)
	f.trust = DaemonTrust{BinarySHA256: hex.EncodeToString(hash[:]), BinaryIdentity: fileIdentity(binaryInfo), PlistIdentity: fileIdentity(plistInfo)}
	writeTrustFixture(t, f.plist, RenderServicePlist(f.cfg, defaultServiceBinaryPath, os.Getuid(), os.Getgid(), f.trust), 0o644)
	return f
}

func writeTrustFixture(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func (f trustFixture) verify() error {
	// Tests trust only the fixture root and descendants, owned by the test user;
	// production starts at / and requires UID 0 for every component.
	binary, err := openTrustedAt(f.root, "helpers/core", false, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer binary.Close()
	plist, err := openTrustedAt(f.root, "core.plist", false, uint32(os.Getuid()))
	if err != nil {
		return err
	}
	defer plist.Close()
	return verifyInstalledFiles(binary, plist, f.cfg, defaultServiceBinaryPath, os.Getuid(), os.Getgid(), f.trust)
}

// The same descriptor-based checker accepts a protected positive control and
// rejects writable objects/ancestors, symlinks, aliases, inode replacement,
// changed bytes and changed launchd settings. No root ownership is simulated.
func TestInstalledTrustPositiveAndNegativeControls(t *testing.T) {
	cases := []struct {
		name, want string
		mutate     func(*testing.T, trustFixture)
	}{
		{name: "protected control"},
		{name: "group writable binary", want: "writable permissions", mutate: func(t *testing.T, f trustFixture) { mustChmod(t, f.binary, 0o775) }},
		{name: "world writable config", want: "writable permissions", mutate: func(t *testing.T, f trustFixture) { mustChmod(t, f.plist, 0o666) }},
		{name: "writable ancestor", want: "writable permissions", mutate: func(t *testing.T, f trustFixture) { mustChmod(t, filepath.Dir(f.binary), 0o775) }},
		{name: "writable fixture root", want: "writable permissions", mutate: func(t *testing.T, f trustFixture) { mustChmod(t, f.dir, 0o777) }},
		{name: "symlink binary", want: "open trusted", mutate: func(t *testing.T, f trustFixture) { replaceWithSymlink(t, f.binary) }},
		{name: "symlink config", want: "open trusted", mutate: func(t *testing.T, f trustFixture) { replaceWithSymlink(t, f.plist) }},
		{name: "symlink ancestor", want: "open trusted", mutate: func(t *testing.T, f trustFixture) { replaceWithSymlink(t, filepath.Dir(f.binary)) }},
		{name: "replaced binary same bytes", want: "identity changed", mutate: func(t *testing.T, f trustFixture) { replaceSameBytes(t, f.binary) }},
		{name: "replaced config same bytes", want: "identity changed", mutate: func(t *testing.T, f trustFixture) { replaceSameBytes(t, f.plist) }},
		{name: "changed binary same inode", want: "digest changed", mutate: func(t *testing.T, f trustFixture) { writeTrustFixture(t, f.binary, []byte("modified binary"), 0o755) }},
		{name: "changed config same inode", want: "configuration changed", mutate: func(t *testing.T, f trustFixture) { writeTrustFixture(t, f.plist, []byte("modified config"), 0o644) }},
		{name: "hard linked binary", want: "multiple hard links", mutate: func(t *testing.T, f trustFixture) {
			if err := os.Link(f.binary, f.binary+".alias"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "wrong expected client", want: "configuration changed", mutate: func(t *testing.T, f trustFixture) {
			writeTrustFixture(t, f.plist, RenderServicePlist(f.cfg, defaultServiceBinaryPath, os.Getuid()+1, os.Getgid(), f.trust), 0o644)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newTrustFixture(t)
			if err := f.verify(); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			if tc.mutate != nil {
				tc.mutate(t, f)
			}
			err := f.verify()
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func replaceWithSymlink(t *testing.T, path string) {
	t.Helper()
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
}

func replaceSameBytes(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	writeTrustFixture(t, path+".replacement", data, info.Mode().Perm())
	if err := os.Rename(path+".replacement", path); err != nil {
		t.Fatal(err)
	}
}

// A real ACL grant on an isolated fixture is a bounded checker control: mode
// 0755 alone must not admit a file or ancestor that grants extended write access.
func TestTrustRejectsExtendedACL(t *testing.T) {
	for _, target := range []string{"binary", "config", "ancestor"} {
		t.Run(target, func(t *testing.T) {
			f := newTrustFixture(t)
			if err := f.verify(); err != nil {
				t.Fatal(err)
			}
			path := map[string]string{"binary": f.binary, "config": f.plist, "ancestor": filepath.Dir(f.binary)}[target]
			if output, err := exec.Command("/bin/chmod", "+a", "everyone allow write", path).CombinedOutput(); err != nil {
				t.Fatalf("fixture ACL control failed: %v: %s", err, output)
			}
			if err := f.verify(); err == nil || !strings.Contains(err.Error(), "extended ACL") {
				t.Fatalf("ACL grant admitted or failed for unrelated reason: %v", err)
			}
		})
	}
}

// Harmless deny-only/read-only ACLs remain usable. Each positive grant control
// is followed by a real write grant which must fail for that exact ACL reason.
func TestTrustAllowsHarmlessACLs(t *testing.T) {
	for _, acl := range []string{"everyone deny delete", "everyone allow read"} {
		t.Run(acl, func(t *testing.T) {
			f := newTrustFixture(t)
			path := filepath.Dir(f.binary)
			t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", path).Run() })
			if out, err := exec.Command("/bin/chmod", "+a", acl, path).CombinedOutput(); err != nil {
				t.Fatalf("fixture ACL: %v: %s", err, out)
			}
			if err := f.verify(); err != nil {
				t.Fatalf("harmless ACL denied: %v", err)
			}
			if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write", path).CombinedOutput(); err != nil {
				t.Fatalf("fixture ACL: %v: %s", err, out)
			}
			if err := f.verify(); err == nil || !strings.Contains(err.Error(), "extended ACL grants modification") {
				t.Fatalf("write ACL not rejected: %v", err)
			}
		})
	}
}

// Ownership mismatches and path escape syntax fail closed at the fixture root.
func TestTrustRejectsWrongOwnerAndEscapes(t *testing.T) {
	f := newTrustFixture(t)
	if _, err := openTrustedAt(f.root, "helpers/core", false, uint32(os.Getuid()+1)); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("wrong owner: %v", err)
	}
	for _, path := range []string{"", "../core", "helpers/../core", "/core"} {
		if _, err := openTrustedAt(f.root, path, false, uint32(os.Getuid())); err == nil || !strings.Contains(err.Error(), "invalid trust-relative") {
			t.Fatalf("path %q: %v", path, err)
		}
	}
}

// Refusal happens before socket creation when the root daemon is invoked with
// alternate paths or without a pinned installation. No privileged work runs.
func TestRunDaemonRejectsUninstalledInvocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sock")
	err := RunDaemon(ServiceConfig{SocketPath: path}, os.Getuid(), os.Getgid(), DaemonTrust{})
	if err == nil || !strings.Contains(err.Error(), "refusing untrusted") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket created: %v", err)
	}
}

// Alternate paths and root/missing client identity are rejected before any
// sudo command; uninstall also refuses alternate service paths.
func TestInstallAndUninstallRejectAlternateScope(t *testing.T) {
	for _, tc := range []struct {
		cfg      ServiceConfig
		uid, gid int
	}{
		{ServiceConfig{}, os.Getuid(), os.Getgid()},
		{DefaultServiceConfig(), 0, os.Getgid()},
		{DefaultServiceConfig(), os.Getuid(), -1},
	} {
		if err := InstallService(tc.cfg, "/not-opened", tc.uid, tc.gid, InstallOptions{}); err == nil || !strings.Contains(err.Error(), "fixed service paths") {
			t.Fatalf("invalid install scope: %v", err)
		}
	}
	if err := UninstallService(ServiceConfig{}); err == nil || !strings.Contains(err.Error(), "fixed installed service paths") {
		t.Fatalf("invalid uninstall scope: %v", err)
	}
}

// Unexpected regular files and symlinks at the socket name survive refusal.
// A stale socket owned by this test user remains a valid cleanup control.
func TestStaleSocketBoundary(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "socket")
		writeTrustFixture(t, path, []byte("keep"), 0o600)
		if symlink {
			replaceWithSymlink(t, path)
		}
		if err := removeStaleSocket(path, os.Getuid()); err == nil {
			t.Fatal("unexpected entry removed")
		}
		if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
			t.Fatalf("entry changed: %v", err)
		}
	}
	path := tempSocketPath(t, "trust-stale")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := removeStaleSocket(path, os.Getuid()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("stale socket remains: %v", err)
	}
}

// Kernel-reported peer UID admits this user and denies a different configured
// user even if filesystem socket permissions would permit the connection.
func TestSocketPeerUIDBoundary(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is intentionally authorized for administration")
	}
	path := tempSocketPath(t, "trust-peer")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	errors := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errors <- err
			return
		}
		defer conn.Close()
		if err := requireSocketPeer(conn, os.Getuid()); err != nil {
			errors <- err
			return
		}
		if err := requireSocketPeer(conn, os.Getuid()+1); err == nil {
			errors <- fmt.Errorf("different client UID admitted")
			return
		}
		errors <- nil
	}()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := <-errors; err != nil {
		t.Fatal(err)
	}
}
