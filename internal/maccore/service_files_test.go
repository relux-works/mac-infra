//go:build darwin && cgo

package maccore

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

type installFixture struct {
	dir       string
	root      *os.File
	calls     []string
	ops       installationOps
	fail      string
	moves     int
	failMoves map[int]bool
}

func newInstallFixture(t *testing.T) *installFixture {
	t.Helper()
	f := &installFixture{dir: t.TempDir()}
	for _, path := range []string{"/Library/PrivilegedHelperTools", "/Library/LaunchDaemons"} {
		if err := os.MkdirAll(f.path(path), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	f.root, err = os.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.root.Close() })
	f.ops = installationOps{
		open: func(path string, directory bool) (*os.File, error) {
			return openTrustedAt(f.root, strings.TrimPrefix(path, "/"), directory, uint32(os.Getuid()))
		},
		lstat:   func(path string) (os.FileInfo, error) { return os.Lstat(f.path(path)) },
		command: f.command,
	}
	return f
}

func (f *installFixture) path(path string) string {
	return filepath.Join(f.dir, strings.TrimPrefix(path, "/"))
}

// This backend models filesystem effects in a disposable current-user tree.
// It never executes shell programs, sudo, launchctl, chown or privileged installs.
func (f *installFixture) command(input []byte, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if name == "/bin/mv" {
		f.moves++
		if f.failMoves[f.moves] {
			return nil, fmt.Errorf("injected publication failure %d", f.moves)
		}
	}
	if name == f.fail {
		return nil, fmt.Errorf("injected %s failure", name)
	}
	switch name {
	case "/usr/bin/install":
		return nil, os.Mkdir(f.path(args[len(args)-1]), 0o755)
	case "/usr/bin/mktemp":
		dir, err := os.MkdirTemp(f.path(defaultServiceDirectory), ".install.")
		return []byte(strings.TrimPrefix(dir, f.dir) + "\n"), err
	case "/bin/sh":
		if len(args) != 4 || args[0] != "-c" || args[1] != `umask 077; /bin/cat > "$1"` || args[2] != "mac-infra-stage" {
			return nil, fmt.Errorf("unexpected shell program")
		}
		return nil, os.WriteFile(f.path(args[3]), input, 0o600)
	case "/usr/sbin/chown":
		if args[0] != "0:0" {
			return nil, fmt.Errorf("unexpected ownership")
		}
		return nil, nil // Actual fixture owner stays the normal test user.
	case "/bin/chmod":
		mode, err := strconv.ParseUint(args[0], 8, 32)
		if err != nil {
			return nil, err
		}
		return nil, os.Chmod(f.path(args[1]), os.FileMode(mode))
	case "/usr/bin/stat":
		info, err := os.Stat(f.path(args[2]))
		if err != nil {
			return nil, err
		}
		if args[1] == "%d" {
			return []byte(fmt.Sprintf("%d\n", info.Sys().(*syscall.Stat_t).Dev)), nil
		}
		if args[1] != "%i:%B" {
			return nil, fmt.Errorf("unexpected stat format")
		}
		return []byte(fileIdentity(info) + "\n"), nil
	case "/bin/mv":
		return nil, os.Rename(f.path(args[1]), f.path(args[2]))
	case "/bin/rm":
		for _, path := range args[1:] {
			if err := os.Remove(f.path(path)); err != nil && !os.IsNotExist(err) {
				return nil, err
			}
		}
		return nil, nil
	case "/bin/rmdir":
		return nil, os.Remove(f.path(args[0]))
	default:
		return nil, fmt.Errorf("unapproved fixture command: %s", name)
	}
}

// Safe installation copies the supplied reviewed bytes, emits only the fixed
// installed executable/socket paths and pins both inodes and the binary digest.
// A reinstall retains this behavior; these fixtures do not prove live sudo or
// launchd integration, actual root ownership, or crash-atomic two-file updates.
func TestInstallReviewedSnapshotSafeAndRepeatable(t *testing.T) {
	f := newInstallFixture(t)
	for _, snapshot := range []string{"first reviewed executable", "updated reviewed executable"} {
		if err := installReviewedSnapshot([]byte(snapshot), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops); err != nil {
			t.Fatal(err)
		}
		binary, err := os.ReadFile(f.path(defaultServiceBinaryPath))
		if err != nil || string(binary) != snapshot {
			t.Fatalf("installed binary: %q, %v", binary, err)
		}
		plist, err := os.ReadFile(f.path(defaultServicePlistPath))
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{defaultServiceBinaryPath, defaultServiceSocketPath, "--binary-sha256", "--binary-id", "--plist-id"} {
			if !strings.Contains(string(plist), required) {
				t.Fatalf("plist missing %q", required)
			}
		}
		if strings.Contains(string(plist), f.dir) || strings.Contains(string(plist), "/Users/") {
			t.Fatal("user path in root plist")
		}
		for path, want := range map[string]os.FileMode{defaultServiceBinaryPath: 0o755, defaultServicePlistPath: 0o644, defaultServiceDirectory: 0o755} {
			info, err := os.Stat(f.path(path))
			if err != nil || info.Mode().Perm() != want {
				t.Fatalf("mode %s: %v, %v", path, info, err)
			}
		}
		stages, _ := filepath.Glob(f.path(defaultServiceDirectory) + "/.install.*")
		if len(stages) != 0 {
			t.Fatalf("staging directories left: %v", stages)
		}
	}
	for _, command := range f.calls {
		if strings.Contains(command, "sudo") || strings.Contains(command, "launchctl") {
			t.Fatalf("privileged fixture command: %s", command)
		}
	}
}

// Existing writable or symlinked destinations/ancestors must stop before any
// staging or publication. The rejected object and its contents are preserved.
func TestInstallReviewedSnapshotRejectsUnsafeTree(t *testing.T) {
	for _, target := range []string{"ancestor", "binary", "plist", "binary symlink", "plist symlink"} {
		t.Run(target, func(t *testing.T) {
			f := newInstallFixture(t)
			if err := installReviewedSnapshot([]byte("original"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops); err != nil {
				t.Fatal(err)
			}
			path := f.path(defaultServiceBinaryPath)
			switch target {
			case "ancestor":
				path = f.path(defaultServiceDirectory)
				mustChmod(t, path, 0o775)
			case "binary":
				mustChmod(t, path, 0o777)
			case "plist":
				path = f.path(defaultServicePlistPath)
				mustChmod(t, path, 0o666)
			case "binary symlink":
				replaceWithSymlink(t, path)
			case "plist symlink":
				path = f.path(defaultServicePlistPath)
				replaceWithSymlink(t, path)
			}
			before, _ := os.ReadFile(f.path(defaultServiceBinaryPath))
			f.calls = nil
			err := installReviewedSnapshot([]byte("forbidden update"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops)
			if err == nil {
				t.Fatal("unsafe installation accepted")
			}
			if len(f.calls) != 0 {
				t.Fatalf("commands after unsafe tree: %v", f.calls)
			}
			after, _ := os.ReadFile(f.path(defaultServiceBinaryPath))
			if string(after) != string(before) {
				t.Fatal("rejected binary changed")
			}
		})
	}
}

// A failed staging write cannot publish either file and its private temporary
// directory is cleaned. No rollback of a live service is attempted by tests.
func TestInstallStagingFailureDoesNotPublish(t *testing.T) {
	f := newInstallFixture(t)
	f.fail = "/bin/sh"
	err := installReviewedSnapshot([]byte("reviewed"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops)
	if err == nil || !strings.Contains(err.Error(), "injected /bin/sh failure") {
		t.Fatalf("error=%v", err)
	}
	for _, path := range []string{defaultServiceBinaryPath, defaultServicePlistPath} {
		if _, err := os.Lstat(f.path(path)); !os.IsNotExist(err) {
			t.Fatalf("published %s", path)
		}
	}
	stages, _ := filepath.Glob(f.path(defaultServiceDirectory) + "/.install.*")
	if len(stages) != 0 {
		t.Fatalf("stage remains: %v", stages)
	}
}

// Publication or activation failure restores the original binary and plist
// bytes AND pinned inodes. This restores files, not a stopped launchd job.
func TestInstallFailureRestoresPreviousFiles(t *testing.T) {
	for _, failure := range []int{1, 2, 3, 4, 0} {
		t.Run(fmt.Sprintf("failure_%d", failure), func(t *testing.T) {
			f := newInstallFixture(t)
			if err := installReviewedSnapshot([]byte("previous"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops); err != nil {
				t.Fatal(err)
			}
			previous := map[string][]byte{}
			identities := map[string]string{}
			for _, path := range []string{defaultServiceBinaryPath, defaultServicePlistPath} {
				previous[path], _ = os.ReadFile(f.path(path))
				info, _ := os.Stat(f.path(path))
				identities[path] = fileIdentity(info)
			}
			f.moves = 0
			f.failMoves = map[int]bool{failure: true}
			err := installReviewedSnapshot([]byte("replacement"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops, func() error {
				return fmt.Errorf("injected activation failure")
			})
			if err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("error=%v", err)
			}
			for path, data := range previous {
				after, readErr := os.ReadFile(f.path(path))
				info, statErr := os.Stat(f.path(path))
				if readErr != nil || statErr != nil || string(after) != string(data) || fileIdentity(info) != identities[path] {
					t.Fatalf("previous installation not restored: %s; read=%v, stat=%v", path, readErr, statErr)
				}
			}
			stages, _ := filepath.Glob(f.path(defaultServiceDirectory) + "/.install.*")
			if len(stages) != 0 {
				t.Fatalf("stage remains after successful rollback: %v", stages)
			}
		})
	}
}

// A rollback failure must retain the original recovery inode in a private
// stage and identify that path; cleanup must not delete the remaining backup.
func TestInstallRollbackFailureRetainsRecoveryFiles(t *testing.T) {
	f := newInstallFixture(t)
	if err := installReviewedSnapshot([]byte("previous"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Stat(f.path(defaultServicePlistPath))
	f.moves = 0
	f.failMoves = map[int]bool{4: true, 5: true}
	err := installReviewedSnapshot([]byte("replacement"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops)
	if err == nil || !strings.Contains(err.Error(), "recovery files retained") {
		t.Fatalf("error=%v", err)
	}
	backups, _ := filepath.Glob(f.path(defaultServiceDirectory) + "/.install.*/previous.plist")
	if len(backups) != 1 {
		t.Fatalf("missing previous plist backup: %v", backups)
	}
	info, statErr := os.Stat(backups[0])
	if statErr != nil || fileIdentity(info) != fileIdentity(old) {
		t.Fatalf("backup identity: %v", statErr)
	}
}

// Cross-filesystem publication is rejected before any rename, since a copying
// mv fallback would change the inode pinned in launchd's arguments.
func TestInstallRejectsCrossFilesystemPublication(t *testing.T) {
	f := newInstallFixture(t)
	command := f.ops.command
	f.ops.command = func(input []byte, name string, args ...string) ([]byte, error) {
		if name == "/usr/bin/stat" && args[1] == "%d" && args[2] == filepath.Dir(defaultServicePlistPath) {
			return []byte("999999999\n"), nil
		}
		return command(input, name, args...)
	}
	err := installReviewedSnapshot([]byte("reviewed"), DefaultServiceConfig(), os.Getuid(), os.Getgid(), f.ops)
	if err == nil || !strings.Contains(err.Error(), "share the staging filesystem") {
		t.Fatalf("error=%v", err)
	}
	if f.moves != 0 {
		t.Fatalf("renamed files across filesystems: %d", f.moves)
	}
}

// Source snapshot accepts a bounded executable regular file and refuses a
// symlink, empty/nonexecutable file, FIFO and oversized file before elevation.
func TestReviewedExecutableSnapshotBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	writeTrustFixture(t, path, []byte("reviewed"), 0o755)
	data, err := readReviewedExecutable(path)
	if err != nil || string(data) != "reviewed" {
		t.Fatalf("positive control: %q, %v", data, err)
	}
	for _, variant := range []string{"symlink", "empty", "nonexecutable", "fifo", "oversized"} {
		t.Run(variant, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "core")
			writeTrustFixture(t, path, []byte("reviewed"), 0o755)
			switch variant {
			case "symlink":
				replaceWithSymlink(t, path)
			case "empty":
				writeTrustFixture(t, path, nil, 0o755)
			case "nonexecutable":
				mustChmod(t, path, 0o644)
			case "fifo":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(path, 0o755); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				if err := os.Truncate(path, maxReviewedExecutableSize+1); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := readReviewedExecutable(path); err == nil {
				t.Fatal("invalid source admitted")
			}
		})
	}
}
