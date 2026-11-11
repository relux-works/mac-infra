package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// degradedFlag is the exec-degraded flag file contract (sysadmin/docs/host-health-degraded-flag.md).
// Present means: do not start a new heavy lane. Absent means: proceed. Running work is untouched.
type degradedFlag struct {
	Reason       string `json:"reason"`
	Since        string `json:"since"`
	HostWatchPID int    `json:"host_watch_pid"`
}

// canonicalFlagPath is the one flag path of the contract; consumers read it and nothing else.
func canonicalFlagPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "host-health", "exec-degraded"), nil
}

func writeDegradedFlag(path string, f degradedFlag) error {
	dirfd, name, err := openFlagDir(path, true)
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	// Exclusive temporary file and rename, both relative to the anchored directory descriptor.
	var tmp string
	var tfd int
	for i := 0; ; i++ {
		tmp = fmt.Sprintf(".%s.tmp-%d-%d", name, os.Getpid(), time.Now().UnixNano()+int64(i))
		tfd, err = unix.Openat(dirfd, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
		if err == nil || !errors.Is(err, unix.EEXIST) || i > 5 {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("flag temp file: %w", err)
	}
	fh := os.NewFile(uintptr(tfd), tmp)
	ok := false
	defer func() {
		if !ok {
			_ = unix.Unlinkat(dirfd, tmp, 0)
		}
	}()
	if _, err := fh.Write(append(raw, '\n')); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Chmod(0o644); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(dirfd, tmp, dirfd, name); err != nil {
		return fmt.Errorf("flag rename: %w", err)
	}
	ok = true
	return nil
}

// removeDegradedFlag removes the entry at the flag name with one unlinkat relative to the anchored
// directory descriptor. unlinkat never follows a symlink: a symlink at the flag name is removed as
// an entry and its target is never touched; a directory there is refused by the kernel. There is
// no separate check before the unlink, so there is no check/use gap at the leaf.
func removeDegradedFlag(path string) error {
	dirfd, name, err := openFlagDir(path, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(dirfd)
	if err := unix.Unlinkat(dirfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("flag removal: %w", err)
	}
	return nil
}

// flagPresentAnchored reports whether the flag is present as a regular file, looked up through the
// anchored directory without following a final symlink. A dangling or any other symlink is not the
// flag, which matches what a consumer's `test -e` sees for a dangling link.
func flagPresentAnchored(path string) bool {
	dirfd, name, err := openFlagDir(path, false)
	if err != nil {
		return false
	}
	defer unix.Close(dirfd)
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG
}

// flagDirHook lets tests interleave a change just before a component is opened.
var flagDirHook func(component string)

// openFlagDir opens the directory of the flag component by component, starting at the home
// directory: every component below home is opened relative to its parent descriptor with
// O_NOFOLLOW and O_DIRECTORY, so a symlink at any component is refused at the moment of opening,
// whatever it points to. With create, a missing component is created relative to its parent
// descriptor. The caller performs every later operation relative to the returned descriptor.
func openFlagDir(path string, create bool) (int, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return -1, "", err
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return -1, "", fmt.Errorf("flag path %s is outside the home directory", path)
	}
	parts := splitPath(rel)
	if len(parts) < 1 {
		return -1, "", fmt.Errorf("flag path %s has no file name", path)
	}
	fd, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", fmt.Errorf("open home: %w", err)
	}
	const dirFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	for _, comp := range parts[:len(parts)-1] {
		if flagDirHook != nil {
			flagDirHook(comp)
		}
		next, err := unix.Openat(fd, comp, dirFlags, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if merr := unix.Mkdirat(fd, comp, 0o755); merr != nil && !errors.Is(merr, unix.EEXIST) {
				unix.Close(fd)
				return -1, "", fmt.Errorf("create %s: %w", comp, merr)
			}
			next, err = unix.Openat(fd, comp, dirFlags, 0)
		}
		unix.Close(fd)
		if errors.Is(err, unix.ENOENT) {
			return -1, "", fmt.Errorf("%s: %w", comp, os.ErrNotExist)
		}
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return -1, "", fmt.Errorf("flag path component %s is a symlink or not a directory", comp)
		}
		if err != nil {
			return -1, "", fmt.Errorf("open %s: %w", comp, err)
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

// atomicWrite publishes data at path through an exclusive temporary file in the same directory,
// so a pre-existing temporary path (including a symlink) is never followed and the final mode is
// exactly mode.
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// ensurePrivateDir creates dir with mode 0700, or tightens an existing directory owned by us to
// 0700; a symlink or a directory owned by someone else is refused.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("state dir %s is not a plain directory", dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("state dir %s is owned by uid %d, not us", dir, st.Uid)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("state dir %s: %w", dir, err)
		}
	}
	return nil
}

func splitPath(rel string) []string {
	var parts []string
	for rel != "." && rel != "" {
		dir, file := filepath.Split(rel)
		parts = append([]string{file}, parts...)
		rel = filepath.Clean(dir)
		if dir == "" {
			break
		}
	}
	return parts
}
