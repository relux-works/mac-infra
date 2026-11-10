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
	dir, name, err := openFlagDir(path, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	// Exclusive temporary file and rename, both through the anchored directory handle.
	var tmp string
	var fh *os.File
	for i := 0; ; i++ {
		tmp = fmt.Sprintf(".%s.tmp-%d-%d", name, os.Getpid(), time.Now().UnixNano()+int64(i))
		fh, err = dir.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err == nil || !errors.Is(err, os.ErrExist) || i > 5 {
			break
		}
	}
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = dir.Remove(tmp)
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
	if err := dir.Rename(tmp, name); err != nil {
		return err
	}
	ok = true
	return nil
}

func removeDegradedFlag(path string) error {
	dir, name, err := openFlagDir(path, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// flagPresentAnchored reports whether the flag file exists, looked up through the anchored path.
func flagPresentAnchored(path string) bool {
	dir, name, err := openFlagDir(path, false)
	if err != nil {
		return false
	}
	defer dir.Close()
	_, err = dir.Lstat(name)
	return err == nil
}

// flagDirHook lets tests interleave a change between the check and the open of a component.
var flagDirHook func(component string)

// openFlagDir opens the directory of the flag through handles anchored at the home directory: each
// component below home is checked with Lstat to be a real directory, opened as a new root, and the
// opened directory must be the same file that was checked. Every later lookup and mutation goes
// through the returned handle, so a component replaced by a symlink after the check is never
// followed. With create, missing components are created inside the anchored parent.
func openFlagDir(path string, create bool) (*os.Root, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", err
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, "", fmt.Errorf("flag path %s is outside the home directory", path)
	}
	parts := splitPath(rel)
	if len(parts) < 1 {
		return nil, "", fmt.Errorf("flag path %s has no file name", path)
	}
	r, err := os.OpenRoot(home)
	if err != nil {
		return nil, "", err
	}
	for _, comp := range parts[:len(parts)-1] {
		fi, err := r.Lstat(comp)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := r.Mkdir(comp, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				r.Close()
				return nil, "", err
			}
			fi, err = r.Lstat(comp)
		}
		if err != nil {
			r.Close()
			return nil, "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			r.Close()
			return nil, "", fmt.Errorf("flag path component %s is a symlink or not a directory", comp)
		}
		if flagDirHook != nil {
			flagDirHook(comp)
		}
		next, err := r.OpenRoot(comp)
		r.Close()
		if err != nil {
			return nil, "", err
		}
		opened, err := next.Stat(".")
		if err != nil || !os.SameFile(fi, opened) {
			next.Close()
			return nil, "", fmt.Errorf("flag path component %s changed between check and open", comp)
		}
		r = next
	}
	return r, parts[len(parts)-1], nil
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

// checkNoSymlinks refuses a flag path whose existing components below the home directory (the
// host-health directories and the flag itself) are symlinks, so the file written is the file
// consumers read.
func checkNoSymlinks(path string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == "../" {
		return fmt.Errorf("flag path %s is outside the home directory", path)
	}
	cur := home
	for _, part := range splitPath(rel) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("flag path component %s is a symlink", cur)
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
