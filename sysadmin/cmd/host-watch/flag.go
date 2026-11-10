package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(raw, '\n'), 0o644)
}

func removeDegradedFlag(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
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
