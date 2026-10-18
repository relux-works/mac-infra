//go:build unix

package keyvault

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const oNoFollow = syscall.O_NOFOLLOW

// requireOwnedDir refuses a directory that is a symlink, not a directory,
// owned by someone else, or open to group or other.
func requireOwnedDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%s is not a plain directory", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by this user", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is open to group or other (mode %o)", path, info.Mode().Perm())
	}
	return nil
}

// requireOwnedFile refuses a path that is a symlink or not a regular file.
// A private file must belong to this user with no group or other bits; an
// executable (private false) must belong to this user or root and be
// writable by neither group nor other.
func requireOwnedFile(path string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	name := filepath.Base(path)
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", name)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: owner unknown", name)
	}
	owner := int(stat.Uid)
	switch {
	case private && owner != os.Getuid():
		return fmt.Errorf("%s is not owned by this user", name)
	case private && info.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s is open to group or other (mode %o)", name, info.Mode().Perm())
	case !private && owner != os.Getuid() && owner != 0:
		return fmt.Errorf("%s is owned by uid %d", name, owner)
	case !private && info.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by group or other (mode %o)", name, info.Mode().Perm())
	}
	return nil
}
