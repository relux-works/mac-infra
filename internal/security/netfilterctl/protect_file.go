package netfilterctl

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// These trust rules mirror apps/netfilter/Shared/ProtectListFile.swift and
// must stay identical. rootDirectory is an explicit trust anchor; path is
// resolved within it (production always uses uid 0 and "/").
func readProtectList(path string, expectedUID uint32, rootDirectory string) ([]byte, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("protect-list path: %w", err)
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("protect-list invalid path component")
		}
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	dir, err := unix.Open(rootDirectory, flags|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("protect-list root directory unavailable: %w", err)
	}
	defer func() { unix.Close(dir) }()
	if err := checkProtectDirectory(dir, expectedUID); err != nil {
		return nil, err
	}
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(dir, part, flags|unix.O_DIRECTORY, 0)
		if err != nil {
			return nil, protectOpenError(dir, part, err, true)
		}
		unix.Close(dir)
		dir = next
		if err := checkProtectDirectory(dir, expectedUID); err != nil {
			return nil, err
		}
	}
	name := parts[len(parts)-1]
	fd, err := unix.Openat(dir, name, flags, 0)
	if err != nil {
		return nil, protectOpenError(dir, name, err, false)
	}
	f := os.NewFile(uintptr(fd), "protect-list")
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("protect-list fstat failed: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, errors.New("protect-list is not a regular file")
	case st.Nlink != 1:
		return nil, errors.New("protect-list link count is not 1")
	case st.Uid != expectedUID:
		return nil, errors.New("protect-list not owned by root")
	case st.Mode&0o022 != 0:
		return nil, errors.New("protect-list is group/world writable")
	case st.Mode&0o7000 != 0:
		return nil, errors.New("protect-list has set-uid, set-gid or sticky bit")
	}
	// Bound allocation even if a checked file grows; read only the checked fd.
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, fmt.Errorf("protect-list read failed: %w", err)
	}
	return raw, nil
}

func checkProtectDirectory(fd int, expectedUID uint32) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("protect-list directory fstat failed: %w", err)
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return errors.New("protect-list path component is not a directory")
	case st.Uid != expectedUID:
		return errors.New("protect-list directory not owned by root")
	case st.Mode&0o022 != 0:
		return errors.New("protect-list directory is group/world writable")
	}
	return nil
}

func protectOpenError(dir int, name string, err error, directory bool) error {
	// Diagnostic only after openat failed: this lookup never authorizes a read.
	var st unix.Stat_t
	if errors.Is(err, unix.ELOOP) || (unix.Fstatat(dir, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK) {
		return errors.New("protect-list path component is a symlink")
	}
	if errors.Is(err, unix.ENOENT) {
		return errors.New("protect-list missing (enforcement off)")
	}
	if directory && errors.Is(err, unix.ENOTDIR) {
		return errors.New("protect-list path component is not a directory")
	}
	return fmt.Errorf("protect-list unavailable (enforcement off): %w", err)
}
