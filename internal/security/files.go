package security

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const maxFile = 2 << 20
const maxEntries = 10000

// Read through O_NOFOLLOW and compare inode identity, refusing symlinks, special
// files and replacement races. Audit sources are never changed by this reader.
func readFile(path string) ([]byte, error) {
	if !safeParents(path) {
		return nil, errors.New("unsafe source parent")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() > maxFile {
		return nil, errors.New("unsupported or oversized source")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	after, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("source changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFile {
		return nil, errors.New("source too large")
	}
	return data, nil
}
func digest(data []byte) string { s := sha256.Sum256(data); return hex.EncodeToString(s[:]) }
func excluded(path string) bool {
	for _, p := range strings.Split(filepath.ToSlash(path), "/") {
		if strings.HasPrefix(p, "com.bsim.") || strings.EqualFold(p, "bsim") || strings.EqualFold(p, "mts") {
			return true
		}
	}
	return false
}

// Directory parent components must not redirect collection outside its scope.
func safeParents(path string) bool {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		s, e := os.Lstat(p)
		if e != nil || !s.IsDir() || s.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return true
}
