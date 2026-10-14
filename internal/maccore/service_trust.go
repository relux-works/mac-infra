package maccore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// DaemonTrust binds launchd's arguments to the installed files. This is a
// corruption/replacement guard, not attestation against an administrator.
type DaemonTrust struct {
	BinarySHA256   string
	BinaryIdentity string
	PlistIdentity  string
}

func fileIdentity(info os.FileInfo) string {
	stat := info.Sys().(*syscall.Stat_t)
	// st_dev can change when volumes are remounted. Inode plus creation time
	// survives reboot while detecting an ordinary replacement at the fixed path.
	return fmt.Sprintf("%d:%d", stat.Ino, stat.Birthtimespec.Sec)
}

func checkTrustedFile(file *os.File, directory bool, owner uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return err
	}
	wantType := uint32(unix.S_IFREG)
	if directory {
		wantType = unix.S_IFDIR
	}
	if uint32(stat.Mode)&unix.S_IFMT != wantType || stat.Uid != owner || stat.Mode&0o022 != 0 || stat.Mode&0o6000 != 0 {
		return fmt.Errorf("untrusted type, owner or writable permissions on %s", file.Name())
	}
	if !directory && stat.Nlink != 1 {
		return fmt.Errorf("multiple hard links on %s", file.Name())
	}
	if err := requireSafeACL(int(file.Fd())); err != nil {
		return fmt.Errorf("%s: %w", file.Name(), err)
	}
	return nil
}

// Every component is opened relative to the previously verified directory.
// O_NOFOLLOW prevents symlink substitution; protected ancestors prevent an
// unprivileged actor from renaming components after validation.
func openTrustedAt(root *os.File, relative string, directory bool, owner uint32) (*os.File, error) {
	if relative == "" || filepath.IsAbs(relative) || filepath.Clean(relative) != relative || relative == ".." || strings.HasPrefix(relative, "../") {
		return nil, fmt.Errorf("invalid trust-relative path %q", relative)
	}
	if err := checkTrustedFile(root, true, owner); err != nil {
		return nil, err
	}
	parent := root
	defer func() {
		if parent != root {
			_ = parent.Close()
		}
	}()
	components := strings.Split(relative, string(os.PathSeparator))
	for index, component := range components {
		isDir := index < len(components)-1 || directory
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if isDir {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(parent.Fd()), component, flags, 0)
		if err != nil {
			return nil, fmt.Errorf("open trusted %s: %w", component, err)
		}
		child := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), component))
		if err := checkTrustedFile(child, isDir, owner); err != nil {
			_ = child.Close()
			return nil, err
		}
		if parent != root {
			_ = parent.Close()
		}
		parent = child
	}
	result := parent
	parent = root // Transfer the final descriptor to the caller.
	return result, nil
}

func openTrustedPath(path string, directory bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("invalid absolute trusted path %q", path)
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if path == "/" {
		if err := checkTrustedFile(root, true, 0); err != nil {
			return nil, err
		}
		return os.Open("/")
	}
	return openTrustedAt(root, strings.TrimPrefix(path, "/"), directory, 0)
}

func requireTrustedDirectory(path string) error {
	file, err := openTrustedPath(path, true)
	if err != nil {
		return err
	}
	return file.Close()
}

func validateTrustArguments(trust DaemonTrust) error {
	digest, err := hex.DecodeString(trust.BinarySHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != trust.BinarySHA256 {
		return fmt.Errorf("missing or invalid installed executable digest")
	}
	for _, identity := range []string{trust.BinaryIdentity, trust.PlistIdentity} {
		parts := strings.Split(identity, ":")
		if len(parts) != 2 {
			return fmt.Errorf("invalid installed file identity")
		}
		for _, part := range parts {
			if _, err := strconv.ParseUint(part, 10, 64); err != nil || part == "" {
				return fmt.Errorf("invalid installed file identity")
			}
		}
	}
	return nil
}

func verifyInstalledFiles(binary, plist *os.File, cfg ServiceConfig, binaryPath string, uid, gid int, trust DaemonTrust) error {
	if err := validateTrustArguments(trust); err != nil {
		return err
	}
	for _, entry := range []struct {
		file *os.File
		id   string
	}{{binary, trust.BinaryIdentity}, {plist, trust.PlistIdentity}} {
		info, err := entry.file.Stat()
		if err != nil {
			return err
		}
		if fileIdentity(info) != entry.id {
			return fmt.Errorf("installed file identity changed: %s", entry.file.Name())
		}
	}
	binaryInfo, err := binary.Stat()
	if err != nil || binaryInfo.Mode().Perm() != 0o755 {
		return fmt.Errorf("installed executable must have mode 0755")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, binary); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != trust.BinarySHA256 {
		return fmt.Errorf("installed executable digest changed")
	}
	data, err := io.ReadAll(io.LimitReader(plist, 64*1024+1))
	if err != nil {
		return err
	}
	if !bytes.Equal(data, RenderServicePlist(cfg, binaryPath, uid, gid, trust)) {
		return fmt.Errorf("installed launchd configuration changed")
	}
	return nil
}

func validateDaemonInstallation(cfg ServiceConfig, uid, gid int, trust DaemonTrust) error {
	if os.Geteuid() != 0 || cfg != DefaultServiceConfig() || uid <= 0 || gid < 0 {
		return fmt.Errorf("daemon requires root, fixed installed paths and a non-root client")
	}
	path, err := os.Executable()
	if err != nil || path != defaultServiceBinaryPath {
		return fmt.Errorf("daemon must run the installed root-owned executable")
	}
	binary, err := openTrustedPath(path, false)
	if err != nil {
		return err
	}
	defer binary.Close()
	plist, err := openTrustedPath(cfg.PlistPath, false)
	if err != nil {
		return err
	}
	defer plist.Close()
	if err := requireTrustedDirectory(filepath.Dir(cfg.SocketPath)); err != nil {
		return err
	}
	return verifyInstalledFiles(binary, plist, cfg, path, uid, gid, trust)
}
