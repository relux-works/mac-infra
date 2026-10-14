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

const maxReviewedExecutableSize = 128 * 1024 * 1024

// Snapshot the reviewed user artifact before elevation. Privileged commands
// consume these bytes on stdin, never reopen a user-writable source pathname.
// Reviewing/authenticating this initial artifact remains the admin's boundary.
func readReviewedExecutable(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open reviewed executable: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0o111 == 0 || before.Size() <= 0 || before.Size() > maxReviewedExecutableSize {
		return nil, fmt.Errorf("reviewed executable must be a bounded nonempty executable regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxReviewedExecutableSize+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	current, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(after, current) ||
		before.Size() != after.Size() || before.Size() != int64(len(data)) ||
		before.ModTime() != after.ModTime() || before.Sys().(*syscall.Stat_t).Ctimespec != after.Sys().(*syscall.Stat_t).Ctimespec {
		return nil, fmt.Errorf("reviewed executable changed while taking installation snapshot")
	}
	return data, nil
}

type installationOps struct {
	open    func(string, bool) (*os.File, error)
	lstat   func(string) (os.FileInfo, error)
	command func([]byte, string, ...string) ([]byte, error)
}

func rootInstallationOps() installationOps {
	return installationOps{open: openTrustedPath, lstat: os.Lstat, command: runInstallationCommand}
}

func runInstallationCommand(input []byte, name string, args ...string) ([]byte, error) {
	if os.Geteuid() != 0 {
		args = append([]string{"-n", name}, args...)
		name = "/usr/bin/sudo"
	}
	cmd := execCommandCore(name, args...)
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

func (ops installationOps) directory(path string) error {
	file, err := ops.open(path, true)
	if err != nil {
		return err
	}
	return file.Close()
}

func (ops installationOps) ensureDirectory(path string) error {
	if err := ops.directory(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := ops.lstat(path); os.IsNotExist(err) {
		if _, err := ops.command(nil, "/usr/bin/install", "-d", "-o", "root", "-g", "wheel", "-m", "0755", path); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return ops.directory(path)
}

func (ops installationOps) existingFile(path string) error {
	if _, err := ops.lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	file, err := ops.open(path, false)
	if err != nil {
		return err
	}
	return file.Close()
}

func (ops installationOps) stageBytes(path string, data []byte, mode string) error {
	// The only shell program is fixed, with a root-private destination passed as
	// one positional argument. No source paths or request actions enter the shell.
	if _, err := ops.command(data, "/bin/sh", "-c", `umask 077; /bin/cat > "$1"`, "mac-infra-stage", path); err != nil {
		return err
	}
	if _, err := ops.command(nil, "/usr/sbin/chown", "0:0", path); err != nil {
		return err
	}
	_, err := ops.command(nil, "/bin/chmod", mode, path)
	return err
}

func (ops installationOps) identity(path string) (string, error) {
	out, err := ops.command(nil, "/usr/bin/stat", "-f", "%i:%B", path)
	if err != nil {
		return "", err
	}
	identity := strings.TrimSpace(string(out))
	probe := DaemonTrust{BinarySHA256: strings.Repeat("0", 64), BinaryIdentity: identity, PlistIdentity: identity}
	return identity, validateTrustArguments(probe)
}

func (ops installationOps) filesystem(path string) (string, error) {
	out, err := ops.command(nil, "/usr/bin/stat", "-f", "%d", path)
	if err != nil {
		return "", err
	}
	device := strings.TrimSpace(string(out))
	if _, err := strconv.ParseUint(device, 10, 64); err != nil {
		return "", fmt.Errorf("invalid filesystem device")
	}
	return device, nil
}

func installReviewedSnapshot(snapshot []byte, cfg ServiceConfig, uid, gid int, ops installationOps, activate ...func() error) error {
	if len(snapshot) == 0 || len(snapshot) > maxReviewedExecutableSize {
		return fmt.Errorf("invalid reviewed executable snapshot")
	}
	if err := ops.ensureDirectory(filepath.Dir(defaultServiceDirectory)); err != nil {
		return err
	}
	if err := ops.ensureDirectory(defaultServiceDirectory); err != nil {
		return err
	}
	if err := ops.directory(filepath.Dir(cfg.PlistPath)); err != nil {
		return err
	}
	for _, path := range []string{defaultServiceBinaryPath, cfg.PlistPath} {
		if err := ops.existingFile(path); err != nil {
			return err
		}
	}
	out, err := ops.command(nil, "/usr/bin/mktemp", "-d", defaultServiceDirectory+"/.install.XXXXXXXX")
	if err != nil {
		return err
	}
	stage := strings.TrimSpace(string(out))
	if filepath.Dir(stage) != defaultServiceDirectory || !strings.HasPrefix(filepath.Base(stage), ".install.") || filepath.Clean(stage) != stage {
		return fmt.Errorf("unexpected privileged staging path")
	}
	binaryStage, plistStage := filepath.Join(stage, "mac-infra-core"), filepath.Join(stage, "core.plist")
	binaryBackup, plistBackup := filepath.Join(stage, "previous-core"), filepath.Join(stage, "previous.plist")
	preserveStage := false
	defer func() {
		if preserveStage {
			return
		}
		_, _ = ops.command(nil, "/bin/rm", "-f", binaryStage, plistStage, binaryBackup, plistBackup)
		_, _ = ops.command(nil, "/bin/rmdir", stage)
	}()
	if err := ops.stageBytes(binaryStage, snapshot, "0755"); err != nil {
		return err
	}
	if err := ops.stageBytes(plistStage, nil, "0644"); err != nil {
		return err
	}
	binaryID, err := ops.identity(binaryStage)
	if err != nil {
		return err
	}
	plistID, err := ops.identity(plistStage)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(snapshot)
	trust := DaemonTrust{BinarySHA256: hex.EncodeToString(hash[:]), BinaryIdentity: binaryID, PlistIdentity: plistID}
	if err := ops.stageBytes(plistStage, RenderServicePlist(cfg, defaultServiceBinaryPath, uid, gid, trust), "0644"); err != nil {
		return err
	}
	// Both final directories must be protected and on the same filesystem:
	// mv then preserves the pinned inode and never needs a copy fallback.
	sourceDir, err := ops.filesystem(stage)
	if err != nil {
		return err
	}
	destDir, err := ops.filesystem(filepath.Dir(cfg.PlistPath))
	if err != nil {
		return err
	}
	if sourceDir != destDir {
		return fmt.Errorf("launchd configuration must share the staging filesystem")
	}
	files := []installationPublication{
		{stage: binaryStage, destination: defaultServiceBinaryPath, backup: binaryBackup},
		{stage: plistStage, destination: cfg.PlistPath, backup: plistBackup},
	}
	if err := publishInstallation(files, ops, func() error {
		binary, err := ops.open(defaultServiceBinaryPath, false)
		if err != nil {
			return err
		}
		defer binary.Close()
		plist, err := ops.open(cfg.PlistPath, false)
		if err != nil {
			return err
		}
		defer plist.Close()
		if err := verifyInstalledFiles(binary, plist, cfg, defaultServiceBinaryPath, uid, gid, trust); err != nil {
			return err
		}
		if len(activate) == 1 {
			return activate[0]()
		}
		return nil
	}); err != nil {
		for _, file := range files {
			if file.oldMoved {
				preserveStage = true
				return fmt.Errorf("%w; recovery files retained in %s", err, stage)
			}
		}
		return err
	}
	return nil
}

type installationPublication struct {
	stage, destination, backup string
	oldMoved, published        bool
}

// Preserve old inodes for rollback, since the previous plist pins them. A crash
// or failed rollback can still require manual recovery from the private stage;
// two filesystem names and launchd state cannot be committed as one transaction.
func publishInstallation(files []installationPublication, ops installationOps, verify func() error) (result error) {
	defer func() {
		if result == nil {
			return
		}
		for index := len(files) - 1; index >= 0; index-- {
			file := &files[index]
			if file.oldMoved {
				if _, err := ops.command(nil, "/bin/mv", "-f", file.backup, file.destination); err != nil {
					result = fmt.Errorf("%w; restore previous installation: %v", result, err)
				} else {
					file.oldMoved = false
				}
			} else if file.published {
				if _, err := ops.command(nil, "/bin/rm", "-f", file.destination); err != nil {
					result = fmt.Errorf("%w; remove incomplete installation: %v", result, err)
				}
			}
		}
	}()
	for index := range files {
		file := &files[index]
		if err := ops.directory(filepath.Dir(file.destination)); err != nil {
			return err
		}
		if err := ops.existingFile(file.destination); err != nil {
			return err
		}
		if _, err := ops.lstat(file.destination); err == nil {
			if _, err := ops.command(nil, "/bin/mv", "-f", file.destination, file.backup); err != nil {
				return err
			}
			file.oldMoved = true
		} else if !os.IsNotExist(err) {
			return err
		}
		if _, err := ops.command(nil, "/bin/mv", "-f", file.stage, file.destination); err != nil {
			return err
		}
		file.published = true
	}
	return verify()
}

// A protected socket directory lets only root create/remove names; the socket
// itself stays 0600 and owned by the intended normal user for client access.
func removeStaleSocket(path string, clientUID int) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	owner := int(info.Sys().(*syscall.Stat_t).Uid)
	if info.Mode()&os.ModeSocket == 0 || (owner != 0 && owner != clientUID) {
		return fmt.Errorf("refusing to replace unexpected socket entry")
	}
	return os.Remove(path)
}
