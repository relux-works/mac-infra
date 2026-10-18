package maccore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	vpnCoreLabel     = "works.relux.vpn-core"
	vpnCoreDirectory = "/Library/PrivilegedHelperTools/works.relux.vpn-core"
	vpnCorePlist     = "/Library/LaunchDaemons/works.relux.vpn-core.plist"
	vpnCoreAudit     = "/private/var/log/works.relux.mac-infra-vpn-core.jsonl"
	// Bounds leave room for growth from the reviewed 9.4 MB and 49 MB artifacts.
	vpnCoreBinaryCap   int64 = 32 << 20
	vpnCoreToolCap     int64 = 128 << 20
	vpnCoreManifestCap int64 = 16 << 10
)

type VPNCoreRequest struct {
	Target         string `json:"target"`
	Package        string `json:"package,omitempty"`
	ExpectedDigest string `json:"expect_digest,omitempty"`
}

type VPNCoreStatus struct {
	Digest         string `json:"digest,omitempty"`
	BinarySHA256   string `json:"binary_sha256,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	PreviousDigest string `json:"previous_digest,omitempty"`
	RecoveryPath   string `json:"recovery_path,omitempty"`
	State          string `json:"state"`
}

type vpnCoreError struct {
	code string
	err  error
}

func (e *vpnCoreError) Error() string      { return e.code + ": " + e.err.Error() }
func (e *vpnCoreError) Unwrap() error      { return e.err }
func vpnRefuse(code, message string) error { return &vpnCoreError{code, errors.New(message)} }
func vpnCode(err error) string {
	var refusal *vpnCoreError
	if errors.As(err, &refusal) {
		return refusal.code
	}
	if err != nil {
		return "io_error"
	}
	return ""
}

type vpnCoreManifest struct {
	Version int `json:"version"`
	Files   []struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
}

type vpnCoreOps struct {
	source        vpnCoreSourceReader
	sourceTimeout time.Duration
	rename        func(string, string) error
	directory     func(string) error
	secure        func(string, bool, os.FileMode) error
	trusted       func(string, bool) error
	swap          func(string, string) error
	launch        func(time.Duration, ...string) (CommandResult, error)
	// afterCopy is a test seam after every source descriptor has been closed.
	afterCopy func()
}

type vpnCoreService struct {
	mu                    sync.Mutex
	auditMu               sync.Mutex
	install, plist, audit string
	uid, gid              int
	ops                   vpnCoreOps
}

func newVPNCoreService(uid, gid int) *vpnCoreService {
	trusted := func(path string, dir bool) error {
		f, err := openTrustedPath(path, dir)
		if err != nil {
			return err
		}
		return f.Close()
	}
	return &vpnCoreService{install: vpnCoreDirectory, plist: vpnCorePlist, audit: vpnCoreAudit, uid: uid, gid: gid, ops: vpnCoreOps{
		source: newVPNCoreExecSource(), sourceTimeout: 120 * time.Second, rename: os.Rename, directory: requireTrustedDirectory, trusted: trusted,
		secure: secureVPNCoreFile, swap: swapVPNCoreTrees,
		launch: func(budget time.Duration, args ...string) (CommandResult, error) {
			return runCoreCommandWithTimeout(budget, launchctlPath, args...)
		},
	}}
}

func validVPNDigest(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func (s *vpnCoreService) handle(action Action, req *VPNCoreRequest) (response Response) {
	response = Response{OK: true}
	var status VPNCoreStatus
	var err error
	// Audit each decoded operation, including admission failures. Audit failures
	// remain visible even when the underlying operation also failed.
	defer func() {
		response.VPNCore = &status
		response.OK = err == nil
		response.ErrorCode = vpnCode(err)
		if err != nil {
			response.Error = err.Error()
		}
		if action == ActionVPNCoreStatus {
			return
		}
		entry := struct {
			Time     time.Time `json:"time"`
			Action   Action    `json:"action"`
			Digest   string    `json:"digest"`
			Binary   string    `json:"binary_sha256"`
			Manifest string    `json:"manifest_sha256"`
			Outcome  string    `json:"outcome"`
			Code     string    `json:"error_code"`
		}{Time: time.Now().UTC(), Action: action, Binary: status.BinarySHA256, Manifest: status.ManifestSHA256, Code: vpnCode(err), Outcome: "accepted"}
		if req != nil && validVPNDigest(req.ExpectedDigest) {
			entry.Digest = req.ExpectedDigest
		}
		if err != nil {
			entry.Outcome = "refused"
			if status.RecoveryPath != "" {
				entry.Outcome = "failed_recoverable"
			}
		}
		data, _ := json.Marshal(entry)
		if auditErr := s.appendAudit(data); auditErr != nil {
			response.OK = false
			response.ErrorCode = "audit_failed"
			response.Error = strings.TrimSpace(response.Error + "; audit_failed: " + auditErr.Error())
		}
	}()
	if !s.mu.TryLock() {
		err = vpnRefuse("busy", "another vpn-core operation is running")
		return
	}
	defer s.mu.Unlock()
	if req == nil || req.Target != "vpn-core" {
		err = vpnRefuse("unknown_target", "only vpn-core is supported")
		return
	}
	if s.uid <= 0 || s.gid <= 0 {
		err = vpnRefuse("invalid_client", "a non-root authorized uid and gid are required")
		return
	}
	if action == ActionVPNCoreStatus {
		if req.Package != "" || req.ExpectedDigest != "" {
			err = vpnRefuse("invalid_request", "status takes only target")
			return
		}
		status, err = s.inspect()
		return
	}
	if !validVPNDigest(req.ExpectedDigest) {
		err = vpnRefuse("invalid_digest", "expect_digest must be 64 lowercase hexadecimal characters")
		return
	}
	if action != ActionVPNCoreInstall && action != ActionVPNCoreRollback || action == ActionVPNCoreRollback && req.Package != "" {
		err = vpnRefuse("invalid_request", "invalid mutation action or arguments")
		return
	}
	// A durable intent must precede even temporary changes under install roots.
	intent, _ := json.Marshal(struct {
		Time    time.Time `json:"time"`
		Action  Action    `json:"action"`
		Digest  string    `json:"digest"`
		Outcome string    `json:"outcome"`
	}{time.Now().UTC(), action, req.ExpectedDigest, "started"})
	if auditErr := s.appendAudit(intent); auditErr != nil {
		err = &vpnCoreError{"audit_failed", auditErr}
		return
	}
	switch action {
	case ActionVPNCoreInstall:
		status, err = s.installPackage(*req)
	case ActionVPNCoreRollback:
		status, err = s.rollback(req.ExpectedDigest)
	default:
		err = vpnRefuse("invalid_request", "unsupported vpn-core action")
	}
	return
}

// Walk from / using directory descriptors; no pathname component is followed.
func openVPNCorePath(path string, directory bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, vpnRefuse("invalid_package_path", "package path must be absolute and clean")
	}
	root, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return openVPNCoreAt(root, strings.TrimPrefix(path, "/"), directory)
}

func openVPNCoreAt(root *os.File, path string, directory bool) (*os.File, error) {
	parent := root
	defer func() {
		if parent != root {
			_ = parent.Close()
		}
	}()
	parts := strings.Split(path, "/")
	for i, part := range parts {
		dir := i < len(parts)-1 || directory
		var stat unix.Stat_t
		if err := unix.Fstatat(int(parent.Fd()), part, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return nil, err
		}
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil, vpnRefuse("symlink", "source components must not be symlinks")
		}
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if dir {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(int(parent.Fd()), part, flags, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				return nil, vpnRefuse("symlink", "symlink substitution refused")
			}
			if errors.Is(err, unix.ENOTDIR) {
				return nil, vpnRefuse("non_regular", "expected directory")
			}
			return nil, err
		}
		child := os.NewFile(uintptr(fd), filepath.Join(parent.Name(), part))
		info, err := child.Stat()
		if err != nil {
			child.Close()
			return nil, err
		}
		if (dir && !info.IsDir()) || (!dir && !info.Mode().IsRegular()) {
			child.Close()
			return nil, vpnRefuse("non_regular", "expected regular file or directory")
		}
		if parent != root {
			parent.Close()
		}
		parent = child
	}
	result := parent
	parent = root
	return result, nil
}

var vpnCoreFiles = []struct {
	path string
	cap  int64
	mode os.FileMode
}{
	{"vpn-core", vpnCoreBinaryCap, 0o755}, {"bin/sing-box", vpnCoreToolCap, 0o755}, {"manifest.json", vpnCoreManifestCap, 0o644},
}

func checkVPNCoreEntries(dir *os.File, want ...string) error {
	entries, err := dir.ReadDir(len(want) + 1)
	if err != nil && err != io.EOF {
		return err
	}
	if len(entries) != len(want) {
		return vpnRefuse("package_entries", "unexpected or missing package entries")
	}
	names := make(map[string]bool, len(want))
	for _, name := range want {
		names[name] = true
	}
	for _, e := range entries {
		if !names[e.Name()] {
			return vpnRefuse("package_entries", "unexpected package entry")
		}
	}
	return nil
}

// The unprivileged worker preflights all types and sizes before emitting bytes.
// The open descriptors also pin files if the user renames source components.
func openVPNCorePackage(path string, owner ...uint32) ([]*os.File, error) {
	checkOwner := func(file *os.File) error {
		if len(owner) == 0 {
			return nil
		}
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
			return err
		}
		if stat.Uid != owner[0] {
			return vpnRefuse("source_owner", "package must belong to the authorized staging user")
		}
		return nil
	}
	dir, err := openVPNCorePath(path, true)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	if err := checkOwner(dir); err != nil {
		return nil, err
	}
	if err := checkVPNCoreEntries(dir, "vpn-core", "bin", "manifest.json"); err != nil {
		return nil, err
	}
	bin, err := openVPNCoreAt(dir, "bin", true)
	if err != nil {
		return nil, err
	}
	defer bin.Close()
	if err := checkOwner(bin); err != nil {
		return nil, err
	}
	if err := checkVPNCoreEntries(bin, "sing-box"); err != nil {
		return nil, err
	}
	var files []*os.File
	for _, entry := range vpnCoreFiles {
		file, err := openVPNCoreAt(dir, entry.path, false)
		if err == nil {
			err = checkOwner(file)
		}
		if err == nil {
			info, statErr := file.Stat()
			err = statErr
			if err == nil && info.Size() > entry.cap {
				err = vpnRefuse("file_too_large", "package file exceeds size cap")
			}
		}
		if err != nil {
			if file != nil {
				file.Close()
			}
			closeVPNCoreFiles(files)
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}
func closeVPNCoreFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func readVPNCoreBounded(file *os.File, cap int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > cap {
		return nil, vpnRefuse("file_too_large", "package file exceeds size cap")
	}
	return data, nil
}

func vpnSHA(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Only the private staged copies enter this verifier, never the source paths.
func verifyVPNCorePackage(path string) (VPNCoreStatus, error) {
	var status VPNCoreStatus
	files, err := openVPNCorePackage(path)
	if err != nil {
		return status, err
	}
	defer closeVPNCoreFiles(files)
	data := make([][]byte, len(files))
	for i, file := range files {
		data[i], err = readVPNCoreBounded(file, vpnCoreFiles[i].cap)
		if err != nil {
			return status, err
		}
	}
	status.BinarySHA256 = vpnSHA(data[0])
	status.ManifestSHA256 = vpnSHA(data[2])
	hash := sha256.New()
	hash.Write(data[0])
	hash.Write(data[2])
	status.Digest = hex.EncodeToString(hash.Sum(nil))
	if err := checkVPNCoreJSON(data[2]); err != nil {
		return status, vpnRefuse("invalid_manifest", "ambiguous manifest JSON")
	}
	var manifest vpnCoreManifest
	decoder := json.NewDecoder(bytes.NewReader(data[2]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return status, vpnRefuse("invalid_manifest", "invalid manifest JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return status, vpnRefuse("invalid_manifest", "trailing manifest JSON")
	}
	if manifest.Version != 1 {
		return status, vpnRefuse("manifest_version", "manifest version must be 1")
	}
	if len(manifest.Files) != 2 {
		return status, vpnRefuse("manifest_entries", "manifest requires exactly vpn-core and bin/sing-box")
	}
	expected := map[string]string{"vpn-core": status.BinarySHA256, "bin/sing-box": vpnSHA(data[1])}
	seen := map[string]bool{}
	for _, entry := range manifest.Files {
		want, ok := expected[entry.Path]
		if !ok || seen[entry.Path] {
			return status, vpnRefuse("manifest_entries", "unknown or repeated manifest path")
		}
		seen[entry.Path] = true
		if !validVPNDigest(entry.SHA256) || entry.SHA256 != want {
			return status, vpnRefuse("file_sha_mismatch", "manifest file sha256 mismatch")
		}
	}
	status.State = "verified"
	return status, nil
}

// Reject duplicate (including escape-spelt) members before struct decoding
// can silently select one value. The manifest is small and has shallow shape.
func checkVPNCoreJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value func(int) error
	value = func(depth int) error {
		if depth > 8 {
			return errors.New("manifest nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate manifest member")
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing manifest JSON")
	}
	return checkVPNCoreExactKeys(data)
}

func checkVPNCoreExactKeys(data []byte) error {
	exact := func(raw json.RawMessage, keys ...string) (map[string]json.RawMessage, error) {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			return nil, err
		}
		if len(object) != len(keys) {
			return nil, errors.New("missing or unknown manifest key")
		}
		for _, key := range keys {
			if _, ok := object[key]; !ok {
				return nil, errors.New("noncanonical manifest key")
			}
		}
		return object, nil
	}
	top, err := exact(data, "version", "files")
	if err != nil {
		return err
	}
	var files []json.RawMessage
	if err := json.Unmarshal(top["files"], &files); err != nil {
		return err
	}
	for _, file := range files {
		if _, err := exact(file, "path", "sha256"); err != nil {
			return err
		}
	}
	return nil
}

func (s *vpnCoreService) checkTree(path string) error {
	for _, entry := range []struct {
		name string
		dir  bool
	}{{"", true}, {"bin", true}, {"vpn-core", false}, {"bin/sing-box", false}, {"manifest.json", false}} {
		if err := s.ops.trusted(filepath.Join(path, entry.name), entry.dir); err != nil {
			return err
		}
	}
	return nil
}

func (s *vpnCoreService) parents() error {
	for _, path := range []string{filepath.Dir(s.install), filepath.Dir(s.plist)} {
		if err := s.ops.directory(path); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(s.plist); err == nil {
		return s.ops.trusted(s.plist, false)
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (s *vpnCoreService) installPackage(req VPNCoreRequest) (status VPNCoreStatus, err error) {
	if err = s.parents(); err != nil {
		return status, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(s.install), ".vpn-core-install-")
	if err != nil {
		return status, err
	}
	preserve := false
	defer func() {
		if !preserve {
			if cleanupErr := os.RemoveAll(stage); cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
		}
	}()
	if err = s.ops.secure(stage, true, 0o700); err != nil {
		return status, err
	}
	tree := filepath.Join(stage, "tree")
	if err = os.Mkdir(tree, 0o700); err != nil {
		return status, err
	}
	if err = s.ops.secure(tree, true, 0o700); err != nil {
		return status, err
	}
	if err = os.Mkdir(filepath.Join(tree, "bin"), 0o700); err != nil {
		return status, err
	}
	if err = s.ops.secure(filepath.Join(tree, "bin"), true, 0o755); err != nil {
		return status, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.ops.sourceTimeout)
	defer cancel()
	err = s.ops.source.Read(ctx, req.Package, s.uid, s.gid, func(reader io.Reader) error {
		return s.receiveSource(reader, tree)
	})
	if err != nil {
		return status, err
	}
	if s.ops.afterCopy != nil {
		s.ops.afterCopy()
	}
	status, err = verifyVPNCorePackage(tree)
	if err != nil {
		return status, err
	}
	if status.Digest != req.ExpectedDigest {
		return status, vpnRefuse("digest_mismatch", "staged package does not match expect_digest")
	}
	if err = s.ops.secure(tree, true, 0o755); err != nil {
		return status, err
	}
	previous := s.install + ".previous"
	if _, statErr := os.Lstat(s.install); statErr == nil {
		if err = s.checkTree(s.install); err != nil {
			return status, err
		}
		if _, prevErr := os.Lstat(previous); prevErr == nil {
			if err = s.checkTree(previous); err != nil {
				return status, err
			}
		} else if !os.IsNotExist(prevErr) {
			return status, prevErr
		}
		if err = s.ops.swap(tree, s.install); err != nil {
			return status, err
		}
		preserve = true
		status.RecoveryPath = stage
		older := filepath.Join(stage, "older")
		movedOlder := false
		compensate := func(cause error) (VPNCoreStatus, error) {
			swapErr := s.ops.swap(tree, s.install)
			var restoreErr error
			if movedOlder {
				restoreErr = s.ops.rename(older, previous)
			}
			if undoErr := errors.Join(swapErr, restoreErr); undoErr != nil {
				return status, &vpnCoreError{"compensation_failed", errors.Join(cause, undoErr)}
			}
			preserve = false
			restored, inspectErr := s.inspect()
			return restored, errors.Join(cause, inspectErr)
		}
		if _, prevErr := os.Lstat(previous); prevErr == nil {
			if err = s.ops.rename(previous, older); err != nil {
				return compensate(err)
			}
			movedOlder = true
		}
		if err = s.ops.rename(tree, previous); err != nil {
			return compensate(err)
		}
		status.RecoveryPath = previous
	} else if os.IsNotExist(statErr) {
		if err = os.Rename(tree, s.install); err != nil {
			return status, err
		}
	} else {
		return status, statErr
	}
	if err = s.activate(status); err != nil {
		preserve = true
		status.State = "restart_failed"
		// First install has no previous tree; retain the installed tree and report it.
		if status.RecoveryPath == "" {
			status.RecoveryPath = s.install
		}
		return status, &vpnCoreError{"restart_failed", fmt.Errorf("installed tree retained; recovery at %s: %w", status.RecoveryPath, err)}
	}
	preserve = false
	status.RecoveryPath = ""
	status.State = "installed"
	return status, nil
}

func (s *vpnCoreService) rollback(expected string) (status VPNCoreStatus, err error) {
	if err = s.parents(); err != nil {
		return status, err
	}
	previous := s.install + ".previous"
	if _, err = os.Lstat(previous); os.IsNotExist(err) {
		return status, vpnRefuse("no_previous", "no previous vpn-core tree")
	} else if err != nil {
		return status, err
	}
	if err = s.checkTree(previous); err != nil {
		return status, err
	}
	status, err = verifyVPNCorePackage(previous)
	if err != nil {
		return status, err
	}
	if status.Digest != expected {
		return status, vpnRefuse("digest_mismatch", "previous tree does not match expect_digest")
	}
	if err = s.checkTree(s.install); err != nil {
		return status, err
	}
	if err = s.ops.swap(previous, s.install); err != nil {
		return status, err
	}
	status.RecoveryPath = previous
	if err = s.activate(status); err != nil {
		status.State = "restart_failed"
		return status, &vpnCoreError{"restart_failed", fmt.Errorf("rollback tree installed; previous retained at %s: %w", previous, err)}
	}
	status.State = "rolled_back"
	status.RecoveryPath = ""
	return status, nil
}

func (s *vpnCoreService) inspect() (VPNCoreStatus, error) {
	status := VPNCoreStatus{State: "absent"}
	if err := s.parents(); err != nil {
		return status, err
	}
	if _, err := os.Lstat(s.install); os.IsNotExist(err) {
		return status, nil
	} else if err != nil {
		return status, err
	}
	if err := s.checkTree(s.install); err != nil {
		return status, err
	}
	status, err := verifyVPNCorePackage(s.install)
	if err != nil {
		return status, err
	}
	previous := s.install + ".previous"
	if _, err := os.Lstat(previous); err == nil {
		if err := s.checkTree(previous); err != nil {
			return status, err
		}
		prev, err := verifyVPNCorePackage(previous)
		if err != nil {
			return status, err
		}
		status.PreviousDigest = prev.Digest
	} else if !os.IsNotExist(err) {
		return status, err
	}
	// Disk verification does not assert that launchd is running these bytes.
	status.State = "installed"
	return status, nil
}

func renderVPNCorePlist(install string, uid, gid int, status VPNCoreStatus) ([]byte, error) {
	if uid <= 0 || gid <= 0 {
		return nil, vpnRefuse("invalid_client", "uid and gid must be nonzero")
	}
	if !validVPNDigest(status.BinarySHA256) || !validVPNDigest(status.ManifestSHA256) {
		return nil, vpnRefuse("invalid_digest", "invalid installed hashes")
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>" + vpnCoreLabel + "</string>\n  <key>ProgramArguments</key>\n  <array>\n")
	for _, value := range []string{filepath.Join(install, "vpn-core"), "_daemon", "--socket", "/private/var/run/works.relux.vpn-core.sock", "--client-uid", strconv.Itoa(uid), "--client-gid", strconv.Itoa(gid), "--binary-sha256", status.BinarySHA256, "--manifest-sha256", status.ManifestSHA256} {
		b.WriteString("    <string>" + plistEscape(value) + "</string>\n")
	}
	b.WriteString("  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <true/>\n</dict>\n</plist>\n")
	return []byte(b.String()), nil
}

func (s *vpnCoreService) activate(status VPNCoreStatus) error {
	data, err := renderVPNCorePlist(s.install, s.uid, s.gid, status)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(s.plist), ".vpn-core-plist-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err := s.ops.secure(file.Name(), false, 0o644); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), s.plist); err != nil {
		return err
	}
	return replaceLaunchServiceWith(ServiceConfig{Label: vpnCoreLabel, PlistPath: s.plist}, 10*time.Second, s.ops.launch, true)
}

func (s *vpnCoreService) appendAudit(data []byte) error {
	s.auditMu.Lock()
	defer s.auditMu.Unlock()
	if err := s.ops.directory(filepath.Dir(s.audit)); err != nil {
		return err
	}
	flags := unix.O_WRONLY | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
	fd, err := unix.Open(s.audit, flags|unix.O_CREAT|unix.O_EXCL, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		fd, err = unix.Open(s.audit, flags, 0)
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), s.audit)
	defer file.Close()
	if created {
		if err := s.ops.secure(s.audit, false, 0o600); err != nil {
			return err
		}
	}
	if err := s.ops.trusted(s.audit, false); err != nil {
		return err
	}
	if err := checkVPNCoreAudit(file); err != nil {
		return err
	}
	_, err = file.Write(append(data, '\n'))
	if err = errors.Join(err, file.Sync()); err != nil {
		return err
	}
	if created {
		parent, err := os.Open(filepath.Dir(s.audit))
		if err != nil {
			return err
		}
		return errors.Join(parent.Sync(), parent.Close())
	}
	return nil
}

// A freshly created audit file inherits root ownership in production. Test
// ownership is checked through the same injected trusted-file seam.
func checkVPNCoreAudit(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return errors.New("unsafe audit file")
	}
	return nil
}
