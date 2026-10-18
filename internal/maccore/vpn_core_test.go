package maccore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type vpnFixture struct {
	s       *vpnCoreService
	root    string
	calls   []string
	secure  []string
	fail    string
	present int
	mu      sync.Mutex
}

func newVPNFixture(t *testing.T) *vpnFixture {
	t.Helper()
	// Test storage stays in the worktree even when the caller omits TMPDIR.
	if err := os.MkdirAll(".temp", 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(".temp", "vpn-core-test-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	f := &vpnFixture{root: root}
	for _, name := range []string{"helpers", "daemons", "logs"} {
		mustVPN(t, os.Mkdir(filepath.Join(root, name), 0o755))
	}
	trust := func(path string, dir bool) error {
		file, err := openVPNCorePath(path, dir)
		if err != nil {
			return err
		}
		defer file.Close()
		return checkTrustedFile(file, dir, uint32(os.Getuid()))
	}
	f.s = &vpnCoreService{install: filepath.Join(root, "helpers", vpnCoreLabel), plist: filepath.Join(root, "daemons", vpnCoreLabel+".plist"), audit: filepath.Join(root, "logs", "audit.jsonl"), uid: 501, gid: 20}
	f.s.ops = vpnCoreOps{
		source:        &vpnCoreInProcessSource{uid: uint32(os.Getuid())},
		sourceTimeout: 5 * time.Second, rename: os.Rename,
		directory: func(path string) error { return trust(path, true) }, trusted: trust,
		secure: func(path string, dir bool, mode os.FileMode) error {
			f.secure = append(f.secure, fmt.Sprintf("%s:%t:%04o", path, dir, mode))
			return secureVPNCoreFileOwned(path, dir, mode, os.Getuid(), os.Getgid())
		},
		swap: swapVPNCoreTrees,
		launch: func(_ time.Duration, args ...string) (CommandResult, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.calls = append(f.calls, strings.Join(args, " "))
			if args[0] == f.fail {
				return CommandResult{}, errors.New("injected launchctl failure")
			}
			if args[0] == "print" {
				if f.present > 0 {
					f.present--
					return CommandResult{}, nil
				}
				// A constructed exit status exercises the real exact-diagnostic matcher.
				return CommandResult{Output: fmt.Sprintf("Could not find service %q in domain for system", vpnCoreLabel)}, &exec.ExitError{ProcessState: vpnExitState(t, 113)}
			}
			return CommandResult{}, nil
		},
	}
	return f
}

// Exit status is a local shell builtin; no launchctl process is started.
func vpnExitState(t *testing.T, code int) *os.ProcessState {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", code))
	_ = cmd.Run()
	return cmd.ProcessState
}
func mustVPN(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func readVPN(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	mustVPN(t, err)
	return b
}
func writeVPN(t *testing.T, path string, b []byte) {
	t.Helper()
	mustVPN(t, os.WriteFile(path, b, 0o600))
}

func (f *vpnFixture) pkg(t *testing.T, binary, tool string) (string, string) {
	t.Helper()
	dir, err := os.MkdirTemp(f.root, "package-")
	mustVPN(t, err)
	mustVPN(t, os.Mkdir(filepath.Join(dir, "bin"), 0o700))
	writeVPN(t, filepath.Join(dir, "vpn-core"), []byte(binary))
	writeVPN(t, filepath.Join(dir, "bin/sing-box"), []byte(tool))
	manifest := fmt.Sprintf("{\"version\":1,\"files\":[{\"path\":\"vpn-core\",\"sha256\":\"%s\"},{\"path\":\"bin/sing-box\",\"sha256\":\"%s\"}]}\n", vpnSHA([]byte(binary)), vpnSHA([]byte(tool)))
	writeVPN(t, filepath.Join(dir, "manifest.json"), []byte(manifest))
	return dir, vpnPackageDigest([]byte(binary), []byte(manifest))
}
func (f *vpnFixture) install(t *testing.T, pkg, digest string) Response {
	t.Helper()
	return f.s.handle(ActionVPNCoreInstall, &VPNCoreRequest{Target: "vpn-core", Package: pkg, ExpectedDigest: digest})
}
func (f *vpnFixture) rollback(digest string) Response {
	return f.s.handle(ActionVPNCoreRollback, &VPNCoreRequest{Target: "vpn-core", ExpectedDigest: digest})
}
func requireVPNCode(t *testing.T, r Response, code string) {
	t.Helper()
	if r.OK || r.ErrorCode != code {
		t.Fatalf("response=%+v, want refusal %s", r, code)
	}
}
func snapshotVPN(t *testing.T, root string) string {
	t.Helper()
	var b strings.Builder
	mustVPN(t, filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := e.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %s", strings.TrimPrefix(path, root), info.Mode())
		if info.Mode().IsRegular() {
			fmt.Fprintf(&b, " %s", vpnSHA(readVPN(t, path)))
		}
		b.WriteByte('\n')
		return nil
	}))
	return b.String()
}
func (f *vpnFixture) snapshot(t *testing.T) string {
	return snapshotVPN(t, filepath.Dir(f.s.install)) + snapshotVPN(t, filepath.Dir(f.s.plist))
}
func auditVPN(t *testing.T, f *vpnFixture) []map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(readVPN(t, f.s.audit)), []byte("\n"))
	result := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var entry map[string]any
		mustVPN(t, json.Unmarshal(line, &entry))
		result = append(result, entry)
	}
	return result
}

// A valid package installs original bytes/modes and golden plist formatting, audits intent and completion, and waits before enable/bootstrap using only fake roots.
func TestVPNCoreInstall(t *testing.T) {
	f := newVPNFixture(t)
	pkg, digest := f.pkg(t, "vpn binary", "sing box")
	f.present = 1
	r := f.install(t, pkg, digest)
	if !r.OK {
		t.Fatal(r.Error)
	}
	for _, e := range []struct {
		path string
		mode os.FileMode
	}{{"", 0o755}, {"bin", 0o755}, {"vpn-core", 0o755}, {"bin/sing-box", 0o755}, {"manifest.json", 0o644}} {
		info, err := os.Stat(filepath.Join(f.s.install, e.path))
		mustVPN(t, err)
		if info.Mode().Perm() != e.mode {
			t.Fatalf("%s mode=%o", e.path, info.Mode().Perm())
		}
	}
	for _, name := range []string{"vpn-core", "bin/sing-box", "manifest.json"} {
		if !bytes.Equal(readVPN(t, filepath.Join(pkg, name)), readVPN(t, filepath.Join(f.s.install, name))) {
			t.Fatal("installed bytes changed:", name)
		}
	}
	golden := string(readVPN(t, "testdata/vpn-core-service.plist"))
	golden = strings.ReplaceAll(golden, vpnCoreDirectory, f.s.install)
	golden = strings.ReplaceAll(golden, "e9d59950256d31a51dfe77f63b07a4fc3c1fe4f5688944f1c98c596d37d78a9a", r.VPNCore.BinarySHA256)
	golden = strings.ReplaceAll(golden, "bda3368336dcab28f443dbe51607b05dd4f5b7ddde8cf7123b60c124b376282c", r.VPNCore.ManifestSHA256)
	if string(readVPN(t, f.s.plist)) != golden {
		t.Fatal("installed plist differs from golden")
	}
	info, err := os.Stat(f.s.plist)
	mustVPN(t, err)
	if info.Mode().Perm() != 0o644 {
		t.Fatal("plist mode")
	}
	want := []string{"bootout system/" + vpnCoreLabel, "print system/" + vpnCoreLabel, "print system/" + vpnCoreLabel, "enable system/" + vpnCoreLabel, "bootstrap system " + f.s.plist}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls=%q", f.calls)
	}
	audit := auditVPN(t, f)
	if len(audit) != 2 || audit[0]["outcome"] != "started" || audit[0]["digest"] != digest || audit[1]["digest"] != digest || audit[1]["outcome"] != "accepted" || audit[1]["binary_sha256"] != r.VPNCore.BinarySHA256 || audit[1]["manifest_sha256"] != r.VPNCore.ManifestSHA256 {
		t.Fatalf("audit=%v", audit)
	}
	if len(f.secure) != 9 {
		t.Fatalf("secure layout calls=%v", f.secure)
	}
}

// The production fixed template matches the keeper's exact reference bytes and never renders a zero uid or gid.
func TestVPNCorePlistGoldenAndClient(t *testing.T) {
	status := VPNCoreStatus{BinarySHA256: "e9d59950256d31a51dfe77f63b07a4fc3c1fe4f5688944f1c98c596d37d78a9a", ManifestSHA256: "bda3368336dcab28f443dbe51607b05dd4f5b7ddde8cf7123b60c124b376282c"}
	data, err := renderVPNCorePlist(vpnCoreDirectory, 501, 20, status)
	mustVPN(t, err)
	if !bytes.Equal(data, readVPN(t, "testdata/vpn-core-service.plist")) {
		t.Fatal("reference mismatch")
	}
	for _, pair := range [][2]int{{0, 20}, {501, 0}, {-1, 20}, {501, -1}} {
		data, err := renderVPNCorePlist(vpnCoreDirectory, pair[0], pair[1], status)
		if vpnCode(err) != "invalid_client" || len(data) != 0 {
			t.Fatalf("pair=%v data=%s err=%v", pair, data, err)
		}
	}
}

// Each invalid package/request returns its specific refusal, preserves existing install/plist bytes and modes, makes no launchctl call, and records one refusal audit.
func TestVPNCoreRefusals(t *testing.T) {
	cases := []struct {
		name, code string
		change     func(*testing.T, *vpnFixture, *VPNCoreRequest)
	}{
		{"wrong digest", "digest_mismatch", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.ExpectedDigest = strings.Repeat("0", 64) }},
		{"unframed digest", "digest_mismatch", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			r.ExpectedDigest = vpnSHA(append(readVPN(t, filepath.Join(r.Package, "vpn-core")), readVPN(t, filepath.Join(r.Package, "manifest.json"))...))
		}},
		{"bad digest", "invalid_digest", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.ExpectedDigest = "" }},
		{"binary sha", "file_sha_mismatch", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			writeVPN(t, filepath.Join(r.Package, "vpn-core"), []byte("other"))
		}},
		{"tool sha", "file_sha_mismatch", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			writeVPN(t, filepath.Join(r.Package, "bin/sing-box"), []byte("other"))
		}},
		{"extra manifest entry", "manifest_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			modifyVPNManifest(t, r.Package, func(m *vpnCoreManifest) { m.Files = append(m.Files, m.Files[0]) })
		}},
		{"missing manifest entry", "manifest_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			modifyVPNManifest(t, r.Package, func(m *vpnCoreManifest) { m.Files = m.Files[:1] })
		}},
		{"duplicate manifest path", "manifest_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			modifyVPNManifest(t, r.Package, func(m *vpnCoreManifest) { m.Files[1] = m.Files[0] })
		}},
		{"unknown manifest path", "manifest_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			modifyVPNManifest(t, r.Package, func(m *vpnCoreManifest) { m.Files[1].Path = "../tool" })
		}},
		{"wrong version", "manifest_version", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			modifyVPNManifest(t, r.Package, func(m *vpnCoreManifest) { m.Version = 2 })
		}},
		{"unknown target", "unknown_target", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Target = "other" }},
		{"relative path", "invalid_package_path", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Package = "relative" }},
		{"unclean path", "invalid_package_path", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { r.Package += "/../package" }},
		{"symlink package", "symlink", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p := filepath.Join(f.root, "link")
			mustVPN(t, os.Symlink(r.Package, p))
			r.Package = p
		}},
		{"symlink file", "symlink", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p := filepath.Join(r.Package, "vpn-core")
			mustVPN(t, os.Rename(p, filepath.Join(f.root, "real")))
			mustVPN(t, os.Symlink(filepath.Join(f.root, "real"), p))
		}},
		{"symlink intermediate", "symlink", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p := filepath.Join(f.root, "parent-link")
			mustVPN(t, os.Symlink(f.root, p))
			r.Package = filepath.Join(p, filepath.Base(r.Package))
		}},
		{"symlink bin", "symlink", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p := filepath.Join(r.Package, "bin")
			target := filepath.Join(f.root, "real-bin")
			mustVPN(t, os.Rename(p, target))
			mustVPN(t, os.Symlink(target, p))
		}},
		{"directory file", "non_regular", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p := filepath.Join(r.Package, "vpn-core")
			mustVPN(t, os.Remove(p))
			mustVPN(t, os.Mkdir(p, 0o700))
		}},
		{"fifo", "non_regular", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			p := filepath.Join(r.Package, "vpn-core")
			mustVPN(t, os.Remove(p))
			mustVPN(t, unix.Mkfifo(p, 0o600))
		}},
		{"oversized binary", "file_too_large", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			mustVPN(t, os.Truncate(filepath.Join(r.Package, "vpn-core"), vpnCoreBinaryCap+1))
		}},
		{"oversized tool", "file_too_large", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			mustVPN(t, os.Truncate(filepath.Join(r.Package, "bin/sing-box"), vpnCoreToolCap+1))
		}},
		{"oversized manifest", "file_too_large", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			mustVPN(t, os.Truncate(filepath.Join(r.Package, "manifest.json"), vpnCoreManifestCap+1))
		}},
		{"extra file", "package_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			writeVPN(t, filepath.Join(r.Package, "extra"), nil)
		}},
		{"extra bin file", "package_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			writeVPN(t, filepath.Join(r.Package, "bin/extra"), nil)
		}},
		{"missing file", "package_entries", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			mustVPN(t, os.Remove(filepath.Join(r.Package, "vpn-core")))
		}},
		{"invalid manifest", "invalid_manifest", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			writeVPN(t, filepath.Join(r.Package, "manifest.json"), []byte("{}{}"))
		}},
		{"duplicate JSON version", "invalid_manifest", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			path := filepath.Join(r.Package, "manifest.json")
			writeVPN(t, path, bytes.Replace(readVPN(t, path), []byte(`"version":1`), []byte(`"version":2,"version":1`), 1))
		}},
		{"escape duplicate JSON version", "invalid_manifest", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			path := filepath.Join(r.Package, "manifest.json")
			writeVPN(t, path, bytes.Replace(readVPN(t, path), []byte(`"version":1`), []byte(`"version":2,"ver\u0073ion":1`), 1))
		}},
		{"foreign source owner", "source_owner", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) {
			f.s.ops.source.(*vpnCoreInProcessSource).uid = uint32(os.Getuid() + 1)
		}},
		{"root uid", "invalid_client", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { f.s.uid = 0 }},
		{"root gid", "invalid_client", func(t *testing.T, f *vpnFixture, r *VPNCoreRequest) { f.s.gid = 0 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newVPNFixture(t)
			base, d := f.pkg(t, "baseline", "old-tool")
			if r := f.install(t, base, d); !r.OK {
				t.Fatal(r.Error)
			}
			before := f.snapshot(t)
			f.calls = nil
			pkg, digest := f.pkg(t, "new binary", "new tool")
			r := &VPNCoreRequest{Target: "vpn-core", Package: pkg, ExpectedDigest: digest}
			tc.change(t, f, r)
			response := f.s.handle(ActionVPNCoreInstall, r)
			requireVPNCode(t, response, tc.code)
			if got := f.snapshot(t); got != before {
				t.Fatalf("install roots changed\nbefore=%s\nafter=%s", before, got)
			}
			if len(f.calls) != 0 {
				t.Fatal("launchctl on refusal", f.calls)
			}
			entries := auditVPN(t, f)
			if len(entries) < 3 || entries[len(entries)-1]["error_code"] != tc.code || entries[len(entries)-1]["outcome"] != "refused" {
				t.Fatalf("audit=%v", entries)
			}
		})
	}
}
func modifyVPNManifest(t *testing.T, dir string, change func(*vpnCoreManifest)) {
	t.Helper()
	var m vpnCoreManifest
	mustVPN(t, json.Unmarshal(readVPN(t, filepath.Join(dir, "manifest.json")), &m))
	change(&m)
	b, err := json.Marshal(m)
	mustVPN(t, err)
	writeVPN(t, filepath.Join(dir, "manifest.json"), b)
}

// Replacing a source after copy cannot invalidate a valid snapshot or bless a corrupt snapshot; hashing source paths instead makes these controls fail.
func TestVPNCoreTOCTOU(t *testing.T) {
	for _, validCopy := range []bool{true, false} {
		t.Run(fmt.Sprint(validCopy), func(t *testing.T) {
			f := newVPNFixture(t)
			pkg, digest := f.pkg(t, "reviewed", "tool")
			if !validCopy {
				writeVPN(t, filepath.Join(pkg, "vpn-core"), []byte("unreviewed"))
			}
			f.s.ops.afterCopy = func() {
				replacement := []byte("unreviewed")
				if !validCopy {
					replacement = []byte("reviewed")
				}
				path := filepath.Join(f.root, "replacement")
				writeVPN(t, path, replacement)
				mustVPN(t, os.Rename(path, filepath.Join(pkg, "vpn-core")))
			}
			before := f.snapshot(t)
			r := f.install(t, pkg, digest)
			if validCopy {
				if !r.OK {
					t.Fatal(r.Error)
				}
				if string(readVPN(t, filepath.Join(f.s.install, "vpn-core"))) != "reviewed" {
					t.Fatal("unverified replacement installed")
				}
			} else {
				requireVPNCode(t, r, "file_sha_mismatch")
				if before != f.snapshot(t) {
					t.Fatal("corrupt snapshot changed roots")
				}
			}
		})
	}
}

// Atomic swaps retain old trees across multiple updates, and rollback uses the previous tree's digest and plist hashes in both directions.
func TestVPNCoreSwapRollback(t *testing.T) {
	f := newVPNFixture(t)
	a, da := f.pkg(t, "a", "tool-a")
	b, db := f.pkg(t, "b", "tool-b")
	c, dc := f.pkg(t, "c", "tool-c")
	for _, p := range [][2]string{{a, da}, {b, db}, {c, dc}} {
		r := f.install(t, p[0], p[1])
		if !r.OK {
			t.Fatal(r.Error)
		}
	}
	if got := string(readVPN(t, filepath.Join(f.s.install+".previous", "vpn-core"))); got != "b" {
		t.Fatalf("previous=%q", got)
	}
	before := f.snapshot(t)
	requireVPNCode(t, f.rollback(da), "digest_mismatch")
	if f.snapshot(t) != before {
		t.Fatal("wrong rollback changed roots")
	}
	for _, d := range []string{db, dc} {
		r := f.rollback(d)
		if !r.OK || r.VPNCore.Digest != d {
			t.Fatalf("rollback=%+v", r)
		}
		want, err := renderVPNCorePlist(f.s.install, 501, 20, *r.VPNCore)
		mustVPN(t, err)
		if !bytes.Equal(want, readVPN(t, f.s.plist)) {
			t.Fatal("rollback plist hashes")
		}
	}
	r := f.s.handle(ActionVPNCoreStatus, &VPNCoreRequest{Target: "vpn-core"})
	if !r.OK || r.VPNCore.Digest != dc || r.VPNCore.PreviousDigest != db {
		t.Fatalf("status=%+v", r)
	}
}

// Missing previous trees refuse without mutation; each activation failure preserves a verifiable previous tree and reports a usable recovery path.
func TestVPNCoreRecovery(t *testing.T) {
	f := newVPNFixture(t)
	before := f.snapshot(t)
	requireVPNCode(t, f.rollback(strings.Repeat("0", 64)), "no_previous")
	if f.snapshot(t) != before {
		t.Fatal("missing rollback changed roots")
	}
	for _, fail := range []string{"bootout", "print", "enable", "bootstrap"} {
		t.Run(fail, func(t *testing.T) {
			f := newVPNFixture(t)
			a, da := f.pkg(t, "a", "tool-a")
			b, db := f.pkg(t, "b", "tool-b")
			if r := f.install(t, a, da); !r.OK {
				t.Fatal(r.Error)
			}
			f.fail = fail
			r := f.install(t, b, db)
			requireVPNCode(t, r, "restart_failed")
			previous, err := verifyVPNCorePackage(f.s.install + ".previous")
			mustVPN(t, err)
			if previous.Digest != da || r.VPNCore.RecoveryPath != f.s.install+".previous" {
				t.Fatalf("recovery=%+v", r)
			}
			f.fail = ""
			r = f.rollback(da)
			if !r.OK {
				t.Fatal(r.Error)
			}
			f.fail = fail
			r = f.rollback(db)
			requireVPNCode(t, r, "restart_failed")
			previous, err = verifyVPNCorePackage(f.s.install + ".previous")
			mustVPN(t, err)
			if previous.Digest != da {
				t.Fatal("rollback failure lost prior tree")
			}
		})
	}
}

// Concurrent mutations refuse busy, audit both attempts, and never install the refused package.
func TestVPNCoreBusy(t *testing.T) {
	f := newVPNFixture(t)
	pkg, digest := f.pkg(t, "binary", "tool")
	entered := make(chan struct{})
	release := make(chan struct{})
	f.s.ops.afterCopy = func() { close(entered); <-release }
	done := make(chan Response, 1)
	go func() { done <- f.install(t, pkg, digest) }()
	<-entered
	r := f.install(t, pkg, digest)
	requireVPNCode(t, r, "busy")
	close(release)
	if r := <-done; !r.OK {
		t.Fatal(r.Error)
	}
	entries := auditVPN(t, f)
	if len(entries) != 3 || entries[0]["outcome"] != "started" || entries[1]["error_code"] != "busy" || entries[2]["outcome"] != "accepted" {
		t.Fatalf("audit=%v", entries)
	}
}

// An atomic-swap error leaves both installed versions and the plist untouched, and temporary staging is removed.
func TestVPNCoreSwapFailure(t *testing.T) {
	f := newVPNFixture(t)
	a, da := f.pkg(t, "a", "tool-a")
	b, db := f.pkg(t, "b", "tool-b")
	if r := f.install(t, a, da); !r.OK {
		t.Fatal(r.Error)
	}
	before := f.snapshot(t)
	f.calls = nil
	f.s.ops.swap = func(string, string) error { return errors.New("injected atomic swap failure") }
	requireVPNCode(t, f.install(t, b, db), "io_error")
	if f.snapshot(t) != before || len(f.calls) != 0 {
		t.Fatal("swap refusal changed roots or launched service")
	}
}

// An unsafe audit destination reports audit_failed, never writes through its symlink, and retains the actual operation outcome in status.
func TestVPNCoreAuditFailure(t *testing.T) {
	f := newVPNFixture(t)
	target := filepath.Join(f.root, "sentinel")
	writeVPN(t, target, []byte("unchanged"))
	mustVPN(t, os.Symlink(target, f.s.audit))
	r := f.s.handle(ActionVPNCoreInstall, &VPNCoreRequest{Target: "other"})
	requireVPNCode(t, r, "audit_failed")
	if string(readVPN(t, target)) != "unchanged" || !strings.Contains(r.Error, "unknown_target") {
		t.Fatalf("response=%+v", r)
	}
}

// Construction pins install/plist/audit paths and the authorized staging/client identity without touching those paths.
func TestVPNCoreFixedConfiguration(t *testing.T) {
	s := newVPNCoreService(501, 20)
	if s.install != vpnCoreDirectory || s.plist != vpnCorePlist || s.audit != "/private/var/log/works.relux.mac-infra-vpn-core.jsonl" || s.uid != 501 || s.gid != 20 || s.ops.sourceTimeout != 120*time.Second || s.ops.source == nil || s.ops.rename == nil {
		t.Fatalf("unexpected fixed configuration: %+v", s)
	}
}

// The pinned package digest is sha256("works.relux.vpn-core.pkg/v1\x00" ||
// u64be(len) || vpn-core || u64be(len) || manifest.json). The expected values
// were computed outside Go (Python hashlib), so this checks the framing, not
// agreement with itself; multi-tun's install-digest must match the same rows.
// The ab|c and a|bc rows share an unframed digest and must not share a framed one.
func TestVPNPackageDigestVectors(t *testing.T) {
	for _, v := range []struct{ program, manifest, framed, unframed string }{
		{"", "", "48f4cf7557a6821acf170fc388daba69ad0d9d8a04fae38053e86126539f6b1d", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"ab", "c", "7ab31c62ae8201c0b1f863be472881cce7ee7ec82cbe8a727077536f37a29232", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"a", "bc", "9e0b399700882203bab875094e4867ab6edb2bb5738bdda78a87bb36e7ec96d2", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"vpn-core\x00\xff", "{\"version\":1}\n", "b4a2a21540e568c0aa15ced42cff78fd96c67a561d831b7fe1fc647fa85e99db", "230585662613f457e6addb9f6fa4b3bfc9e0d81edbeb0d8707be8b9b19f7fd96"},
	} {
		if got := vpnPackageDigest([]byte(v.program), []byte(v.manifest)); got != v.framed {
			t.Fatalf("%q|%q framed = %s, want %s", v.program, v.manifest, got, v.framed)
		}
		if got := vpnSHA([]byte(v.program + v.manifest)); got != v.unframed || got == v.framed {
			t.Fatalf("%q|%q unframed control = %s", v.program, v.manifest, got)
		}
	}
}
