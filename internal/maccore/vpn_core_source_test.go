package maccore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

type vpnCoreSourceFunc func(context.Context, string, int, int, func(io.Reader) error) error

func (f vpnCoreSourceFunc) Read(ctx context.Context, pkg string, uid, gid int, consume func(io.Reader) error) error {
	return f(ctx, pkg, uid, gid, consume)
}

type vpnCoreInProcessSource struct{ uid uint32 }

func (s *vpnCoreInProcessSource) Read(_ context.Context, pkg string, _, _ int, consume func(io.Reader) error) error {
	// Real OS pipes and production worker framing, without changing credentials.
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		err := streamVPNCoreSource(pkg, s.uid, writer)
		_ = writer.Close()
		done <- err
	}()
	consumeErr := consume(reader)
	_ = reader.Close()
	if err := <-done; err != nil {
		return err
	}
	return consumeErr
}

// Claim: this subprocess entry invokes only the source worker, or a finite blocked-reader fixture; it never starts a daemon or executes package bytes.
func TestVPNCoreWorkerProcess(t *testing.T) {
	for i, arg := range os.Args {
		if arg != "--vpn-source-test" {
			continue
		}
		mode, pkg := os.Args[i+1], os.Args[i+2]
		switch mode {
		case "worker":
			os.Exit(RunVPNCoreSource([]string{pkg}, os.Stdout, os.Stderr))
		case "block":
			time.Sleep(2 * time.Second)
			os.Exit(0)
		case "unknown":
			fmt.Fprintln(os.Stderr, `{"code":"made_up"}`)
			os.Exit(1)
		case "oversized":
			_ = binary.Write(os.Stdout, binary.BigEndian, uint64(vpnCoreBinaryCap+1))
			os.Exit(0)
		}
		os.Exit(2)
	}
}

func vpnExecFixture(t *testing.T, mode string, observe func(*exec.Cmd)) (*vpnCoreExecSource, **exec.Cmd) {
	t.Helper()
	binaryPath, err := os.Executable()
	mustVPN(t, err)
	var started *exec.Cmd
	source := &vpnCoreExecSource{
		executable: func() (string, error) { return binaryPath, nil },
		start: func(cmd *exec.Cmd) error {
			if observe != nil {
				observe(cmd)
			}
			started = cmd
			pkg := cmd.Args[2]
			// Test process cannot setgroups/setuid: inspect production credentials
			// above, then execute this source-only helper as the current user.
			cmd.SysProcAttr.Credential = nil
			cmd.Args = []string{binaryPath, "-test.run=^TestVPNCoreWorkerProcess$", "--", "--vpn-source-test", mode, pkg}
			return cmd.Start()
		},
	}
	return source, &started
}

// Claim: a source behind an unreadable ancestor is refused with client credentials configured before exec; the readable control streams successfully. No root-owned fixture or setuid is used.
func TestVPNCoreWorkerCredentials(t *testing.T) {
	f := newVPNFixture(t)
	pkg, digest := f.pkg(t, "binary", "tool")
	ancestor := filepath.Join(f.root, "restricted")
	mustVPN(t, os.Mkdir(ancestor, 0o700))
	nested := filepath.Join(ancestor, "package")
	mustVPN(t, os.Rename(pkg, nested))
	pkg = nested
	starts := 0
	source, _ := vpnExecFixture(t, "worker", func(cmd *exec.Cmd) {
		starts++
		cred := cmd.SysProcAttr.Credential
		if cred == nil || cred.Uid != uint32(f.s.uid) || cred.Gid != uint32(f.s.gid) || len(cred.Groups) != 0 || cred.NoSetGroups {
			t.Fatalf("worker must drop to client credentials with no supplementary groups: %+v", cred)
		}
		stdin, ok := cmd.Stdin.(*os.File)
		if cmd.Dir != "/" || cmd.Env == nil || len(cmd.Env) != 0 || !ok || stdin.Name() != os.DevNull || !filepath.IsAbs(cmd.Path) || !reflect.DeepEqual(cmd.Args[1:], []string{"_vpn-core-source", pkg}) {
			t.Fatalf("unsafe worker process configuration: %+v", cmd)
		}
	})
	f.s.ops.source = source
	before := f.snapshot(t)
	// Mode 000 models the access boundary of a root-only ancestor. Both this
	// worker and the test run unprivileged; kernel access denial is real.
	mustVPN(t, os.Chmod(ancestor, 0))
	t.Cleanup(func() { _ = os.Chmod(ancestor, 0o700) })
	refused := f.install(t, pkg, digest)
	requireVPNCode(t, refused, "source_unreadable")
	if refused.VPNCore.Digest != "" || refused.VPNCore.BinarySHA256 != "" || refused.VPNCore.ManifestSHA256 != "" {
		t.Fatal("unreadable source disclosed hashes")
	}
	mustVPN(t, os.Chmod(ancestor, 0o700))
	if f.snapshot(t) != before || len(f.calls) != 0 || starts != 1 {
		t.Fatal("unreadable source had effects or did not start worker")
	}
	if r := f.install(t, pkg, digest); !r.OK {
		t.Fatal(r.Error)
	}
	if starts != 2 {
		t.Fatal("readable control did not use worker")
	}
}

// Claim: a blocked exec worker is killed and reaped by the deadline; its stage is removed and both status and a subsequent install can acquire the mutex.
func TestVPNCoreWorkerDeadline(t *testing.T) {
	f := newVPNFixture(t)
	pkg, digest := f.pkg(t, "binary", "tool")
	source, started := vpnExecFixture(t, "block", nil)
	f.s.ops.source = source
	f.s.ops.sourceTimeout = 100 * time.Millisecond
	before := f.snapshot(t)
	begin := time.Now()
	requireVPNCode(t, f.install(t, pkg, digest), "source_timeout")
	if time.Since(begin) > time.Second {
		t.Fatal("deadline did not kill blocking worker promptly")
	}
	cmd := *started
	if cmd == nil || cmd.ProcessState == nil {
		t.Fatal("worker was not reaped")
	}
	state := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !state.Signaled() || state.Signal() != syscall.SIGKILL {
		t.Fatalf("worker was not killed: %v", cmd.ProcessState)
	}
	if f.snapshot(t) != before || len(f.calls) != 0 {
		t.Fatal("timeout left staging or activation effects")
	}
	r := f.s.handle(ActionVPNCoreStatus, &VPNCoreRequest{Target: "vpn-core"})
	if !r.OK || r.VPNCore.State != "absent" {
		t.Fatalf("status after timeout: %+v", r)
	}
	f.s.ops.source = &vpnCoreInProcessSource{uid: uint32(os.Getuid())}
	if r := f.install(t, pkg, digest); !r.OK {
		t.Fatalf("mutex not reusable: %+v", r)
	}
}

// Claim: truncated lengths/payloads, per-file overflow and trailing bytes refuse, clean staging and preserve installed state; production pipe framing is a positive control.
func TestVPNCoreSourceFrames(t *testing.T) {
	for _, variant := range []string{"header", "payload", "oversized", "trailing"} {
		t.Run(variant, func(t *testing.T) {
			f := newVPNFixture(t)
			pkg, digest := f.pkg(t, "binary", "tool")
			if r := f.install(t, pkg, digest); !r.OK {
				t.Fatal(r.Error)
			}
			before := f.snapshot(t)
			f.calls = nil
			var stream bytes.Buffer
			switch variant {
			case "header":
				stream.WriteByte(0)
			case "payload":
				mustVPN(t, binary.Write(&stream, binary.BigEndian, uint64(10)))
				stream.WriteString("short")
			case "oversized":
				mustVPN(t, binary.Write(&stream, binary.BigEndian, uint64(vpnCoreBinaryCap+1)))
			case "trailing":
				mustVPN(t, streamVPNCoreSource(pkg, uint32(os.Getuid()), &stream))
				stream.WriteByte(1)
			}
			f.s.ops.source = vpnCoreSourceFunc(func(_ context.Context, _ string, _, _ int, consume func(io.Reader) error) error {
				return consume(&stream)
			})
			requireVPNCode(t, f.install(t, pkg, digest), "source_stream")
			if before != f.snapshot(t) || len(f.calls) != 0 {
				t.Fatal("bad frame changed installation")
			}
		})
	}
}

// Claim: exec preserves known bounded stderr refusal codes; unknown failures and malformed/overflow diagnostics cannot manufacture a daemon code.
func TestVPNCoreWorkerRefusals(t *testing.T) {
	f := newVPNFixture(t)
	pkg, digest := f.pkg(t, "binary", "tool")
	mustVPN(t, os.WriteFile(filepath.Join(pkg, "extra"), nil, 0o600))
	source, _ := vpnExecFixture(t, "worker", nil)
	f.s.ops.source = source
	requireVPNCode(t, f.install(t, pkg, digest), "package_entries")
	malformed, _ := vpnExecFixture(t, "oversized", nil)
	f.s.ops.source = malformed
	requireVPNCode(t, f.install(t, pkg, digest), "source_stream")
	source, _ = vpnExecFixture(t, "unknown", nil)
	f.s.ops.source = source
	requireVPNCode(t, f.install(t, pkg, digest), "source_failed")
	for _, diagnostic := range []string{`{"code":"busy"}` + "\n", `{"code":"symlink"}`, strings.Repeat("x", 1025), "{}\n{}\n"} {
		stderr := &vpnCoreWorkerStderr{}
		_, _ = stderr.Write([]byte(diagnostic))
		if code := vpnCoreWorkerCode(stderr); code != "" {
			t.Fatalf("invalid diagnostic mapped to %s", code)
		}
	}
}

// Claim: both post-swap rename faults restore current, previous, plist and status exactly, perform no activation and preserve the next rollback.
func TestVPNCoreRenameCompensation(t *testing.T) {
	for _, failAt := range []int{1, 2} {
		t.Run(fmt.Sprint(failAt), func(t *testing.T) {
			f := newVPNFixture(t)
			a, da := f.pkg(t, "a", "tool-a")
			b, db := f.pkg(t, "b", "tool-b")
			c, dc := f.pkg(t, "c", "tool-c")
			for _, pair := range [][2]string{{a, da}, {b, db}} {
				if r := f.install(t, pair[0], pair[1]); !r.OK {
					t.Fatal(r.Error)
				}
			}
			before := f.snapshot(t)
			statusBefore := f.s.handle(ActionVPNCoreStatus, &VPNCoreRequest{Target: "vpn-core"})
			f.calls = nil
			renames := 0
			f.s.ops.rename = func(from, to string) error {
				renames++
				if renames == failAt {
					return errors.New("injected post-swap rename failure")
				}
				return os.Rename(from, to)
			}
			requireVPNCode(t, f.install(t, c, dc), "io_error")
			statusAfter := f.s.handle(ActionVPNCoreStatus, &VPNCoreRequest{Target: "vpn-core"})
			if before != f.snapshot(t) || !reflect.DeepEqual(statusBefore, statusAfter) || len(f.calls) != 0 {
				t.Fatal("compensation did not restore exact mapping/status/plist")
			}
			if r := f.rollback(da); !r.OK || r.VPNCore.Digest != da {
				t.Fatalf("rollback after compensation: %+v", r)
			}
		})
	}
}

// Claim: valid install and rollback refuse unusable audit destinations before any stage, swap, plist change or launch call; normal intent is durable before source work or rollback swap.
func TestVPNCoreIntentAudit(t *testing.T) {
	for _, action := range []Action{ActionVPNCoreInstall, ActionVPNCoreRollback} {
		t.Run(string(action), func(t *testing.T) {
			f := newVPNFixture(t)
			a, da := f.pkg(t, "a", "tool-a")
			b, db := f.pkg(t, "b", "tool-b")
			for _, pair := range [][2]string{{a, da}, {b, db}} {
				if r := f.install(t, pair[0], pair[1]); !r.OK {
					t.Fatal(r.Error)
				}
			}
			before := f.snapshot(t)
			f.calls = nil
			audit := f.s.audit
			sentinel := filepath.Join(f.root, "sentinel")
			writeVPN(t, sentinel, []byte("unchanged"))
			mustVPN(t, os.Remove(audit))
			mustVPN(t, os.Symlink(sentinel, audit))
			req := &VPNCoreRequest{Target: "vpn-core", ExpectedDigest: da}
			if action == ActionVPNCoreInstall {
				req.Package = a
			}
			requireVPNCode(t, f.s.handle(action, req), "audit_failed")
			if f.snapshot(t) != before || len(f.calls) != 0 || string(readVPN(t, sentinel)) != "unchanged" {
				t.Fatal("failed intent audit allowed mutation")
			}
			mustVPN(t, os.Remove(audit))
			assertIntent := func() {
				entries := auditVPN(t, f)
				entry := entries[len(entries)-1]
				if entry["action"] != string(action) || entry["digest"] != da || entry["outcome"] != "started" {
					t.Fatalf("mutation preceded durable intent: %v", entry)
				}
			}
			if action == ActionVPNCoreInstall {
				delegate := f.s.ops.source
				f.s.ops.source = vpnCoreSourceFunc(func(ctx context.Context, pkg string, uid, gid int, consume func(io.Reader) error) error {
					assertIntent()
					return delegate.Read(ctx, pkg, uid, gid, consume)
				})
			} else {
				f.s.ops.swap = func(a, b string) error { assertIntent(); return swapVPNCoreTrees(a, b) }
			}
			if r := f.s.handle(action, req); !r.OK {
				t.Fatal(r.Error)
			}
		})
	}
}

// Claim: case aliases, conflicting aliases, escaped aliases and missing keys are refused before publication; escaped canonical names remain valid.
func TestVPNCoreManifestExactKeys(t *testing.T) {
	variants := []string{"Version", "Files", "SHA256", "escaped-Version", "escaped-Files", "escaped-SHA256", "conflict-Version", "conflict-Files", "conflict-SHA256", "missing-version", "missing-files", "missing-path", "missing-sha256", "canonical-escape"}
	for _, variant := range variants {
		t.Run(variant, func(t *testing.T) {
			f := newVPNFixture(t)
			pkg, _ := f.pkg(t, "binary", "tool")
			raw := string(readVPN(t, filepath.Join(pkg, "manifest.json")))
			switch {
			case strings.HasPrefix(variant, "missing-"):
				var top map[string]json.RawMessage
				mustVPN(t, json.Unmarshal([]byte(raw), &top))
				key := strings.TrimPrefix(variant, "missing-")
				if key == "version" || key == "files" {
					delete(top, key)
				} else {
					var files []map[string]json.RawMessage
					mustVPN(t, json.Unmarshal(top["files"], &files))
					delete(files[0], key)
					top["files"], _ = json.Marshal(files)
				}
				data, err := json.Marshal(top)
				mustVPN(t, err)
				raw = string(data)
			case variant == "canonical-escape":
				raw = strings.Replace(raw, `"sha256"`, `"sha\u003256"`, 1)
			default:
				alias := strings.TrimPrefix(strings.TrimPrefix(variant, "escaped-"), "conflict-")
				canonical := strings.ToLower(alias)
				encoded := alias
				if strings.HasPrefix(variant, "escaped-") {
					encoded = fmt.Sprintf(`\u%04x%s`, alias[0], alias[1:])
				}
				raw = strings.Replace(raw, `"`+canonical+`"`, `"`+encoded+`"`, 1)
				if strings.HasPrefix(variant, "conflict-") {
					// Case aliases beside canonical keys must not select a value
					// according to Go's case-insensitive struct decoder.
					raw = strings.Replace(raw, `"`+encoded+`":`, `"`+canonical+`":null,"`+encoded+`":`, 1)
				}
			}
			writeVPN(t, filepath.Join(pkg, "manifest.json"), []byte(raw))
			digest := vpnSHA(append([]byte("binary"), []byte(raw)...))
			before := f.snapshot(t)
			r := f.install(t, pkg, digest)
			if variant == "canonical-escape" {
				if !r.OK {
					t.Fatal(r.Error)
				}
				return
			}
			requireVPNCode(t, r, "invalid_manifest")
			if before != f.snapshot(t) || len(f.calls) != 0 {
				t.Fatal("ambiguous manifest published")
			}
		})
	}
}
