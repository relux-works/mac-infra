package netnone

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// F1: the reviewer's heredoc body cannot forge an approved stage; a real pinned stage still works.
func TestToolchainHeredocStageForgery(t *testing.T) {
	h := newHarness(t)
	witness := "FROM " + BaseImage + "\nCOPY <<EOF /fake\nFROM " + BaseImage + " AS ubuntu\nEOF\nFROM ubuntu\n"
	h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
	writeFixture(t, h.o.Toolchain, witness, 0600)
	h.exec(t, "prep", 2)
	if len(h.f.calls) != 0 {
		t.Fatal("heredoc forgery reached runner")
	}
	writeFixture(t, h.o.Toolchain, "FROM "+BaseImage+" AS ubuntu\nFROM ubuntu\n", 0600)
	h.exec(t, "prep", 0)
}

func writeFixture(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to the umask; set the exact mode so permission
	// assertions start from what the fixture claims.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// F2/F3: all operational calls share the private namespace despite inherited root/context overrides.
// Shared-state snapshots alone retain the original user environment.
func TestPrivateColimaNamespace(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "prep", 0)
	h.exec(t, "run", 0)
	h.exec(t, "status", 0)
	h.exec(t, "stop", 0)
	for _, c := range h.f.calls {
		want := map[string]string{
			"COLIMA_HOME":   filepath.Join(h.home, ".colima-netnone"),
			"LIMA_HOME":     filepath.Join(h.home, ".colima-netnone/_lima"),
			"DOCKER_HOST":   "unix://" + filepath.Join(h.home, ".colima-netnone/netnone/docker.sock"),
			"DOCKER_CONFIG": filepath.Join(h.state, "docker-config"),
		}
		for key, value := range want {
			count := 0
			for _, v := range c.Env {
				if strings.HasPrefix(v, key+"=") {
					count++
					if v != key+"="+value {
						t.Fatalf("wrong %s in %s %v", v, c.Name, c.Args)
					}
				}
			}
			if count != 1 {
				t.Fatalf("%s count=%d for %s %v", key, count, c.Name, c.Args)
			}
		}
	}
	assertPrivate(t, h)
	h.f.calls = nil
	h.f.fixtureMode = "qualified"
	h.exec(t, "selftest", 0)
	assertPrivate(t, h)
}

// F4: failed/cancelled startup always attempts a fresh-context stop, surfaces its error, and records no prep.
func TestStartupRollback(t *testing.T) {
	for _, mode := range []string{"failed", "cancelled", "stop-failed"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h.f.hook = func(stopCtx context.Context, c Command) (Result, error, bool) {
				if c.Name == "colima" && c.Args[0] == "start" {
					if mode == "cancelled" {
						cancel()
						return Result{}, context.Canceled, true
					}
					return Result{ExitCode: 7, Stderr: []byte("runtime provisioning failed")}, nil, true
				}
				if c.Name == "colima" && c.Args[0] == "stop" {
					if stopCtx.Err() != nil {
						t.Fatal("rollback reused cancelled context")
					}
					if mode == "stop-failed" {
						return Result{ExitCode: 9}, nil, true
					}
				}
				return Result{}, nil, false
			}
			if got := h.e.Execute(ctx, "prep", h.o); got != 1 {
				t.Fatalf("startup exit=%d", got)
			}
			if len(callsNamed(h.f.calls, "colima", "stop")) != 1 {
				t.Fatal("startup rollback stop missing")
			}
			if !strings.Contains(h.out.String(), "colima stop --profile netnone:") {
				t.Fatal("rollback was not reported")
			}
			if mode == "stop-failed" && !strings.Contains(h.err.String(), "stop failed") {
				t.Fatal("stop failure lost")
			}
			if len(callsNamed(h.f.calls, "docker", "build")) != 0 {
				t.Fatal("failed startup ran work")
			}
			if _, err := os.Stat(filepath.Join(h.state, "prep-records.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed startup wrote record")
			}
		})
	}
}

// F5: keeper's NDJSON name/status schema tolerates extra fields, distinguishes missing/stopped/running,
// and rejects unknown states, malformed evidence, duplicate target rows and all listing errors.
func TestProfileListSchema(t *testing.T) {
	fixture, err := os.ReadFile("testdata/colima-list.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, data, want string
		exit             int
	}{
		{"real-format", string(fixture), "stopped", 0},
		{"running", strings.Replace(string(fixture), `"name":"netnone","status":"Stopped"`, `"name":"netnone","status":"Running"`, 1), "running", 0},
		{"missing", `{"name":"default","status":"Running"}`, "stopped", 0},
		{"empty", "", "stopped", 0}, {"array", "[]", "stopped", 0},
		{"unknown", `{"name":"netnone","status":"Starting"}`, "", 0},
		{"missing-status", `{"name":"netnone"}`, "", 0},
		{"wrong-keys", `{"Name":"netnone","Status":"Stopped"}`, "", 0},
		{"wrong-type", `{"name":"netnone","status":true}`, "", 0},
		{"lowercase-state", `{"name":"netnone","status":"stopped"}`, "", 0},
		{"invalid", "not JSON", "", 0}, {"not-found-error", "profile not found", "", 1},
		{"duplicate", string(fixture) + string(fixture), "", 0},
	} {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if !reflect.DeepEqual(c.Args, []string{"list", "--json"}) {
					t.Fatalf("wrong profile query %v", c.Args)
				}
				return Result{Stdout: []byte(row.data), Stderr: []byte("not found"), ExitCode: row.exit}, nil, true
			}
			s := session{e: h.e, env: privateEnv(h.e.UserEnv, h.home, h.state)}
			got, err := s.profile(context.Background())
			if got != row.want || (err != nil) != (row.want == "") {
				t.Fatalf("state=%q err=%v want=%q", got, err, row.want)
			}
		})
	}
}

// F6: replacing the source Dockerfile during VM startup cannot change the bytes built or their recorded hash.
func TestBuildValidatedBytes(t *testing.T) {
	h := newHarness(t)
	h.o.Toolchain = filepath.Join(h.root, "toolchain", "Dockerfile")
	original := "FROM " + BaseImage + "\nENTRYPOINT [\"ignored\"]\n"
	writeFixture(t, h.o.Toolchain, original, 0600)
	h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
		if c.Name == "colima" && c.Args[0] == "start" {
			writeFixture(t, h.o.Toolchain, "FROM ubuntu\n", 0600)
		}
		return Result{}, nil, false
	}
	h.exec(t, "prep", 0)
	builds := callsNamed(h.f.calls, "docker", "build")
	if len(builds) != 2 {
		t.Fatalf("builds=%d", len(builds))
	}
	base, _ := assets.ReadFile("assets/Dockerfile")
	for i, want := range []string{string(base), original} {
		c := builds[i]
		if !has(c.Args, "-f", "-") || c.Stdin == nil {
			t.Fatalf("build reopened path: %v", c.Args)
		}
		got, err := io.ReadAll(c.Stdin)
		if err != nil || string(got) != want {
			t.Fatalf("built different bytes: %s %v", got, err)
		}
	}
	if builds[1].Args[len(builds[1].Args)-1] != filepath.Dir(h.o.Toolchain) {
		t.Fatal("caller context changed")
	}
	s := session{state: h.state}
	records, err := s.records()
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(original))
	if _, ok := records[recordKey(h.o.Repo, hex.EncodeToString(sum[:]))]; !ok {
		t.Fatal("record does not match validated bytes")
	}
}

// F7: toolchain ENTRYPOINT cannot replace prep/run shell commands or the qualification Java probe.
func TestExplicitContainerEntrypoints(t *testing.T) {
	h := newHarness(t)
	h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
	writeFixture(t, h.o.Toolchain, "FROM "+BaseImage+"\nENTRYPOINT [\"false\"]\n", 0600)
	h.exec(t, "prep", 0)
	h.exec(t, "run", 0)
	h.f.fixtureMode = "qualified"
	h.exec(t, "selftest", 0)
	kinds := map[string]bool{}
	for _, c := range callsNamed(h.f.calls, "docker", "run") {
		kind, entry := "probe", "java"
		if has(c.Args, "netnone-prep") {
			kind, entry = "prep", "/bin/sh"
		}
		if has(c.Args, "netnone-run") {
			kind, entry = "run", "/bin/sh"
		}
		if !has(c.Args, "--entrypoint", entry, testImage) {
			t.Fatalf("%s inherited entrypoint: %v", kind, c.Args)
		}
		if entry == "/bin/sh" && !has(c.Args, testImage, "-c") {
			t.Fatalf("shell command not positional: %v", c.Args)
		}
		kinds[kind] = true
	}
	if len(kinds) != 3 {
		t.Fatalf("missing container kinds: %v", kinds)
	}
}

// shellFixture executes only fixed guest scripts with local fake tools in t.TempDir.
// Its tar fake emits/extracts a real local archive, with independently injected producer/consumer failures.
func shellFixture(t *testing.T, script, mode string, dirs ...string) (string, error) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"src", "work", "tmp", "out", "bin"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(filepath.Join(root, "src", dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeFixture(t, filepath.Join(root, "src", "omitted.txt"), "source skipped by failing archive producer", 0600)
	writeFixture(t, filepath.Join(root, "src", "gradlew"), `#!/bin/sh
case " $* " in *" --dry-run "*) echo dry-run-ok; exit 0;; esac
if [ "$FAKE_MODE" = dependency ]; then echo 'Could not resolve dependency' >&2; exit 7; fi
if [ "$FAKE_MODE" = test-failed ]; then mkdir -p module/build/test-results/test; echo '<testsuite/>' > module/build/test-results/test/TEST.xml; exit 1; fi
exit 0
`, 0700)
	writeFixture(t, filepath.Join(root, "bin", "java"), "#!/bin/sh\nexit 0\n", 0700)
	writeFixture(t, filepath.Join(root, "bin", "tar"), `#!/bin/sh
case " $* " in
 *" -cf "*) if [ "$FAKE_MODE" = producer ]; then /usr/bin/tar -cf - ./gradlew; exit 7; fi; exec /usr/bin/tar -cf - .;;
 *" -xf "*) /usr/bin/tar -xf -; rc=$?; if [ "$FAKE_MODE" = consumer ]; then exit 8; fi; exit "$rc";;
esac
exit 99
`, 0700)
	// Substitute only fixed absolute guest paths, never interpolate fixture input into shell code.
	script = strings.NewReplacer("/src", filepath.Join(root, "src"), "/work", filepath.Join(root, "work"), "/tmp", filepath.Join(root, "tmp"), "/out", filepath.Join(root, "out")).Replace(script)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "fixture", "test")
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":/usr/bin:/bin", "FAKE_MODE="+mode)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("guest fixture timed out: %s", out)
	}
	if mode == "producer" {
		if _, err := os.Stat(filepath.Join(root, "work", "gradlew")); err != nil {
			t.Fatal("producer control did not extract a valid partial archive", err)
		}
		if _, err := os.Stat(filepath.Join(root, "work", "omitted.txt")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("producer control did not omit a source file")
		}
	}
	return string(out), err
}

// F8: even a valid partial archive with successful extraction is rejected on the producer's own exit status.
func TestCopySourceProducerFailure(t *testing.T) {
	out, err := shellFixture(t, copySource+"echo copy-completed\n", "producer")
	if err == nil || !strings.Contains(out, "source archive creation failed") || strings.Contains(out, "copy-completed") {
		t.Fatalf("producer failure masked: err=%v out=%s", err, out)
	}
}

// F8: extraction failure is independently rejected; ordinary source copying succeeds.
func TestCopySourceExtraction(t *testing.T) {
	out, err := shellFixture(t, copySource+"echo copy-completed\n", "consumer")
	if err == nil || !strings.Contains(out, "source extraction failed") {
		t.Fatalf("extraction failure masked: %v %s", err, out)
	}
	out, err = shellFixture(t, copySource+"echo copy-completed\n", "")
	if err != nil || !strings.Contains(out, "copy-completed") {
		t.Fatalf("copy rejected: %v %s", err, out)
	}
}

// F8: newline-bearing excluded directory names fail clearly; spaces and non-excluded newline source names are allowed.
func TestCopySourceNewlineExclusion(t *testing.T) {
	for _, dir := range []string{"a\nb/.gradle", ".gradle\na/.gradle"} {
		out, err := shellFixture(t, copySource, "", dir)
		if err == nil || !strings.Contains(out, "excluded directory path contains a newline") {
			t.Fatalf("newline exclusion admitted: %q %v %s", dir, err, out)
		}
	}
	if out, err := shellFixture(t, copySource, "", "a b/.gradle", "a\nb/src"); err != nil {
		t.Fatalf("safe source refused: %v %s", err, out)
	}
}

// F9: a post-dry-run dependency failure has no XML and fails prep without a record; an evidenced test failure is tolerated.
func TestWarmTaskRequiresResults(t *testing.T) {
	for _, mode := range []string{"dependency", "test-failed", "success"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if has(c.Args, "netnone-prep") {
					var script string
					for i, a := range c.Args {
						if a == "-c" {
							script = c.Args[i+1]
							break
						}
					}
					out, err := shellFixture(t, script, mode)
					code := 0
					if err != nil {
						var exit *exec.ExitError
						if !errors.As(err, &exit) {
							t.Fatal(err)
						}
						code = exit.ExitCode()
					}
					if !strings.Contains(out, "dry-run-ok") {
						t.Fatalf("control did not reach successful dry run: %s", out)
					}
					return Result{Stdout: []byte(out), ExitCode: code}, nil, true
				}
				return Result{}, nil, false
			}
			want := 0
			if mode == "dependency" {
				want = 1
			}
			h.exec(t, "prep", want)
			_, err := os.Stat(filepath.Join(h.state, "prep-records.json"))
			if want == 1 && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("bootstrap failure wrote prep record")
			}
			if want == 0 && err != nil {
				t.Fatal("successful warm task missing record", err)
			}
		})
	}
}

// F10: only the current timestamp is exposed to a test; old artifacts are inaccessible through /out and retain their contents/modes.
func TestCurrentRunOutputIsolation(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "prep", 0)
	previous := filepath.Join(h.o.Out, "previous", "result.xml")
	writeFixture(t, previous, "old evidence", 0600)
	h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
		if has(c.Args, "netnone-run") {
			var bind string
			for _, a := range c.Args {
				if strings.HasSuffix(a, ":/out") {
					bind = strings.TrimSuffix(a, ":/out")
				}
			}
			if bind == "" || bind == h.o.Out || filepath.Dir(bind) != h.o.Out {
				t.Fatalf("previous outputs exposed: bind=%q root=%q", bind, h.o.Out)
			}
			if _, err := os.Stat(filepath.Join(bind, "previous", "result.xml")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("previous run is visible")
			}
			writeFixture(t, filepath.Join(bind, "build", "test-results", "TEST.xml"), "new evidence", 0666)
		}
		return Result{}, nil, false
	}
	h.exec(t, "run", 0)
	data, _ := os.ReadFile(previous)
	if string(data) != "old evidence" {
		t.Fatal("old artifacts changed")
	}
	st, _ := os.Stat(previous)
	if st.Mode().Perm() != 0600 {
		t.Fatal("old artifact permissions changed")
	}
	entries, _ := os.ReadDir(h.o.Out)
	for _, entry := range entries {
		if entry.Name() == "previous" {
			continue
		}
		dest := filepath.Join(h.o.Out, entry.Name())
		st, err := os.Stat(dest)
		if err != nil || st.Mode().Perm() != 0755 {
			t.Fatalf("current output not restricted: %v %v", st, err)
		}
		st, err = os.Stat(filepath.Join(dest, "build/test-results/TEST.xml"))
		if err != nil || st.Mode().Perm() != 0644 {
			t.Fatalf("result not restricted: %v %v", st, err)
		}
	}
}

const validJUnit = `<testsuite><testcase classname="OfflineTest" name="arithmetic"/><testcase classname="OfflineTest" name="buildPackageWasCopied"/><testcase classname="NetworkTest" name="repositoryReachable"><failure type="java.net.UnknownHostException">repo.maven.apache.org</failure></testcase></testsuite>`

// F11: every expected fixture method is required; no unrelated passing method can replace the source-copy witness.
func TestJUnitCompleteTestcaseSet(t *testing.T) {
	for _, row := range []struct {
		name, xml string
		off, net  bool
	}{
		{"complete", validJUnit, true, true},
		{"missing-copy", strings.Replace(validJUnit, `<testcase classname="OfflineTest" name="buildPackageWasCopied"/>`, "", 1), false, true},
		{"missing-arithmetic", strings.Replace(validJUnit, `<testcase classname="OfflineTest" name="arithmetic"/>`, "", 1), false, true},
		{"wrong-offline-method", strings.Replace(validJUnit, "buildPackageWasCopied", "other", 1), false, true},
		{"wrong-network-method", strings.Replace(validJUnit, "repositoryReachable", "other", 1), true, false},
		{"junit5-methods", strings.NewReplacer(`name="arithmetic"`, `name="arithmetic()"`, `name="buildPackageWasCopied"`, `name="buildPackageWasCopied()"`, `name="repositoryReachable"`, `name="repositoryReachable()"`).Replace(validJUnit), true, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			writeFixture(t, filepath.Join(root, "build/test-results/test/TEST.xml"), row.xml, 0600)
			off, net, detail := inspectJUnit(root)
			if off != row.off || net != row.net {
				t.Fatalf("incomplete testcase verdict off=%t net=%t: %s", off, net, detail)
			}
		})
	}
}

// F11: exception types must be actual network-denial evidence, not an assertion mentioning a network exception.
func TestJUnitExceptionIdentity(t *testing.T) {
	for _, row := range []struct {
		kind, text string
		want       bool
	}{
		{"java.net.UnknownHostException", "repo.maven.apache.org", true},
		{"java.net.NoRouteToHostException", "No route to host", true},
		{"java.net.SocketException", "Network is unreachable", true},
		{"", "java.net.UnknownHostException: repo.maven.apache.org", true},
		{"java.lang.AssertionError", "expected java.net.UnknownHostException", false},
		{"", "java.lang.AssertionError: expected java.net.UnknownHostException", false},
		{"java.net.ConnectException", "Connection refused", false},
		{"java.net.SocketException", "Connection reset", false},
		{"java.net.UnknownHostException", "Could not resolve dependencies", false},
	} {
		t.Run(fmt.Sprintf("%s-%s", row.kind, row.text), func(t *testing.T) {
			root := t.TempDir()
			xml := strings.Replace(validJUnit, `type="java.net.UnknownHostException">repo.maven.apache.org`, `type="`+row.kind+`">`+row.text, 1)
			writeFixture(t, filepath.Join(root, "build/test-results/test/TEST.xml"), xml, 0600)
			off, net, detail := inspectJUnit(root)
			if !off || net != row.want {
				t.Fatalf("misleading exception verdict=%t: %s", net, detail)
			}
		})
	}
}

// F11: connection refused is not an unreachable-network control; unreachable and no-route probes qualify.
func TestDeniedTCPRequiresUnreachable(t *testing.T) {
	for _, row := range []struct {
		text string
		want bool
	}{
		{"tcp=fail:java.net.ConnectException:Connection refused", false},
		{"tcp=fail:java.net.SocketException:Network is unreachable", true},
		{"tcp=fail:java.net.NoRouteToHostException:No route to host", true},
		{"tcp=ok", false},
	} {
		if got := deniedTCP(row.text); got != row.want {
			t.Fatalf("%q verdict=%t", row.text, got)
		}
	}
}

// F12: stable names/statuses cannot hide endpoint or default-home profile config drift; private home config is excluded.
func TestSnapshotContextAndProfileConfig(t *testing.T) {
	for _, mode := range []string{"context", "profile", "private-home"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			profile := filepath.Join(h.home, ".colima/default/colima.yaml")
			private := filepath.Join(h.home, ".colima-netnone/netnone/colima.yaml")
			writeFixture(t, profile, "memory: 8", 0600)
			writeFixture(t, private, "memory: 8", 0600)
			s := session{e: h.e, home: h.home}
			before, err := s.snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "context":
				h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
					if has(c.Args, "context", "inspect") {
						if !reflect.DeepEqual(c.Env, h.e.UserEnv) {
							t.Fatal("context inspection lost user env")
						}
						return Result{Stdout: []byte(`[{"Name":"default","Endpoints":{"docker":{"Host":"unix:///changed"}}}]`)}, nil, true
					}
					return Result{}, nil, false
				}
			case "profile":
				writeFixture(t, profile, "memory: 16", 0600)
			case "private-home":
				writeFixture(t, private, "memory: 16", 0600)
			}
			after, err := s.snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			diff := snapshotDiff(before, after)
			if (diff != "") != (mode != "private-home") {
				t.Fatalf("snapshot drift missing or private home leaked: %s", diff)
			}
		})
	}
}

// F11: a missing XML type cannot be filled from an assertion message that merely names a network exception.
func TestJUnitMessageCannotSupplyExceptionIdentity(t *testing.T) {
	for _, text := range []string{"java.lang.AssertionError: assertion failed", "no exception class"} {
		root := t.TempDir()
		xml := strings.Replace(validJUnit, `type="java.net.UnknownHostException">repo.maven.apache.org`, `message="expected java.net.UnknownHostException">`+text, 1)
		writeFixture(t, filepath.Join(root, "build/test-results/test/TEST.xml"), xml, 0600)
		off, net, detail := inspectJUnit(root)
		if !off || net {
			t.Fatalf("message supplied exception identity: %s", detail)
		}
	}
}

// F11: successful stop invocation alone cannot qualify; a subsequent private list must freshly report stopped.
func TestSelftestStoppedVerification(t *testing.T) {
	for _, mode := range []string{"stopped", "running", "list-error"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h.f.fixtureMode = "qualified"
			stopSeen, verified := false, false
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if c.Name == "colima" && c.Args[0] == "stop" {
					stopSeen = true
				}
				if c.Name == "colima" && c.Args[0] == "list" && stopSeen && !reflect.DeepEqual(c.Env, h.e.UserEnv) {
					verified = true
					if mode == "list-error" {
						return Result{ExitCode: 1, Stderr: []byte("list failed")}, nil, true
					}
					state := "Stopped"
					if mode == "running" {
						state = "Running"
					}
					return Result{Stdout: []byte(fmt.Sprintf(`{"name":"netnone","status":%q}`, state))}, nil, true
				}
				return Result{}, nil, false
			}
			want := 1
			if mode == "stopped" {
				want = 0
			}
			h.exec(t, "selftest", want)
			if !stopSeen || !verified {
				t.Fatal("no fresh private-profile verification after stop")
			}
			if !strings.Contains(h.out.String(), "| lifecycle | completed and stopped |") {
				t.Fatal("stopped-state verdict missing")
			}
		})
	}
}

// F10: a failed task still closes public write permissions on its collected files/directories and skips artifact symlinks.
func TestOutputPermissionsAfterFailure(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "prep", 0)
	target := filepath.Join(h.root, "private-target")
	writeFixture(t, target, "private", 0600)
	var dest string
	h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
		if has(c.Args, "netnone-run") {
			for _, a := range c.Args {
				if strings.HasSuffix(a, ":/out") {
					dest = strings.TrimSuffix(a, ":/out")
				}
			}
			writeFixture(t, filepath.Join(dest, "result.xml"), "failure result", 0666)
			if err := os.Symlink(target, filepath.Join(dest, "linked-result")); err != nil {
				t.Fatal(err)
			}
			return Result{ExitCode: 7}, nil, true
		}
		return Result{}, nil, false
	}
	h.exec(t, "run", 1)
	for _, row := range []struct {
		path string
		mode os.FileMode
	}{{dest, 0755}, {filepath.Join(dest, "result.xml"), 0644}, {target, 0600}} {
		st, err := os.Stat(row.path)
		if err != nil || st.Mode().Perm() != row.mode {
			t.Fatalf("permissions after failure %s: %v %v", row.path, st, err)
		}
	}
}

// F12: inspection is required for every listed context, using user env; failed/malformed inspection cannot become equal snapshots.
func TestSnapshotInspectEveryContext(t *testing.T) {
	for _, mode := range []string{"valid", "error", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			inspected := map[string]bool{}
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if has(c.Args, "context", "ls") {
					return Result{Stdout: []byte(`[{"Name":"default","Current":true},{"Name":"remote","Current":false}]`)}, nil, true
				}
				if has(c.Args, "context", "inspect") {
					if !reflect.DeepEqual(c.Env, h.e.UserEnv) {
						t.Fatal("inspect lost user env")
					}
					name := c.Args[len(c.Args)-1]
					inspected[name] = true
					if name == "remote" && mode == "error" {
						return Result{ExitCode: 1}, nil, true
					}
					if name == "remote" && mode == "malformed" {
						return Result{Stdout: []byte("broken")}, nil, true
					}
					return Result{Stdout: []byte(fmt.Sprintf(`[{"Name":%q,"Endpoints":{}}]`, name))}, nil, true
				}
				return Result{}, nil, false
			}
			s := session{e: h.e, home: h.home}
			snap, err := s.snapshot(context.Background())
			if len(inspected) != 2 {
				t.Fatalf("some contexts uninspected: %v", inspected)
			}
			if mode == "valid" {
				if err != nil || snap["context:default"] == snap["context:remote"] {
					t.Fatalf("context hashes missing: %v %v", snap, err)
				}
			} else if err == nil {
				t.Fatal("unknown inspect evidence accepted")
			}
		})
	}
}

// F1 (round 2): a heredoc opener split by a line continuation is joined
// before the check, as Docker joins it, so it cannot forge a pinned stage.
// A continued instruction without a heredoc stays accepted (positive control).
func TestToolchainContinuedHeredocStageForgery(t *testing.T) {
	witness := "FROM " + BaseImage + "\nCOPY <\\\n<EOF /fake\nFROM " + BaseImage + " AS ubuntu\nEOF\nFROM ubuntu\n"
	if validToolchain([]byte(witness)) {
		t.Fatal("continued heredoc opener accepted")
	}
	control := "FROM " + BaseImage + "\nRUN echo a \\\n  && echo b\n"
	if !validToolchain([]byte(control)) {
		t.Fatal("continued instruction without heredoc rejected")
	}
}

// F13: output cleanup never follows a symlink. Links to a host file or a host
// directory are skipped, so their targets keep their modes, while real
// entries are restricted. A name swapped for a symlink after listing is the
// same case at open time: O_NOFOLLOW fails with ELOOP and the entry is skipped.
// Limit: the concurrent swap itself is not raced here.
func TestRestrictOutputNeverFollowsSymlinks(t *testing.T) {
	outside := t.TempDir()
	hostFile := filepath.Join(outside, "host-file")
	writeFixture(t, hostFile, "host", 0600)
	hostDir := filepath.Join(outside, "host-dir")
	if err := os.Mkdir(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, filepath.Join(hostDir, "inner"), "inner", 0600)
	root := filepath.Join(t.TempDir(), "stamp")
	writeFixture(t, filepath.Join(root, "build/test-results/TEST.xml"), "result", 0666)
	if err := os.Chmod(filepath.Join(root, "build"), 0777); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"file-link": hostFile, "build/dir-link": hostDir} {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	var errOut bytes.Buffer
	restrictOutput(root, &errOut)
	for path, want := range map[string]os.FileMode{hostFile: 0600, hostDir: 0700, filepath.Join(hostDir, "inner"): 0600, root: 0755, filepath.Join(root, "build"): 0755, filepath.Join(root, "build/test-results/TEST.xml"): 0644} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: mode %v want %v (%v)", path, st.Mode().Perm(), want, err)
		}
	}
	if errOut.Len() != 0 {
		t.Fatalf("symlinks reported as errors: %s", &errOut)
	}
	// A root that is itself a symlink is refused, not followed.
	link := filepath.Join(t.TempDir(), "stamp-link")
	if err := os.Symlink(hostDir, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(hostDir, 0700); err != nil {
		t.Fatal(err)
	}
	restrictOutput(link, &errOut)
	if st, _ := os.Stat(hostDir); st.Mode().Perm() != 0700 || errOut.Len() == 0 {
		t.Fatalf("symlinked root followed: %v %q", st.Mode().Perm(), &errOut)
	}
}

// F11 (round 2): a type-less failure qualifies only through its leading
// exception header; prose that names a network exception later does not.
func TestJUnitExceptionHeaderOnly(t *testing.T) {
	for text, want := range map[string]bool{
		"AssertionError: expected java.net.UnknownHostException":                   false,
		"java.lang.AssertionError: expected java.net.UnknownHostException":         false,
		"expected java.net.UnknownHostException\njava.net.UnknownHostException: x": false,
		"java.net.UnknownHostException: repo.maven.apache.org\n\tat NetworkTest":   true,
		"\njava.net.SocketException: Network is unreachable":                       true,
		"java.net.ConnectException: Connection refused":                            false,
	} {
		if got := networkFailure("", "", text); got != want {
			t.Errorf("%q: got %t want %t", text, got, want)
		}
	}
}

// F14: the output cleanup walk is bounded. A tree deeper than
// outputDepthLimit, written by the test container, completes cleanup:
// shallow entries are restricted, the subtree past the limit is left
// unchanged and reported, and the VM is still stopped after the run.
func TestRestrictOutputDepthBound(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "prep", 0)
	var bind string
	h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
		if has(c.Args, "netnone-run") {
			for _, a := range c.Args {
				if strings.HasSuffix(a, ":/out") {
					bind = strings.TrimSuffix(a, ":/out")
				}
			}
			writeFixture(t, filepath.Join(bind, "shallow.xml"), "shallow", 0666)
			deep := bind
			for i := 0; i < outputDepthLimit+6; i++ {
				deep = filepath.Join(deep, "d")
			}
			writeFixture(t, filepath.Join(deep, "deep.xml"), "deep", 0666)
		}
		return Result{}, nil, false
	}
	h.exec(t, "run", 0)
	if st, err := os.Stat(filepath.Join(bind, "shallow.xml")); err != nil || st.Mode().Perm() != 0644 {
		t.Fatalf("shallow result not restricted: %v %v", st, err)
	}
	deep := bind
	for i := 0; i < outputDepthLimit+6; i++ {
		deep = filepath.Join(deep, "d")
	}
	if st, err := os.Stat(filepath.Join(deep, "deep.xml")); err != nil || st.Mode().Perm() != 0666 {
		t.Fatalf("cleanup went past the depth limit: %v %v", st, err)
	}
	if !strings.Contains(h.err.String(), fmt.Sprintf("deeper than %d levels", outputDepthLimit)) {
		t.Fatalf("skipped subtree not reported: %s", &h.err)
	}
	runAt, stopAt := -1, -1
	for i, c := range h.f.calls {
		if has(c.Args, "netnone-run") {
			runAt = i
		}
		if c.Name == "colima" && has(c.Args, "stop") {
			stopAt = i
		}
	}
	if runAt < 0 || stopAt < runAt {
		t.Fatalf("VM not stopped after the run: run=%d stop=%d", runAt, stopAt)
	}
}
