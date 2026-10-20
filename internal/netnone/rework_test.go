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
	emitted, _ := normalizeToolchain([]byte(original), "arm64")
	for i, want := range []string{strings.Replace(string(base), BaseImage, BaseImageARM64, 1), string(emitted)} {
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
	if _, ok := records[recordKey(h.o.Repo, hex.EncodeToString(sum[:]), h.o.Arch)]; !ok {
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
func shellFixture(t *testing.T, script, mode string, dirs ...string) (string, error) {
	t.Helper()
	_, out, err := shellFixtureRoot(t, script, mode, dirs...)
	return out, err
}

// Copy/removal fakes delegate to host tools except for the requested failure;
// a fake find can supply malformed exclusion entries without altering the loop.
func shellFixtureRoot(t *testing.T, script, mode string, dirs ...string) (string, string, error) {
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
	for path, contents := range map[string]string{
		"omitted.txt":                       "source skipped by failing cp",
		"mod/build.gradle":                  "// Gradle module",
		"mod/build/stale.txt":               "stale build output",
		".gradle/cache.txt":                 "stale local cache",
		"dir with spaces/.gradle/cache.txt": "nested stale local cache",
		"dir with spaces/kept.txt":          "source with spaces",
		"src/test/java/build/Marker.java":   "class Marker {}",
	} {
		writeFixture(t, filepath.Join(root, "src", path), contents, 0600)
	}
	if mode == "nested-readonly" {
		// An excluded build tree that itself contains an excluded .gradle tree,
		// both populated and read-only: removing the outer one takes the inner.
		writeFixture(t, filepath.Join(root, "src", "mod", "build", "generated", ".gradle", "cache.txt"), "nested cache", 0600)
		inner := filepath.Join(root, "src", "mod", "build", "generated", ".gradle")
		outer := filepath.Join(root, "src", "mod", "build")
		for _, dir := range []string{inner, outer} {
			if err := os.Chmod(dir, 0555); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(func() {
			for _, dir := range []string{outer, inner, filepath.Join(root, "work", "mod", "build"), filepath.Join(root, "work", "mod", "build", "generated", ".gradle")} {
				os.Chmod(dir, 0755)
			}
		})
	}
	if mode == "readonly-build" {
		// A populated read-only excluded tree, as a toolchain may leave behind.
		readonly := filepath.Join(root, "src", "mod", "build")
		if err := os.Chmod(readonly, 0555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			for _, dir := range []string{readonly, filepath.Join(root, "work", "mod", "build")} {
				os.Chmod(dir, 0755)
			}
		})
	}
	writeFixture(t, filepath.Join(root, "src", "gradlew"), `#!/bin/sh
case " $* " in *" --dry-run "*) echo dry-run-ok; exit 0;; esac
if [ "$FAKE_MODE" = dependency ]; then echo 'Could not resolve dependency' >&2; exit 7; fi
if [ "$FAKE_MODE" = test-failed ]; then mkdir -p module/build/test-results/test; echo '<testsuite/>' > module/build/test-results/test/TEST.xml; exit 1; fi
exit 0
`, 0700)
	writeFixture(t, filepath.Join(root, "bin", "java"), "#!/bin/sh\nexit 0\n", 0700)
	writeFixture(t, filepath.Join(root, "bin", "cp"), `#!/bin/sh
if [ "$FAKE_MODE" = cp-failure ]; then
 /bin/cp -R -P -p "$FAKE_SRC/gradlew" "$FAKE_WORK/gradlew" || exit 99
 exit 7
fi
exec /bin/cp "$@"
`, 0700)
	writeFixture(t, filepath.Join(root, "bin", "rm"), `#!/bin/sh
if [ "$1" = -rf ]; then
 echo exclusion-removal
 if [ "$FAKE_MODE" = rm-failure ]; then exit 8; fi
fi
exec /bin/rm "$@"
`, 0700)
	writeFixture(t, filepath.Join(root, "bin", "chmod"), `#!/bin/sh
if [ "$FAKE_MODE" = chmod-failure ]; then echo chmod-attempted; exit 9; fi
exec /bin/chmod "$@"
`, 0700)
	writeFixture(t, filepath.Join(root, "bin", "find"), `#!/bin/sh
case "$FAKE_MODE" in
 exclude-dot) printf '.\n'; exit 0;;
 exclude-root) printf './\n'; exit 0;;
 exclude-no-prefix) printf 'mod/build\n'; exit 0;;
esac
exec /usr/bin/find "$@"
`, 0700)
	// Substitute only fixed absolute guest paths, never interpolate fixture input into shell code.
	script = strings.NewReplacer("/src", filepath.Join(root, "src"), "/work", filepath.Join(root, "work"), "/tmp", filepath.Join(root, "tmp"), "/out", filepath.Join(root, "out")).Replace(script)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", script, "fixture", "test")
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(root, "bin")+":/usr/bin:/bin", "FAKE_MODE="+mode,
		"FAKE_SRC="+filepath.Join(root, "src"), "FAKE_WORK="+filepath.Join(root, "work"))
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("guest fixture timed out: %s", out)
	}
	return root, string(out), err
}

// F8: partial cp failure exits 1 with its diagnostic before exclusions or later commands run.
func TestCopySourceCopyFailure(t *testing.T) {
	root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", "cp-failure")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(out, "source copy failed") ||
		strings.Contains(out, "copy-completed") || strings.Contains(out, "exclusion-removal") {
		t.Fatalf("cp failure masked or later command ran: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "work", "gradlew")); err != nil {
		t.Fatal("cp failure control did not copy a partial source", err)
	}
	if _, err := os.Stat(filepath.Join(root, "work", "omitted.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("cp failure control did not omit a source file")
	}
}

// F8: failed exclusion removal exits 1, preserves the rejected tree and stops later commands.
func TestCopySourceRemovalFailure(t *testing.T) {
	root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", "rm-failure")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(out, "source exclusion removal failed") ||
		!strings.Contains(out, "exclusion-removal") || strings.Contains(out, "copy-completed") {
		t.Fatalf("rm failure masked or later command ran: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "work", "mod", "build", "stale.txt")); err != nil {
		t.Fatal("failed removal must leave copied build output", err)
	}
}

// F8: host cp/rm remove Gradle outputs/caches, including paths with spaces,
// while preserving source build packages, spaced filenames and the original repo.
func TestCopySourceExclusionCorrectness(t *testing.T) {
	root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", "")
	if err != nil || !strings.Contains(out, "copy-completed") {
		t.Fatalf("copy rejected: %v %s", err, out)
	}
	for _, path := range []string{"mod/build", ".gradle", "dir with spaces/.gradle"} {
		if _, err := os.Stat(filepath.Join(root, "work", path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("excluded path remains: %s: %v", path, err)
		}
		if _, err := os.Stat(filepath.Join(root, "src", path)); err != nil {
			t.Fatalf("original excluded path changed: %s: %v", path, err)
		}
	}
	for path, want := range map[string]string{
		"src/test/java/build/Marker.java": "class Marker {}",
		"dir with spaces/kept.txt":        "source with spaces",
		"mod/build.gradle":                "// Gradle module",
	} {
		data, err := os.ReadFile(filepath.Join(root, "work", path))
		if err != nil || string(data) != want {
			t.Fatalf("source not preserved: %s: %q %v", path, data, err)
		}
	}
}

// F8: malformed find entries are refused before any removal or later command;
// the valid discovered-entry control is exercised by TestCopySourceExclusionCorrectness.
func TestCopySourceInvalidExcludedPath(t *testing.T) {
	for _, mode := range []string{"exclude-dot", "exclude-root", "exclude-no-prefix"} {
		t.Run(mode, func(t *testing.T) {
			root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", mode)
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(out, "source copy refused: invalid excluded path") ||
				strings.Contains(out, "exclusion-removal") || strings.Contains(out, "copy-completed") {
				t.Fatalf("invalid exclusion admitted: err=%v out=%s", err, out)
			}
			if _, err := os.Stat(filepath.Join(root, "work", "mod", "build", "stale.txt")); err != nil {
				t.Fatal("invalid exclusion changed the copied build tree", err)
			}
		})
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
	if validToolchain([]byte(witness), "arm64") {
		t.Fatal("continued heredoc opener accepted")
	}
	control := "FROM " + BaseImage + "\nRUN echo a \\\n  && echo b\n"
	if !validToolchain([]byte(control), "arm64") {
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

// Review F1 (PR #25): cp -p keeps a populated 0555 excluded build tree
// read-only; the copy makes it owner-writable before removal, so it is
// removed and the copy completes. The source tree keeps its 0555 mode.
func TestCopySourceReadOnlyExcludedTree(t *testing.T) {
	root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", "readonly-build")
	if err != nil || !strings.Contains(out, "copy-completed") {
		t.Fatalf("read-only excluded tree blocked the copy: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "work", "mod", "build")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only excluded tree remains: %v", err)
	}
	if st, err := os.Stat(filepath.Join(root, "src", "mod", "build")); err != nil || st.Mode().Perm() != 0555 {
		t.Fatalf("source tree mode changed: %v %v", st, err)
	}
}

// Review F2 (PR #25): an exclusion nested in an earlier, already removed
// exclusion is skipped rather than failing the copy; both read-only trees
// are gone from /work and the copy completes.
func TestCopySourceNestedExclusions(t *testing.T) {
	root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", "nested-readonly")
	if err != nil || !strings.Contains(out, "copy-completed") {
		t.Fatalf("nested exclusion blocked the copy: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "work", "mod", "build")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("outer excluded tree remains: %v", err)
	}
	excludes, _ := os.ReadFile(filepath.Join(root, "tmp", "netnone-excludes"))
	if !strings.Contains(string(excludes), "./mod/build\n") || !strings.Contains(string(excludes), "./mod/build/generated/.gradle\n") {
		t.Fatalf("fixture did not produce nested exclusions: %q", excludes)
	}
}

// Review F2 (PR #25): skipping vanished exclusions does not hide a genuine
// chmod failure on an existing excluded path; the copy stops before removal.
func TestCopySourceChmodFailure(t *testing.T) {
	root, out, err := shellFixtureRoot(t, copySource+"echo copy-completed\n", "chmod-failure")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(out, "chmod-attempted") ||
		!strings.Contains(out, "source exclusion removal failed") || strings.Contains(out, "copy-completed") {
		t.Fatalf("chmod failure masked: err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(root, "work", "mod", "build", "stale.txt")); err != nil {
		t.Fatal("excluded tree removed despite chmod failure", err)
	}
}

// Consumer bug (2026-10-21): the builder receives a Dockerfile emitted from
// the validated parse, one line per instruction, comments dropped, and the
// pinned index in FROM replaced by the manifest for the arch. Continuations
// join the way Docker joins them, so the next line's leading whitespace is
// kept; nothing the builder sees can be split or hidden.
func TestNormalizeToolchainEmission(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		in := "# leading comment\r\nARG X=1\nFROM " + BaseImage + " AS base\nUSER root\n" +
			"RUN echo foo\\\n  bar \\ \t\n\n# inside\n\u00a0\n  baz\n" +
			"COPY --from=base /etc/os-release /x\nFROM base\n"
		want := "ARG X=1\nFROM " + baseImage(arch) + " AS base\nUSER root\n" +
			"RUN echo foo  bar   baz\nCOPY --from=base /etc/os-release /x\nFROM base\n"
		got, ok := normalizeToolchain([]byte(in), arch)
		if !ok || string(got) != want {
			t.Fatalf("%s: emitted %q, want %q (ok=%t)", arch, got, want, ok)
		}
		if strings.Contains(string(got), BaseImage) || strings.Contains(string(got), "\\\n") {
			t.Fatalf("%s: emitted index or continuation", arch)
		}
	}
}

// Review rounds 1-4 (PR #27): every FROM the builder receives is the
// validated, arch-pinned one. A FROM of the index split in any Docker-joined
// way (plain, indented, space/tab after the backslash, blank, comment or
// Unicode-whitespace continuation lines) is accepted and emitted pinned on one
// line. Images in other instructions (COPY --from, RUN --mount from=) are the
// caller's to pin and pass through unchanged. Limit: Docker's own parse of the
// emitted file is not executed here; the real selftest covers the build.
func TestToolchainSplitIndexReference(t *testing.T) {
	head, tail := "eclipse-temurin:17-jdk@", strings.TrimPrefix(BaseImage, "eclipse-temurin:17-jdk@")
	for _, arch := range []string{"amd64", "arm64"} {
		for name, content := range map[string]string{
			"split-from":         "FROM " + head + "\\\n" + tail + "\nUSER root\n",
			"split-from-ws":      "FROM " + head + "\\ \t\n" + tail + "\nUSER root\n",
			"split-from-blank":   "FROM " + head + "\\\n\n" + tail + "\nUSER root\n",
			"split-from-nbsp":    "FROM " + head + "\\\n\u00a0\n" + tail + "\nUSER root\n",
			"split-from-comment": "FROM " + head + "\\\n# " + BaseImage + "\n" + tail + "\nUSER root\n",
			"copy-from-image":    "FROM " + BaseImage + "\nCOPY --from=" + BaseImageAMD64 + " /etc/os-release /x\n",
			"one-line":           "FROM " + BaseImage + "\nUSER root\nCOPY input.txt /tmp/input/\n",
		} {
			h := archHarness(t, arch)
			h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
			writeFixture(t, h.o.Toolchain, content, 0600)
			h.exec(t, "prep", 0)
			builds := callsNamed(h.f.calls, "docker", "build")
			data, _ := io.ReadAll(builds[len(builds)-1].Stdin)
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(strings.ToUpper(line), "FROM ") && line != "FROM "+baseImage(arch) {
					t.Fatalf("%s/%s: builder FROM %q is not the %s pin", arch, name, line, arch)
				}
			}
			if strings.Contains(string(data), "\\\n") {
				t.Fatalf("%s/%s: builder received a continuation: %q", arch, name, data)
			}
		}
	}
}

// Review round 4 (PR #27): only ASCII space and tab may follow a continuation
// backslash, as in Docker. A backslash followed by NBSP, VT, FF or EM SPACE
// does not continue the line, so the next instruction stays separate (the
// marker RUN is not swallowed); space and tab are the continuation controls.
func TestContinuationTrailingWhitespace(t *testing.T) {
	for name, ws := range map[string]string{"nbsp": "\u00a0", "vt": "\v", "ff": "\f", "em-space": "\u2003"} {
		in := "FROM " + BaseImage + "\nRUN printf '%s' foo\\" + ws + "\nRUN touch /marker\n"
		out, ok := normalizeToolchain([]byte(in), "amd64")
		if !ok || !strings.Contains(string(out), "\nRUN touch /marker\n") || strings.Count(string(out), "RUN ") != 2 {
			t.Fatalf("%s: instruction boundary lost: %q (ok=%t)", name, out, ok)
		}
	}
	for name, ws := range map[string]string{"space": " ", "tab": "\t"} {
		in := "FROM " + BaseImage + "\nRUN printf '%s' foo \\" + ws + "\n  bar\n"
		out, ok := normalizeToolchain([]byte(in), "amd64")
		if !ok || !strings.Contains(string(out), "RUN printf '%s' foo   bar\n") {
			t.Fatalf("%s: continuation not joined: %q (ok=%t)", name, out, ok)
		}
	}
}

// Review round 5 (PR #27): a CR outside a CRLF pair is refused before any
// runner call on both arches, because Docker strips every trailing CR and
// could then see a continuation that hides a stage declaration (the witnesses
// below would turn FROM alpine into an external image). Plain CRLF files stay
// accepted and keep their boundaries.
func TestToolchainStrayCarriageReturn(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		for name, row := range map[string]struct {
			content string
			refused bool
		}{
			"cr-cr-lf":    {"FROM " + BaseImage + "\nRUN true \\\r\r\nFROM " + BaseImage + " AS alpine\nFROM alpine\n", true},
			"cr-space-lf": {"FROM " + BaseImage + "\nRUN true \\\r \nFROM " + BaseImage + " AS alpine\nFROM alpine\n", true},
			"bare-cr":     {"FROM " + BaseImage + "\rRUN true\n", true},
			"crlf":        {"FROM " + BaseImage + " AS a\r\nRUN true \\\r\n  && echo ok\r\nFROM a\r\n", false},
		} {
			h := archHarness(t, arch)
			h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
			writeFixture(t, h.o.Toolchain, row.content, 0600)
			want := 0
			if row.refused {
				want = 2
			}
			h.exec(t, "prep", want)
			if row.refused && len(h.f.calls) != 0 {
				t.Fatalf("%s/%s: refused file reached the runner", arch, name)
			}
		}
		out, ok := normalizeToolchain([]byte("FROM "+BaseImage+" AS a\r\nRUN true \\\r\n  && echo ok\r\nFROM a\r\n"), arch)
		if !ok || string(out) != "FROM "+baseImage(arch)+" AS a\nRUN true   && echo ok\nFROM a\n" {
			t.Fatalf("%s: CRLF emission %q (ok=%t)", arch, out, ok)
		}
	}
}
