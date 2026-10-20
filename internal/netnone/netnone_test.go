package netnone

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testImage = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const warmOutput = "dns=ok\ntcp=ok\nnetnone-prep-test-exit=0\n"
const deniedOutput = "dns=fail:java.net.UnknownHostException\ntcp=fail:java.net.SocketException:Network is unreachable\n"

type fakeRunner struct {
	calls           []Command
	hook            func(context.Context, Command) (Result, error, bool)
	test            *testing.T
	fixtureMode     string
	probeOutput     string
	contextReads    int
	changedSnapshot bool
}

func has(args []string, want ...string) bool {
	for i := 0; i+len(want) <= len(args); i++ {
		if reflect.DeepEqual(args[i:i+len(want)], want) {
			return true
		}
	}
	return false
}
func (f *fakeRunner) Run(ctx context.Context, c Command) (Result, error) {
	// Capture stdin now, so later assertions do not depend on its consumption.
	if c.Stdin != nil {
		data, err := io.ReadAll(c.Stdin)
		if err != nil {
			f.test.Fatal(err)
		}
		c.Stdin = strings.NewReader(string(data))
	}
	f.calls = append(f.calls, c)
	if f.hook != nil {
		if r, e, handled := f.hook(ctx, c); handled {
			return r, e
		}
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	if c.Name == "colima" {
		switch c.Args[0] {
		case "status":
			return Result{Stdout: []byte(`{"status":"Stopped"}`)}, nil
		case "start", "stop":
			return Result{}, nil
		case "list":
			return Result{Stdout: []byte(`[{"name":"default","status":"Running"},{"name":"netnone","status":"Stopped"}]`)}, nil
		}
	}
	if c.Name == "docker" {
		switch c.Args[0] {
		case "context":
			f.contextReads++
			name := "default"
			if f.changedSnapshot && f.contextReads > 1 {
				name = "changed"
			}
			return Result{Stdout: []byte(fmt.Sprintf(`{"Name":%q,"Current":true}`, name))}, nil
		case "build":
			return Result{Stdout: []byte(testImage + "\n")}, nil
		case "volume", "image":
			return Result{}, nil
		case "run":
			if has(c.Args, "java", "/src/Probe.java") {
				output := f.probeOutput
				if output == "" {
					output = deniedOutput
				}
				return Result{Stdout: []byte(output)}, nil
			}
			if has(c.Args, "sh", "-c", prepScript) || strings.Contains(strings.Join(c.Args, " "), "netnone-prep-test-exit") {
				return Result{Stdout: []byte(warmOutput)}, nil
			}
			if has(c.Args, "sh", "-c", runScript) {
				// Simulate only the copied artifact, never execute the guest script.
				if f.fixtureMode != "" {
					dest := ""
					for _, a := range c.Args {
						if strings.HasSuffix(a, ":/out") {
							dest = strings.TrimSuffix(a, ":/out")
						}
					}
					dest = filepath.Join(dest, c.Args[len(c.Args)-1], "build/test-results/test")
					if err := os.MkdirAll(dest, 0700); err != nil {
						f.test.Fatal(err)
					}
					offline, network := "", `<failure type="java.net.UnknownHostException">repo.maven.apache.org</failure>`
					switch f.fixtureMode {
					case "both-pass":
						network = ""
					case "both-fail":
						offline = `<failure type="java.lang.AssertionError"/>`
					case "dependency":
						network = `<failure type="java.net.UnknownHostException">Could not resolve dependencies</failure>`
					}
					xml := `<testsuite><testcase classname="OfflineTest" name="arithmetic">` + offline + `</testcase><testcase classname="NetworkTest" name="repositoryReachable">` + network + `</testcase></testsuite>`
					if err := os.WriteFile(filepath.Join(dest, "TEST-fixture.xml"), []byte(xml), 0600); err != nil {
						f.test.Fatal(err)
					}
					code := 1
					if f.fixtureMode == "both-pass" {
						code = 0
					}
					return Result{ExitCode: code}, nil
				}
				return Result{}, nil
			}
		}
	}
	f.test.Fatalf("unexpected command: %+v", c)
	return Result{}, errors.New("unexpected command")
}

type harness struct {
	e                 *Engine
	f                 *fakeRunner
	o                 Options
	root, state, home string
	out, err          bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{root: root, state: filepath.Join(root, "state"), home: filepath.Join(root, "home")}
	h.f = &fakeRunner{test: t}
	h.e = New(h.f, &h.out, &h.err)
	h.e.Home = func() (string, error) { return h.home, nil }
	h.e.StateDir = func(string) string { return h.state }
	h.e.Load = func(context.Context) ([3]float64, error) { return [3]float64{1, 2, 3}, nil }
	h.e.CPUCount = func() int { return 4 }
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	h.e.Now = func() time.Time { now = now.Add(time.Second); return now }
	h.e.UserEnv = []string{"PATH=/fake", "HOME=" + h.home, "DOCKER_HOST=old", "DOCKER_CONFIG=old", "DOCKER_CONTEXT=old", "DOCKER_TLS_VERIFY=1", "COLIMA_PROFILE=default"}
	h.o = DefaultOptions()
	h.o.Repo = filepath.Join(root, "repo")
	h.o.Out = filepath.Join(root, "out")
	h.o.Task = "test"
	for _, p := range []string{h.o.Repo, h.o.Out, h.home} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return h
}
func (h *harness) exec(t *testing.T, action string, want int) {
	t.Helper()
	got := h.e.Execute(context.Background(), action, h.o)
	if got != want {
		t.Fatalf("%s exit %d want %d; stdout=%s stderr=%s", action, got, want, &h.out, &h.err)
	}
}
func callsNamed(calls []Command, name, verb string) []Command {
	var found []Command
	for _, c := range calls {
		if c.Name == name && len(c.Args) > 0 && c.Args[0] == verb {
			found = append(found, c)
		}
	}
	return found
}
func assertPrivate(t *testing.T, h *harness) {
	t.Helper()
	for _, c := range h.f.calls {
		if c.Name != "docker" && c.Name != "colima" {
			continue
		}
		if has(c.Args, "context", "ls") || has(c.Args, "list", "--json") {
			if !reflect.DeepEqual(c.Env, h.e.UserEnv) {
				t.Fatalf("snapshot must use user env: %v", c.Env)
			}
			continue
		}
		if !has(c.Env, "DOCKER_CONFIG="+filepath.Join(h.state, "docker-config")) || !has(c.Env, "DOCKER_HOST=unix://"+filepath.Join(h.home, ".colima/netnone/docker.sock")) {
			t.Fatalf("private Docker env absent: %s %v %v", c.Name, c.Args, c.Env)
		}
		for _, v := range c.Env {
			if strings.HasPrefix(v, "DOCKER_CONTEXT=") || strings.HasPrefix(v, "DOCKER_TLS_VERIFY=") || v == "COLIMA_PROFILE=default" {
				t.Fatalf("unsafe inherited env %s", v)
			}
		}
		for _, verb := range []string{"use", "create", "rm"} {
			if has(c.Args, "context", verb) {
				t.Fatalf("context mutation: %v", c.Args)
			}
		}
	}
}

// Prep followed by run uses exact non-root argv, UID-owned HOME tmpfs and /gradle cache mounts, without a chown helper; private env and immutable image are preserved.
func TestPrepThenRun(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "prep", 0)
	h.exec(t, "run", 0)
	starts := callsNamed(h.f.calls, "colima", "start")
	stops := callsNamed(h.f.calls, "colima", "stop")
	if len(starts) != 2 || len(stops) != 2 {
		t.Fatalf("start/stop counts %d/%d", len(starts), len(stops))
	}
	for i, c := range starts {
		out := h.o.Out
		if i == 0 {
			out = strings.TrimSuffix(c.Args[14], ":w")
			if !strings.HasPrefix(out, h.state+"/prep-") {
				t.Fatalf("prep scratch %s", out)
			}
		}
		want := []string{"start", "--profile", "netnone", "--activate=false", "--ssh-config=false", "--template=false", "--port-forwarder", "none", "--mount-inotify=false", "--mount-type", "virtiofs", "--mount", h.o.Repo, "--mount", out + ":w", "--vm-type", "vz", "--runtime", "docker", "--cpus", "4", "--memory", "8", "--disk", "40"}
		if !reflect.DeepEqual(c.Args, want) {
			t.Fatalf("start argv\ngot %q\nwant %q", c.Args, want)
		}
	}
	for _, c := range stops {
		if !reflect.DeepEqual(c.Args, []string{"stop", "--profile", "netnone"}) {
			t.Fatalf("stop: %v", c.Args)
		}
	}
	builds := callsNamed(h.f.calls, "docker", "build")
	if len(builds) != 1 {
		t.Fatalf("builds %d", len(builds))
	}
	b := builds[0].Args
	dir := b[len(b)-1]
	if !reflect.DeepEqual(b, []string{"build", "--quiet", "-t", "netnone-base:local", "-f", filepath.Join(dir, "Dockerfile"), dir}) {
		t.Fatalf("build %q", b)
	}
	var warm, run *Command
	for i := range h.f.calls {
		c := &h.f.calls[i]
		if has(c.Args, "netnone-prep") {
			warm = c
		}
		if has(c.Args, "netnone-run") {
			run = c
		}
	}
	if warm == nil || run == nil {
		t.Fatal("missing warm/test container")
	}
	wantWarm := []string{"run", "--rm", "-i", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--tmpfs", "/home/netnone:rw,size=64m,uid=10001,gid=10001,mode=0700", "-v", "netnone-gradle-home:/gradle", "-v", "netnone-work:/work", "-v", h.o.Repo + ":/src:ro", "-e", "GRADLE_USER_HOME=/gradle", "-w", "/work", testImage, "sh", "-c", prepScript, "netnone-prep", "test"}
	if !reflect.DeepEqual(warm.Args, wantWarm) {
		t.Fatalf("warm argv %q", warm.Args)
	}
	wantRun := []string{"run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "10001:10001", "--read-only", "--tmpfs", "/tmp:rw,exec,size=2g", "--tmpfs", "/home/netnone:rw,size=64m,uid=10001,gid=10001,mode=0700", "-v", "netnone-gradle-home:/gradle", "-v", "netnone-work:/work", "-v", h.o.Repo + ":/src:ro", "-v", h.o.Out + ":/out", "-e", "GRADLE_USER_HOME=/gradle", "-w", "/work", testImage, "sh", "-c", runScript, "netnone-run", "test", run.Args[len(run.Args)-1]}
	if !reflect.DeepEqual(run.Args, wantRun) {
		t.Fatalf("run argv\ngot %q\nwant %q", run.Args, wantRun)
	}
	containers := callsNamed(h.f.calls, "docker", "run")
	if len(containers) != 2 {
		t.Fatalf("want only prep and test containers, got %d", len(containers))
	}
	for _, c := range containers {
		if !has(c.Args, "--user", "10001:10001") || has(c.Args, "chown") || has(c.Args, "--cap-add") {
			t.Fatalf("runtime container must stay non-root without ownership helpers: %q", c.Args)
		}
	}
	for _, c := range h.f.calls {
		for _, a := range c.Args {
			if strings.Contains(a, "docker.sock") || a == "--privileged" || a == "--add-host" || a == "-p" {
				t.Fatalf("forbidden argument %s", a)
			}
		}
	}
	assertPrivate(t, h)
	st, err := os.Stat(h.state)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("state permissions %v %v", st, err)
	}
	records, err := os.ReadFile(filepath.Join(h.state, "prep-records.json"))
	if err != nil || !bytes.Contains(records, []byte(testImage)) {
		t.Fatalf("record %s %v", records, err)
	}
}

// Static contract: source copying excludes only directories, with build outputs
// conditional on Gradle files in their parent; tar matches literal anchored paths.
func TestSourceExcludesParentConditional(t *testing.T) {
	for _, want := range []string{
		`find . -type d \( -name .gradle -o -name build \) -exec sh -c '`,
		`if [ "${d##*/}" = .gradle ] ||`,
		`[ -f "$d/../build.gradle" ] || [ -f "$d/../build.gradle.kts" ] ||`,
		`[ -f "$d/../settings.gradle" ] || [ -f "$d/../settings.gradle.kts" ]; then`,
		`printf "%s\n" "$d"`,
		`> /tmp/netnone-excludes`,
		`tar --no-wildcards --anchored -X /tmp/netnone-excludes -cf - .`,
	} {
		if !strings.Contains(copySource, want) {
			t.Fatalf("parent-conditional copy contract missing %q", want)
		}
	}
	if strings.Contains(copySource, "--exclude=") || strings.Contains(copySource, "-prune") {
		t.Fatal("copy must not broadly exclude or prune source packages named build")
	}
}

// Static fixture contract: materialization includes the build package and a
// JUnit test whose compilation requires it. No JVM/Gradle execution is claimed.
func TestFixtureBuildPackage(t *testing.T) {
	h := newHarness(t)
	if err := materializeFixture(h.o.Repo); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{
		"src/test/java/build/Marker.java": "package build;\n\npublic final class Marker",
		"src/test/java/OfflineTest.java":  "@Test void buildPackageWasCopied() { assertEquals(42, build.Marker.value()); }",
		"build.gradle":                    "plugins { id 'java' }",
	} {
		data, err := os.ReadFile(filepath.Join(h.o.Repo, path))
		if err != nil || !strings.Contains(string(data), want) {
			t.Fatalf("fixture compile witness missing from %s: %v", path, err)
		}
	}
}

// A 5-minute load above the gate refuses before filesystem setup or any runner call; equality and CPU-count defaults are admitted.
func TestLoadGate(t *testing.T) {
	for _, row := range []struct {
		name      string
		load, max float64
		code      int
	}{{"over", 4.01, 4, 3}, {"boundary", 4, 4, 0}, {"default", 4, 0, 0}} {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			h.o.MaxLoad = row.max
			h.e.Load = func(context.Context) ([3]float64, error) { return [3]float64{7, row.load, 9}, nil }
			h.exec(t, "prep", row.code)
			if row.code == 3 {
				if len(h.f.calls) != 0 {
					t.Fatalf("load refusal ran %d commands", len(h.f.calls))
				}
				if _, err := os.Stat(h.state); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("state created before load gate")
				}
				if h.err.String() != "refused: host load 5m=4.01 above --max-load 4 (1m=7 15m=9)\n" {
					t.Fatal(h.err.String())
				}
			}
		})
	}
}

// A running pre-existing profile is never started or stopped by prep.
func TestAlreadyRunningRefusal(t *testing.T) {
	h := newHarness(t)
	h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
		if c.Name == "colima" && c.Args[0] == "status" {
			return Result{Stdout: []byte(`{"status":"Running"}`)}, nil, true
		}
		return Result{}, nil, false
	}
	h.exec(t, "prep", 3)
	if len(h.f.calls) != 1 || len(callsNamed(h.f.calls, "colima", "start")) != 0 || len(callsNamed(h.f.calls, "colima", "stop")) != 0 {
		t.Fatalf("refusal commands %+v", h.f.calls)
	}
	if !strings.Contains(h.err.String(), "not started by this invocation") {
		t.Fatal(h.err.String())
	}
}

// Docker failure, cancellation and invalid image errors all stop an owned VM using a fresh context; stop failures override success.
func TestDeferredStop(t *testing.T) {
	for _, mode := range []string{"docker-error", "cancel", "bad-image", "stop-error"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopFresh := false
			h.f.hook = func(ctx context.Context, c Command) (Result, error, bool) {
				if c.Name == "colima" && c.Args[0] == "stop" {
					stopFresh = ctx.Err() == nil
					if mode == "stop-error" {
						return Result{ExitCode: 7}, nil, true
					}
				}
				if c.Name == "docker" && c.Args[0] == "build" {
					switch mode {
					case "docker-error":
						return Result{}, errors.New("scripted build failure"), true
					case "cancel":
						cancel()
						return Result{}, ctx.Err(), true
					case "bad-image":
						return Result{Stdout: []byte("not-an-id")}, nil, true
					}
				}
				return Result{}, nil, false
			}
			if code := h.e.Execute(ctx, "prep", h.o); code != 1 {
				t.Fatalf("exit=%d stderr=%s", code, &h.err)
			}
			if len(callsNamed(h.f.calls, "colima", "stop")) != 1 || !stopFresh {
				t.Fatal("owned VM did not stop with fresh context")
			}
		})
	}
}

// A held real flock refuses without running a CLI; releasing it admits a normal invocation.
func TestLockHeld(t *testing.T) {
	h := newHarness(t)
	if err := os.MkdirAll(h.state, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireLock(h.state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	h.exec(t, "prep", 3)
	if len(h.f.calls) != 0 || !strings.Contains(h.err.String(), "another mac-netnone run holds the lock") {
		t.Fatalf("lock refusal %d %s", len(h.f.calls), &h.err)
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	h.exec(t, "prep", 0)
}

// Missing records and a changed Dockerfile hash refuse run before any Colima command; the newly prepped hash is a valid control.
func TestPrepRecordRequired(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "run", 3)
	if len(h.f.calls) != 0 {
		t.Fatal("missing record called runner")
	}
	file := filepath.Join(h.root, "Dockerfile")
	h.o.Toolchain = file
	if err := os.WriteFile(file, []byte("FROM "+BaseImage+"\nUSER netnone\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h.exec(t, "prep", 0)
	if err := os.WriteFile(file, []byte("FROM "+BaseImage+"\n# changed\nUSER netnone\n"), 0600); err != nil {
		t.Fatal(err)
	}
	h.f.calls = nil
	h.exec(t, "run", 3)
	if len(h.f.calls) != 0 {
		t.Fatal("mismatched hash called runner")
	}
	h.exec(t, "prep", 0)
	h.exec(t, "run", 0)
	builds := callsNamed(h.f.calls, "docker", "build")
	if len(builds) != 2 || !reflect.DeepEqual(builds[1].Args, []string{"build", "--quiet", "-f", file, filepath.Dir(file)}) {
		t.Fatalf("toolchain build argv %+v", builds)
	}
	assertPrivate(t, h)
}

// Dockerfile validation admits pinned bases and earlier pinned aliases, and rejects unpinned stages, parser directives and malformed continuations before any runner call.
func TestToolchainFROM(t *testing.T) {
	for _, row := range []struct {
		name, content string
		valid         bool
	}{
		{"pinned", "FROM " + BaseImage, true}, {"comments-args", "# ordinary comment\n\nARG X=17\n# comment\nFROM " + BaseImage + "\nUSER netnone", true},
		{"tag-only", "FROM eclipse-temurin:17-jdk", false}, {"digest", "FROM eclipse-temurin:17-jdk@sha256:" + strings.Repeat("0", 64), false},
		{"run-first", "RUN echo bad\nFROM " + BaseImage, false}, {"multi-stage", "FROM other AS builder\nFROM " + BaseImage, false},
		{"later-unpinned", "FROM " + BaseImage + "\nFROM ubuntu:latest", false},
		{"later-pinned", "FROM " + BaseImage + "\nRUN echo ok\nFROM " + BaseImage, true},
		{"escaped-backslash-before-unpinned", "FROM " + BaseImage + "\nRUN echo " + `\\` + "\nFROM ubuntu:latest", false},
		{"escaped-backslash-before-pinned", "FROM " + BaseImage + "\nRUN echo " + `\\` + "\nFROM " + BaseImage, true},
		{"syntax-directive", "# syntax=docker/dockerfile:1\nFROM " + BaseImage, false},
		{"check-directive", "  # ChEcK = skip=all\nFROM " + BaseImage, false},
		{"escape-directive", "#  EsCaPe = `\nFROM " + BaseImage, false},
		{"pinned-stage-reference", "FROM " + BaseImage + " AS a\nFROM a", true},
		{"unknown-stage-reference", "FROM " + BaseImage + " AS a\nFROM b", false},
		{"forward-stage-reference", "FROM a\nFROM " + BaseImage + " AS a", false},
		{"case-insensitive-stage", "from " + BaseImage + " as a\nFrOm A", true},
		{"reference-alias", "FROM " + BaseImage + " AS a\nFROM a AS b", false},
		{"numeric-stage", "FROM " + BaseImage + " AS a\nFROM 0", false},
		{"platform", "FROM --platform=linux/arm64 " + BaseImage, false},
		{"later-platform", "FROM " + BaseImage + "\nFROM --platform=linux/arm64 " + BaseImage, false},
		{"duplicate-alias", "FROM " + BaseImage + " AS a\nFROM " + BaseImage + " AS a", false},
		{"invalid-alias", "FROM " + BaseImage + " AS --bad", false},
		{"continued-from", "FROM \\\n  " + BaseImage, true},
		{"continued-stage", "FROM " + BaseImage + " \\\nAS a\nFROM \\\n a", true},
		{"continued-unpinned", "FROM " + BaseImage + "\nFROM \\\n ubuntu:latest", false},
		{"continued-unknown-stage", "FROM " + BaseImage + " AS a\nFROM \\\n b", false},
		{"continued-comments", "FROM \\\n# comment\n\n " + BaseImage, true},
		{"unterminated-continuation", "FROM " + BaseImage + " \\", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			h.o.Toolchain = filepath.Join(h.root, "Dockerfile")
			if err := os.WriteFile(h.o.Toolchain, []byte(row.content), 0600); err != nil {
				t.Fatal(err)
			}
			want := 2
			if row.valid {
				want = 0
			}
			h.exec(t, "prep", want)
			if !row.valid && len(h.f.calls) != 0 {
				t.Fatal("invalid FROM ran external command")
			}
		})
	}
	data, err := assets.ReadFile("assets/Dockerfile")
	if err != nil || !strings.HasPrefix(string(data), "FROM "+BaseImage+"\n") {
		t.Fatalf("embedded base is not pinned: %v", err)
	}
}

// Static image contract: empty volumes copy up UID/GID 10001 from both mountpoints,
// created as root before returning to netnone. This does not execute Docker copy-up.
func TestEmbeddedVolumeOwnership(t *testing.T) {
	data, err := assets.ReadFile("assets/Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "USER root\nRUN install -d -o 10001 -g 10001 /work /gradle\nUSER netnone\n") {
		t.Fatalf("embedded image must prepare both volume mountpoints as UID/GID 10001 before dropping root:\n%s", data)
	}
}

// Invalid source/output mount paths reject relative, missing, file, colon and comma variants; symlinks resolve to an absolute directory.
func TestPathValidation(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(h.root, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"relative", filepath.Join(h.root, "missing"), file, filepath.Join(h.root, "bad:name"), filepath.Join(h.root, "bad,name")} {
		if got, err := directory(p); err == nil {
			t.Fatalf("accepted %q -> %q", p, got)
		}
	}
	link := filepath.Join(h.root, "link")
	if err := os.Symlink(h.o.Repo, link); err != nil {
		t.Fatal(err)
	}
	got, err := directory(link)
	if err != nil || got != h.o.Repo {
		t.Fatalf("canonicalization %s %v", got, err)
	}
}

// Selftest passes only with networked positive probes, denied negative probes, one offline pass, one network failure, and unchanged snapshots.
func TestSelftest(t *testing.T) {
	for _, row := range []struct {
		name, fixture, probe string
		changed              bool
		want                 int
	}{
		{"positive", "qualified", "", false, 0}, {"snapshot-changed", "qualified", "", true, 1}, {"dns-allowed", "qualified", "dns=ok\ntcp=fail:java.net.ConnectException:no route\n", false, 1},
		{"dependency", "dependency", "", false, 1}, {"both-pass", "both-pass", "", false, 1}, {"both-fail", "both-fail", "", false, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			h := newHarness(t)
			h.f.fixtureMode = row.fixture
			h.f.probeOutput = row.probe
			h.f.changedSnapshot = row.changed
			h.exec(t, "selftest", row.want)
			if h.f.contextReads != 2 {
				t.Fatalf("snapshots=%d", h.f.contextReads)
			}
			if !strings.Contains(h.out.String(), "| check | expected | observed | pass/fail |") {
				t.Fatal("missing verdict table")
			}
			if row.changed && !strings.Contains(h.out.String(), "context:changed") {
				t.Fatal("missing snapshot diff")
			}
			assertPrivate(t, h)
		})
	}
}

// Status reads held locks and records without creating state or stopping; explicit stop is allowed even for an unowned profile.
func TestStatusAndExplicitStop(t *testing.T) {
	h := newHarness(t)
	h.exec(t, "status", 0)
	if _, err := os.Stat(h.state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("status wrote state")
	}
	if err := os.Mkdir(h.state, 0700); err != nil {
		t.Fatal(err)
	}
	lock, err := acquireLock(h.state)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	h.out.Reset()
	h.exec(t, "status", 0)
	if !strings.Contains(h.out.String(), `"LockHeld":true`) {
		t.Fatal(h.out.String())
	}
	h.exec(t, "stop", 0)
	if len(callsNamed(h.f.calls, "colima", "stop")) != 1 {
		t.Fatal("explicit stop missing")
	}
	assertPrivate(t, h)
}

// Valid sysctl load parses exactly three finite nonnegative values; malformed, NaN, negative and extra values are rejected.
func TestParseLoad(t *testing.T) {
	got, err := ParseLoad("{ 1.5 2.25 3 }")
	if err != nil || got != [3]float64{1.5, 2.25, 3} {
		t.Fatalf("%v %v", got, err)
	}
	for _, s := range []string{"", "{ 1 2 }", "1 2 3 4", "1 NaN 3", "1 +Inf 3", "1 -1 3"} {
		if _, err := ParseLoad(s); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

// Bounded capture keeps at most 8 MiB and flags overflow without short writes; no subprocess is started.
func TestCappedBuffer(t *testing.T) {
	var b cappedBuffer
	n, err := b.Write(bytes.Repeat([]byte("x"), 8<<20+1))
	if err != nil || n != 8<<20+1 || len(b.data) != 8<<20 || !b.exceeded {
		t.Fatalf("capture n=%d len=%d exceeded=%t err=%v", n, len(b.data), b.exceeded, err)
	}
}

// Warm-task test failures do not fail prep; dry-run failures and malformed builds do not create a prep record.
func TestPrepWarmFailurePolicy(t *testing.T) {
	for _, mode := range []string{"test-failed", "dry-run-failed", "bad-build"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if mode == "bad-build" && c.Name == "docker" && c.Args[0] == "build" {
					return Result{Stdout: []byte("tag-only")}, nil, true
				}
				if has(c.Args, "netnone-prep") {
					if mode == "test-failed" {
						return Result{Stdout: []byte("dns=fail:java.net.UnknownHostException\ntcp=fail:java.net.ConnectException:no route\nnetnone-prep-test-exit=1\n")}, nil, true
					}
					if mode == "dry-run-failed" {
						return Result{ExitCode: 1, Stderr: []byte("Could not resolve dependency")}, nil, true
					}
				}
				return Result{}, nil, false
			}
			want := 1
			if mode == "test-failed" {
				want = 0
			}
			h.exec(t, "prep", want)
			_, err := os.Stat(filepath.Join(h.state, "prep-records.json"))
			if want == 0 && err != nil {
				t.Fatal(err)
			}
			if want != 0 && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed prep wrote a record")
			}
		})
	}
}

// Missing images refuse after start and still stop; test failures map to exit 1 and still print the output destination.
func TestRunFailurePolicy(t *testing.T) {
	for _, mode := range []string{"missing-image", "test-failed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h.exec(t, "prep", 0)
			h.f.calls = nil
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if has(c.Args, "image", "inspect") && mode == "missing-image" {
					return Result{ExitCode: 1}, nil, true
				}
				if has(c.Args, "netnone-run") {
					if mode == "cancelled" {
						return Result{}, context.Canceled, true
					}
					return Result{ExitCode: 7}, nil, true
				}
				return Result{}, nil, false
			}
			want := 1
			if mode == "missing-image" {
				want = 3
			}
			h.exec(t, "run", want)
			if len(callsNamed(h.f.calls, "colima", "stop")) != 1 {
				t.Fatal("run failure did not stop")
			}
			if mode != "missing-image" && !strings.Contains(h.out.String(), "out: "+h.o.Out) {
				t.Fatal("missing output path")
			}
		})
	}
}

// Bootstrap assets pin the supplied distribution/hash and order verification before extraction; mismatch refuses explicitly (static contract, not Java execution).
func TestBootstrapChecksumGuard(t *testing.T) {
	props, err := assets.ReadFile("assets/fixture/gradle/wrapper/gradle-wrapper.properties")
	if err != nil {
		t.Fatal(err)
	}
	want := "distributionUrl=https://services.gradle.org/distributions/gradle-8.10.2-bin.zip\ndistributionSha256Sum=31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26\n"
	if string(props) != want {
		t.Fatalf("distribution contract changed: %s", props)
	}
	boot, _ := assets.ReadFile("assets/fixture/gradlew")
	download, _ := assets.ReadFile("assets/fixture/Download.java")
	b, d := string(boot), string(download)
	verify, extract := strings.Index(b, "java /work/Download.java"), strings.Index(b, "jar xf gradle.zip")
	if verify < 0 || extract < verify || !strings.Contains(b, " --offline ") || !strings.Contains(b, `exec sh "$gradle" "$@"`) {
		t.Fatal("bootstrap verification/offline contract missing")
	}
	if !strings.Contains(d, `if (!actual.equals(properties.getProperty("distributionSha256Sum")))`) || !strings.Contains(d, "Files.delete(target);") || !strings.Contains(d, `throw new SecurityException("Gradle distribution SHA-256 mismatch")`) {
		t.Fatal("checksum mismatch rejection missing")
	}
}

// Snapshot content hashes and socket link identity participate in drift detection without reporting unchanged config content.
func TestSnapshotEvidence(t *testing.T) {
	h := newHarness(t)
	for _, rel := range []string{".docker/config.json", ".colima/ssh_config", ".ssh/config"} {
		p := filepath.Join(h.home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("before"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	socket := filepath.Join(h.home, ".colima/docker.sock")
	if err := os.Symlink("default/docker.sock", socket); err != nil {
		t.Fatal(err)
	}
	s := session{e: h.e, home: h.home, state: h.state, env: privateEnv(h.e.UserEnv, h.home, h.state)}
	before, err := s.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.home, ".ssh/config"), []byte("after"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other/docker.sock", socket); err != nil {
		t.Fatal(err)
	}
	after, err := s.snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	diff := snapshotDiff(before, after)
	if !strings.Contains(diff, ".ssh/config") || !strings.Contains(diff, ".colima/docker.sock") || strings.Contains(diff, ".docker/config.json") {
		t.Fatal(diff)
	}
}

// Invalid/incomplete JSON, dependency-resolution failures and missing fixture XML cannot qualify a selftest.
func TestUnknownEvidenceFails(t *testing.T) {
	for _, s := range []string{"", "null", "{", "{} garbage"} {
		if _, err := objects([]byte(s)); err == nil {
			t.Fatalf("accepted JSON %q", s)
		}
	}
	h := newHarness(t)
	if off, net, _ := inspectJUnit(h.root); off || net {
		t.Fatal("missing XML qualified")
	}
	for _, text := range []string{"java.net.UnknownHostException: Could not download dependency", "java.lang.AssertionError", "dependency-resolution java.net.ConnectException"} {
		if networkException(text) {
			t.Fatalf("non-network failure qualified: %s", text)
		}
	}
	if !networkException("java.net.ConnectException: Network is unreachable") {
		t.Fatal("network positive rejected")
	}
}

// A failed start never claims ownership or stops the profile; missing and stopped profiles permit start while unknown status fails closed.
func TestProfileAdmission(t *testing.T) {
	for _, mode := range []string{"start-error", "missing", "unknown", "stopping"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if c.Name == "colima" && c.Args[0] == "start" && mode == "start-error" {
					return Result{ExitCode: 1}, nil, true
				}
				if c.Name == "colima" && c.Args[0] == "status" {
					switch mode {
					case "missing":
						return Result{ExitCode: 1, Stderr: []byte("profile does not exist")}, nil, true
					case "unknown":
						return Result{Stdout: []byte(`{"status":"unknown"}`)}, nil, true
					case "stopping":
						return Result{Stdout: []byte(`{"status":"stopping"}`)}, nil, true
					}
				}
				return Result{}, nil, false
			}
			want := 1
			if mode == "missing" {
				want = 0
			}
			h.exec(t, "prep", want)
			stops := len(callsNamed(h.f.calls, "colima", "stop"))
			if mode == "missing" && stops != 1 || mode != "missing" && stops != 0 {
				t.Fatalf("stop count %d for %s", stops, mode)
			}
		})
	}
}

// Selftest fails unknown snapshots and missing XML, but accepts an empty successful Colima list and ignores netnone's own changing status.
func TestSelftestEvidenceBoundaries(t *testing.T) {
	for _, mode := range []string{"malformed-before", "malformed-after", "missing-xml", "empty-profiles", "own-profile-change", "prep-dns-fail", "prep-task-fail"} {
		t.Run(mode, func(t *testing.T) {
			h := newHarness(t)
			h.f.fixtureMode = "qualified"
			if mode == "missing-xml" {
				h.f.fixtureMode = ""
			}
			reads, lists := 0, 0
			h.f.hook = func(_ context.Context, c Command) (Result, error, bool) {
				if has(c.Args, "context", "ls") {
					reads++
					if mode == "malformed-before" || mode == "malformed-after" && reads == 2 {
						return Result{Stdout: []byte("invalid JSON")}, nil, true
					}
				}
				if c.Name == "colima" && c.Args[0] == "list" {
					lists++
					if mode == "empty-profiles" {
						return Result{}, nil, true
					}
					if mode == "own-profile-change" {
						status := "Stopped"
						if lists > 1 {
							status = "Running"
						}
						return Result{Stdout: []byte(fmt.Sprintf(`[{"name":"netnone","status":%q}]`, status))}, nil, true
					}
				}
				if has(c.Args, "netnone-prep") {
					if mode == "prep-dns-fail" {
						return Result{Stdout: []byte("dns=fail:java.net.UnknownHostException\ntcp=ok\nnetnone-prep-test-exit=0\n")}, nil, true
					}
					if mode == "prep-task-fail" {
						return Result{Stdout: []byte("dns=ok\ntcp=ok\nnetnone-prep-test-exit=1\n")}, nil, true
					}
				}
				return Result{}, nil, false
			}
			want := 1
			if mode == "empty-profiles" || mode == "own-profile-change" {
				want = 0
			}
			h.exec(t, "selftest", want)
			if mode == "malformed-before" && len(callsNamed(h.f.calls, "colima", "start")) > 0 {
				t.Fatal("started without before snapshot")
			}
		})
	}
}

// Resource overrides are passed literally to the VM; source/output permissions are preserved while only the new result directory is writable by UID 10001.
func TestResourcesAndOutputPermissions(t *testing.T) {
	h := newHarness(t)
	h.o.CPUs = 6
	h.o.Memory = 12
	h.o.Disk = 80
	h.exec(t, "prep", 0)
	h.exec(t, "run", 0)
	for _, c := range callsNamed(h.f.calls, "colima", "start") {
		if !has(c.Args, "--cpus", "6", "--memory", "12", "--disk", "80") {
			t.Fatalf("resources %v", c.Args)
		}
	}
	for _, path := range []string{h.o.Repo, h.o.Out} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != 0700 {
			t.Fatalf("changed existing permissions %s %v", path, err)
		}
	}
	entries, err := os.ReadDir(h.o.Out)
	if err != nil || len(entries) != 1 {
		t.Fatalf("output entries %v %v", entries, err)
	}
	st, err := os.Stat(filepath.Join(h.o.Out, entries[0].Name()))
	if err != nil || st.Mode().Perm() != 0777 {
		t.Fatalf("UID 10001 cannot write new result dir: %v %v", st, err)
	}
}

// Fixed guest scripts exclude stale build/cache trees, pass tasks literally, preserve normal task failure for artifact copying, and never bootstrap Gradle in offline mode (static contract only).
func TestGuestScriptContracts(t *testing.T) {
	for _, script := range []string{prepScript, runScript} {
		for _, required := range []string{"tar --no-wildcards --anchored -X /tmp/netnone-excludes -cf - .", "tar --no-same-owner -xf -", "cd /work"} {
			if !strings.Contains(script, required) {
				t.Fatalf("guest copy contract missing %q", required)
			}
		}
		if strings.Contains(script, "--no-daemon") || strings.Contains(script, "--exclude=src") {
			t.Fatal("guest script disables daemon or excludes source")
		}
	}
	if !strings.Contains(prepScript, "java /tmp/Probe.java || true") || !strings.Contains(prepScript, `./gradlew --refresh-dependencies "$1" --dry-run`) || !strings.Contains(prepScript, `./gradlew "$1"`) {
		t.Fatal("prep must tolerate probe failure and warm the literal task twice")
	}
	gradle, capture, collect, exit := strings.Index(runScript, `./gradlew --offline "$1"`), strings.Index(runScript, "rc=$?"), strings.Index(runScript, "find . -type d \\( -path"), strings.LastIndex(runScript, `exit "$rc"`)
	if gradle < 0 || capture < gradle || collect < capture || exit < collect {
		t.Fatal("task exit must be captured before reports are copied and returned afterwards")
	}
	for _, required := range []string{"*/build/test-results", "*/build/reports", `cp -R "$d" "/out/$stamp/$parent/"`} {
		if !strings.Contains(runScript, required) {
			t.Fatalf("artifact preservation missing %q", required)
		}
	}
}
