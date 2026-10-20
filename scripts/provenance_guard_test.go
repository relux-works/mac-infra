package scripts_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// Isolate fixture Git identity/config and Go stamping from host preferences.
func provenanceEnv() []string {
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GIT_") {
			env = append(env, value)
		}
	}
	return append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GOENV=off", "GOFLAGS=", "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local",
		"GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
}

func provenanceCommand(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, provenanceEnv()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func writeProvenanceFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func provenanceRepo(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "source repo")
	provenanceCommand(t, "", "git", "init", "--template=", root)
	for key, value := range map[string]string{
		"user.name": "Provenance Fixture", "user.email": "fixture@example.invalid",
		"commit.gpgsign": "false", "core.hooksPath": "/dev/null",
	} {
		provenanceCommand(t, root, "git", "config", "--local", key, value)
	}
	writeProvenanceFile(t, filepath.Join(root, "go.mod"), "module example.com/p\n\ngo 1.25.5\n")
	writeProvenanceFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {}\n")
	writeProvenanceFile(t, filepath.Join(root, ".gitignore"), "ignored.log\n")
	provenanceCommand(t, root, "git", "add", "go.mod", "main.go", ".gitignore")
	provenanceCommand(t, root, "git", "-c", "commit.gpgsign=false", "commit", "-m", "fixture A")
	provenanceCommand(t, root, "git", "remote", "add", "origin", "https://example.invalid/p.git")
	return root
}

func buildProvenanceBinary(t *testing.T, root string, flags ...string) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "fixture binary")
	args := append([]string{"build", "-o", binary}, flags...)
	provenanceCommand(t, root, "go", append(args, ".")...)
	return binary
}

func runProvenanceGuard(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("./provenance-guard.sh", args...)
	cmd.Env = provenanceEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return stdout.String(), stderr.String(), code
}

func requireProvenancePass(t *testing.T, args ...string) {
	t.Helper()
	if out, stderr, code := runProvenanceGuard(t, args...); code != 0 || out != "" || stderr != "" {
		t.Fatalf("want provenance pass for %v: stdout %q, stderr %q, exit %d", args, out, stderr, code)
	}
}

func requirePreflightRefusal(t *testing.T, root, reason string) {
	t.Helper()
	out, stderr, code := runProvenanceGuard(t, "preflight", root)
	lines := strings.Split(strings.TrimSuffix(stderr, "\n"), "\n")
	if code != 3 || out != "" || len(lines) != 2 || !strings.Contains(lines[0], reason) {
		t.Fatalf("want preflight refusal %q and one hint: stdout %q, stderr %q, exit %d", reason, out, stderr, code)
	}
	sha := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	want := "build from a standalone clone: git clone https://example.invalid/p.git DIR && git -C DIR checkout --detach " + sha
	if lines[1] != want {
		t.Fatalf("clone hint: got %q, want %q", lines[1], want)
	}
}

func requireVerifyRefusal(t *testing.T, root string, binaries ...string) string {
	t.Helper()
	args := append([]string{"verify", root}, binaries...)
	out, stderr, code := runProvenanceGuard(t, args...)
	if code != 3 || out != "" {
		t.Fatalf("want verify refusal: stdout %q, stderr %q, exit %d", out, stderr, code)
	}
	for _, binary := range binaries {
		if !strings.Contains(stderr, binary) {
			t.Errorf("verify did not report failing binary %q: %s", binary, stderr)
		}
	}
	if !strings.Contains(stderr, "vcs.revision=[") || !strings.Contains(stderr, "vcs.modified=[") {
		t.Errorf("verify did not report observed values: %s", stderr)
	}
	return stderr
}

// Claim: a clean standalone repo (also through a canonicalized symlink) and its actual Go build pass.
func TestProvenanceCleanStandalone(t *testing.T) {
	root := provenanceRepo(t)
	requireProvenancePass(t, "preflight", root)
	alias := filepath.Join(t.TempDir(), "source alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	requireProvenancePass(t, "preflight", alias+"/.")
	binary := buildProvenanceBinary(t, root)
	info := provenanceCommand(t, root, "go", "version", "-m", binary)
	sha := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	if !strings.Contains(info, "vcs.revision="+sha) || !strings.Contains(info, "vcs.modified=false") {
		t.Fatalf("positive build control has wrong metadata: %s", info)
	}
	requireProvenancePass(t, "verify", root, binary)
}

// Claim: tracked and non-ignored untracked changes refuse preflight; a committed ignore rule excludes ignored files.
func TestProvenanceDirtyTree(t *testing.T) {
	for _, kind := range []string{"tracked", "untracked", "ignored"} {
		t.Run(kind, func(t *testing.T) {
			root := provenanceRepo(t)
			requireProvenancePass(t, "preflight", root)
			name := map[string]string{"tracked": "main.go", "untracked": "extra.txt", "ignored": "ignored.log"}[kind]
			writeProvenanceFile(t, filepath.Join(root, name), "changed\n")
			if kind == "ignored" {
				requireProvenancePass(t, "preflight", root)
			} else {
				requirePreflightRefusal(t, root, "dirty tree")
			}
		})
	}
}

// Claim: a nested worktree refuses admission and a real inner build inherits the dirty outer repo's stamp.
func TestProvenanceNestedWorktree(t *testing.T) {
	outer := provenanceRepo(t)
	writeProvenanceFile(t, filepath.Join(outer, "main.go"), "package main\n\nfunc main() {} // outer change\n")
	provenanceCommand(t, outer, "git", "worktree", "add", "inner", "HEAD")
	inner := filepath.Join(outer, "inner")
	if status := provenanceCommand(t, inner, "git", "status", "--porcelain"); status != "" {
		t.Fatalf("inner worktree control is dirty: %s", status)
	}
	requirePreflightRefusal(t, inner, "worktree")
	binary := buildProvenanceBinary(t, inner)
	info := provenanceCommand(t, inner, "go", "version", "-m", binary)
	sha := provenanceCommand(t, outer, "git", "rev-parse", "HEAD")
	if !strings.Contains(info, "vcs.revision="+sha) || !strings.Contains(info, "vcs.modified=true") {
		t.Fatalf("real Go nested-worktree control did not inherit the dirty outer stamp: %s", info)
	}
	stderr := requireVerifyRefusal(t, inner, binary)
	if !strings.Contains(stderr, "vcs.modified=[true]") {
		t.Fatalf("verify did not report actual dirty stamp: %s", stderr)
	}
}

// Claim: a repository subdirectory refuses with the distinct not-repository-top reason.
func TestProvenanceNotRepositoryTop(t *testing.T) {
	root := provenanceRepo(t)
	subdir := filepath.Join(root, "subdir")
	if err := os.Mkdir(subdir, 0o700); err != nil {
		t.Fatal(err)
	}
	requirePreflightRefusal(t, subdir, "not repository top")
}

// Claim: advancing source HEAD refuses an older clean binary and reports both full revisions.
func TestProvenanceStaleBinary(t *testing.T) {
	root := provenanceRepo(t)
	binary := buildProvenanceBinary(t, root)
	requireProvenancePass(t, "verify", root, binary)
	oldSHA := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	writeProvenanceFile(t, filepath.Join(root, "main.go"), "package main\n\nfunc main() {} // commit B\n")
	provenanceCommand(t, root, "git", "add", "main.go")
	provenanceCommand(t, root, "git", "-c", "commit.gpgsign=false", "commit", "-m", "fixture B")
	newSHA := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	requireProvenancePass(t, "preflight", root)
	stderr := requireVerifyRefusal(t, root, binary)
	if !strings.Contains(stderr, "vcs.revision=["+oldSHA+"]") || !strings.Contains(stderr, "expected "+newSHA) {
		t.Fatalf("wrong stale revision diagnosis: %s", stderr)
	}
	requireProvenancePass(t, "verify", root, buildProvenanceBinary(t, root))
}

// Claim: a real build with VCS stamping disabled refuses with both metadata values missing.
func TestProvenanceMissingBuildinfo(t *testing.T) {
	root := provenanceRepo(t)
	binary := buildProvenanceBinary(t, root, "-buildvcs=false")
	stderr := requireVerifyRefusal(t, root, binary)
	if !strings.Contains(stderr, "vcs.revision=[missing]") || !strings.Contains(stderr, "vcs.modified=[missing]") {
		t.Fatalf("wrong missing metadata diagnosis: %s", stderr)
	}
}

// Claim: a dirty standalone build at the correct revision refuses specifically because its modified stamp is true.
func TestProvenanceDirtyBinary(t *testing.T) {
	root := provenanceRepo(t)
	requireProvenancePass(t, "verify", root, buildProvenanceBinary(t, root))
	writeProvenanceFile(t, filepath.Join(root, "extra.txt"), "untracked change\n")
	binary := buildProvenanceBinary(t, root)
	sha := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	stderr := requireVerifyRefusal(t, root, binary)
	if !strings.Contains(stderr, "vcs.revision=["+sha+"]") || !strings.Contains(stderr, "vcs.modified=[true]") {
		t.Fatalf("wrong dirty build diagnosis: %s", stderr)
	}
}

// Claim: parser fixtures require exactly one revision and one false modified record; real Go builds are covered separately.
func TestProvenanceBuildinfoCardinality(t *testing.T) {
	root := provenanceRepo(t)
	sha := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	tools := t.TempDir()
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	revision := "\tbuild\tvcs.revision=" + sha + "\n"
	clean := "\tbuild\tvcs.modified=false\n"
	for _, row := range []struct {
		name, records string
		pass          bool
	}{
		{"valid", revision + clean, true},
		{"duplicate-revision", revision + revision + clean, false},
		{"duplicate-modified", revision + clean + clean, false},
		{"conflicting-modified", revision + clean + "\tbuild\tvcs.modified=true\n", false},
		{"missing-revision", clean, false},
		{"missing-modified", revision, false},
		{"short-revision", "\tbuild\tvcs.revision=" + sha[:12] + "\n" + clean, false},
		{"similar-text", "prefix" + revision + clean, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fakeTool(t, tools, "go", "cat <<'BUILDINFO'\n"+row.records+"BUILDINFO")
			if row.pass {
				requireProvenancePass(t, "verify", root, "parser-fixture")
			} else {
				requireVerifyRefusal(t, root, "parser-fixture")
			}
		})
	}
}

// Claim: unreadable and non-Go paths refuse with observed metadata missing, rather than being silently accepted.
func TestProvenanceUnreadableBinary(t *testing.T) {
	root := provenanceRepo(t)
	nonGo := filepath.Join(t.TempDir(), "not a Go binary")
	writeProvenanceFile(t, nonGo, "plain text\n")
	requireVerifyRefusal(t, root, nonGo, nonGo+"-missing")
}

// Claim: verify reports two real unstamped binaries even with a valid binary between them.
func TestProvenanceReportsEveryFailure(t *testing.T) {
	root := provenanceRepo(t)
	badA := buildProvenanceBinary(t, root, "-buildvcs=false")
	good := buildProvenanceBinary(t, root)
	badB := buildProvenanceBinary(t, root, "-buildvcs=false")
	out, stderr, code := runProvenanceGuard(t, "verify", root, badA, good, badB)
	if code != 3 || out != "" || !strings.Contains(stderr, badA) || !strings.Contains(stderr, badB) || strings.Contains(stderr, good) {
		t.Fatalf("want every bad binary and no good binary reported: stdout %q, stderr %q, exit %d", out, stderr, code)
	}
}

// Claim: static setup wiring gates all Go outputs before installation, includes only rebuilt keyvault, and warns on both bypass endpoints.
func TestSetupProvenanceWiring(t *testing.T) {
	data, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	preflight := strings.Index(source, `"$SCRIPT_DIR/provenance-guard.sh" preflight`)
	keyvault := strings.Index(source, `KEYVAULT_DECISION=`)
	goTest := strings.Index(source, `go -C "$PROJECT_ROOT" test ./...`)
	goCheck := strings.Index(source, `if ! command -v go`)
	firstWrite := strings.Index(source, `mkdir -p "$BIN_DIR"`)
	verify := strings.Index(source, `"$SCRIPT_DIR/provenance-guard.sh" verify`)
	lastBuild := strings.LastIndex(source, `go -C "$PROJECT_ROOT" build`)
	firstLink := strings.Index(source, `ln -sf `)
	launcherInstall := strings.Index(source, `mkdir -p "$HEARTBEAT_LAUNCHER_DIR"`)
	if goCheck < 0 || preflight <= goCheck || keyvault <= preflight || goTest <= preflight || firstWrite <= preflight {
		t.Fatal("preflight must follow the Go check and precede keyvault, tests and directory creation")
	}
	if lastBuild < 0 || verify <= lastBuild || firstLink <= verify || launcherInstall <= verify {
		t.Fatal("verify must follow every Go build and precede linking and launcher installation")
	}
	for _, want := range []string{
		"--allow-unprovable)\n      ALLOW_UNPROVABLE=1\n      shift",
		"if [[ \"$ALLOW_UNPROVABLE\" == 1 ]]; then\n  warn_unprovable\nelse\n  \"$SCRIPT_DIR/provenance-guard.sh\" preflight",
		"if [[ \"$ALLOW_UNPROVABLE\" != 1 ]]; then\n  BUILT_BINARIES=(",
		"if [[ \"$KEYVAULT_DECISION\" == build ]]; then\n    BUILT_BINARIES+=(\"$BUILD_DIR/mac-keyvault\")\n  fi\n  \"$SCRIPT_DIR/provenance-guard.sh\" verify \"$PROJECT_ROOT\" \"${BUILT_BINARIES[@]}\"\nfi",
		"WARNING: --allow-unprovable: installed binaries are not provably built from a reviewed commit.",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("setup missing provenance contract %q", want)
		}
	}
	if !strings.HasSuffix(source, "if [[ \"$ALLOW_UNPROVABLE\" == 1 ]]; then\n  warn_unprovable\nfi\n") || strings.Count(source, "\n  warn_unprovable\n") != 2 {
		t.Error("bypass must warn once at the start and once at the end")
	}
	listStart := strings.Index(source, "  BUILT_BINARIES=(\n")
	if listStart < 0 || listStart >= verify {
		t.Fatal("missing verification list")
	}
	list := source[listStart:verify]
	builds := regexp.MustCompile(`go -C "\$PROJECT_ROOT" build[^\n]* -o "(\$BUILD_DIR/[^"\n]+)"`).FindAllStringSubmatch(source, -1)
	if len(builds) == 0 {
		t.Fatal("no Go build outputs found")
	}
	for _, build := range builds {
		if strings.Count(list, `"`+build[1]+`"`) != 1 {
			t.Errorf("Go output %s must occur exactly once in the verification list", build[1])
		}
	}
	if strings.Contains(list, "mac-keyvault-enclave") {
		t.Error("Swift helper has no Go VCS buildinfo")
	}
}
