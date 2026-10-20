package scripts_test

import (
	"bytes"
	"encoding/json"
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
	return runProvenanceGuardEnv(t, nil, args...)
}

func runProvenanceGuardEnv(t *testing.T, overrides []string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("./provenance-guard.sh", args...)
	cmd.Env = append(provenanceEnv(), overrides...)
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

// Claim: structured fixtures require one JSON object and exactly one matching revision/false modified setting.
// Real Go inspection and filename injection are covered separately.
func TestProvenanceBuildinfoCardinality(t *testing.T) {
	root := provenanceRepo(t)
	sha := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	tools := t.TempDir()
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	binary := filepath.Join(t.TempDir(), "parser-fixture")
	writeProvenanceFile(t, binary, "fixture")
	revision := `{"Key":"vcs.revision","Value":"` + sha + `"}`
	clean := `{"Key":"vcs.modified","Value":"false"}`
	object := func(settings string) string { return `{"Settings":[` + settings + `]}` }
	valid := object(revision + "," + clean)
	for _, row := range []struct {
		name, records string
		pass          bool
		exit          string
	}{
		{"valid", valid, true, "0"},
		{"empty-unrelated-value", object(revision + "," + clean + `,{"Key":"CGO_CFLAGS"}`), true, "0"},
		{"duplicate-revision", object(revision + "," + revision + "," + clean), false, "0"},
		{"duplicate-modified", object(revision + "," + clean + "," + clean), false, "0"},
		{"conflicting-modified", object(revision + "," + clean + `,{"Key":"vcs.modified","Value":"true"}`), false, "0"},
		{"missing-revision", object(clean), false, "0"},
		{"missing-modified", object(revision), false, "0"},
		{"short-revision", object(`{"Key":"vcs.revision","Value":"` + sha[:12] + `"},` + clean), false, "0"},
		{"text-records", "\tbuild\tvcs.revision=" + sha + "\n\tbuild\tvcs.modified=false", false, "0"},
		{"two-objects", valid + "\n" + valid, false, "0"},
		{"array", "[" + valid + "]", false, "0"},
		{"malformed", valid + "trailer", false, "0"},
		{"wrong-settings-type", `{"Settings":{}}`, false, "0"},
		{"wrong-value-type", object(revision + `,{"Key":"vcs.modified","Value":false}`), false, "0"},
		{"nonzero-with-valid-json", valid, false, "1"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fakeTool(t, tools, "go", "cat <<'BUILDINFO'\n"+row.records+"\nBUILDINFO\nexit "+row.exit)
			if row.pass {
				requireProvenancePass(t, "verify", root, binary)
			} else {
				requireVerifyRefusal(t, root, binary)
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

// Claim: static setup wiring stages every Go build/sign, preflights at all three boundaries,
// disables workspaces, publishes only rebuilt keyvault, and installs/links only after publication.
// This inspects source; setup is never executed.
func TestSetupProvenanceWiring(t *testing.T) {
	data, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	preflights := regexp.MustCompile(`"\$SCRIPT_DIR/provenance-guard.sh" preflight "\$PROJECT_ROOT"`).FindAllStringIndex(source, -1)
	goTest := strings.Index(source, `go -C "$PROJECT_ROOT" test ./...`)
	firstBuild := strings.Index(source, `go -C "$PROJECT_ROOT" build`)
	lastBuild := strings.LastIndex(source, `go -C "$PROJECT_ROOT" build`)
	publish := strings.Index(source, `"$SCRIPT_DIR/provenance-guard.sh" publish`)
	firstWrite := strings.Index(source, `mkdir -p "$BIN_DIR"`)
	if len(preflights) != 3 {
		t.Fatalf("want three preflights, got %d", len(preflights))
	}
	if goTest < 0 || preflights[0][0] <= strings.Index(source, `if ! command -v go`) || preflights[0][0] >= firstWrite || preflights[0][0] >= strings.Index(source, `KEYVAULT_DECISION=`) {
		t.Fatal("initial preflight must follow Go availability and precede writes, keyvault and tests")
	}
	if preflights[1][0] <= goTest || preflights[1][0] >= firstBuild {
		t.Fatal("second preflight must follow tests and precede the first build")
	}
	// The bypass branch occurs first in source; the last preflight gates normal publication.
	normalPublish := strings.LastIndex(source, `"$SCRIPT_DIR/provenance-guard.sh" publish`)
	if preflights[2][0] <= lastBuild || preflights[2][0] >= normalPublish {
		t.Fatal("final preflight must follow builds and precede publish")
	}
	if publish <= lastBuild || strings.Index(source, `ln -sf `) <= normalPublish || strings.Index(source, `mkdir -p "$HEARTBEAT_LAUNCHER_DIR"`) <= normalPublish {
		t.Fatal("publish must follow every Go build and precede linking and launcher installation")
	}
	workspace := strings.Index(source, "export GOWORK=off")
	if workspace < 0 || workspace >= goTest || strings.Count(source, "GOWORK=") != 1 {
		t.Fatal("setup must disable ambient workspaces before tests and every build")
	}
	for _, want := range []string{
		"--allow-unprovable)\n      ALLOW_UNPROVABLE=1\n      shift",
		"if [[ \"$ALLOW_UNPROVABLE\" == 1 ]]; then\n  warn_unprovable\nelse\n  \"$SCRIPT_DIR/provenance-guard.sh\" preflight",
		`STAGE_DIR="$(mktemp -d "$BUILD_DIR/.staging.XXXXXX")"`,
		`trap 'rm -rf "$STAGE_DIR"' EXIT`,
		`trap 'exit 129' HUP`, `trap 'exit 130' INT`, `trap 'exit 143' TERM`,
		"if [[ \"$KEYVAULT_DECISION\" == build ]]; then\n  BUILT_BINARIES+=(\"mac-keyvault\")\nfi",
		`publish "$PROJECT_ROOT" "$STAGE_DIR" "$BUILD_DIR" --allow-unprovable "${BUILT_BINARIES[@]}"`,
		`publish "$PROJECT_ROOT" "$STAGE_DIR" "$BUILD_DIR" "${BUILT_BINARIES[@]}"`,
		"WARNING: --allow-unprovable: installed binaries are not provably built from a reviewed commit.",
	} {
		if !strings.Contains(source, want) {
			t.Errorf("setup missing provenance contract %q", want)
		}
	}
	if !strings.HasSuffix(source, "if [[ \"$ALLOW_UNPROVABLE\" == 1 ]]; then\n  warn_unprovable\nfi\n") || strings.Count(source, "\n  warn_unprovable\n") != 2 {
		t.Error("bypass must warn once at the start and once at the end")
	}
	listStart := strings.Index(source, "BUILT_BINARIES=(\n")
	if listStart < 0 || listStart >= publish {
		t.Fatal("missing publication list")
	}
	list := source[listStart:publish]
	builds := regexp.MustCompile(`go -C "\$PROJECT_ROOT" build[^\n]* -o "\$STAGE_DIR/([^"\n]+)"`).FindAllStringSubmatch(source, -1)
	if len(builds) != 15 || strings.Count(source, `go -C "$PROJECT_ROOT" build`) != len(builds) {
		t.Fatal("all 15 Go outputs must build into staging")
	}
	for _, build := range builds {
		if strings.Count(list, `"`+build[1]+`"`) != 1 {
			t.Errorf("Go output %s must occur once in publication list", build[1])
		}
	}
	if strings.Contains(list, "mac-keyvault-enclave") {
		t.Error("Swift helper has no Go VCS buildinfo")
	}
	for _, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "codesign") && (strings.Contains(line, "mac-safari-session") || strings.Contains(line, "mac-chrome-session")) && !strings.Contains(line, "$STAGE_DIR/") {
			t.Errorf("browser signing must use staging: %s", line)
		}
	}
}

// Claim: newline/tab filename headers cannot supply VCS settings to a real unstamped binary.
func TestProvenanceFilenameInjection(t *testing.T) {
	root := provenanceRepo(t)
	requireProvenancePass(t, "verify", root, buildProvenanceBinary(t, root))
	binary := buildProvenanceBinary(t, root, "-buildvcs=false")
	sha := provenanceCommand(t, root, "git", "rev-parse", "HEAD")
	injected := filepath.Join(filepath.Dir(binary), "tool\n\tbuild\tvcs.revision="+sha+"\n\tbuild\tvcs.modified=false\ntrailer")
	if err := os.Rename(binary, injected); err != nil {
		t.Fatal(err)
	}
	stderr := requireVerifyRefusal(t, root, injected)
	if !strings.Contains(stderr, "vcs.revision=[missing]") || !strings.Contains(stderr, "vcs.modified=[missing]") {
		t.Fatalf("filename impersonated metadata: %s", stderr)
	}
}

// Claim: directories containing a valid Go binary and symlinks to one are refused as verification inputs.
func TestProvenanceRegularFilesOnly(t *testing.T) {
	root := provenanceRepo(t)
	binary := buildProvenanceBinary(t, root)
	requireProvenancePass(t, "verify", root, binary)
	link := filepath.Join(t.TempDir(), "binary link")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	requireVerifyRefusal(t, root, filepath.Dir(binary), link)
}

// Claim: explicit status flags expose an untracked compiling source file even when local config hides untracked files.
func TestProvenanceHiddenUntrackedSource(t *testing.T) {
	root := provenanceRepo(t)
	provenanceCommand(t, root, "git", "config", "--local", "status.showUntrackedFiles", "no")
	requireProvenancePass(t, "preflight", root)
	writeProvenanceFile(t, filepath.Join(root, "extra.go"), "package main\n\nfunc extra() {}\n")
	if status := provenanceCommand(t, root, "git", "status", "--porcelain"); status != "" {
		t.Fatalf("control config did not hide source: %s", status)
	}
	// This is real compilable input; Go's default stamp alone misses it under this config.
	binary := buildProvenanceBinary(t, root)
	requireProvenancePass(t, "verify", root, binary)
	requirePreflightRefusal(t, root, "dirty tree")
}

func copyProvenanceFile(t *testing.T, from, to string) []byte {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o700); err != nil {
		t.Fatal(err)
	}
	return data
}

func requireProvenanceBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("publication changed bytes at %q: read error %v, equal=%v", path, err, bytes.Equal(got, want))
	}
}

// Claim: a bad second staged binary leaves every existing destination and staged byte intact;
// all-good publication replaces every destination and consumes staged files. Bypass skips buildinfo only.
func TestProvenancePublish(t *testing.T) {
	root := provenanceRepo(t)
	good := buildProvenanceBinary(t, root)
	bad := buildProvenanceBinary(t, root, "-buildvcs=false")
	for _, kind := range []string{"bad-second", "all-good", "bypass"} {
		t.Run(kind, func(t *testing.T) {
			stage, dest := t.TempDir(), t.TempDir()
			names := []string{"first", "second"}
			old := [][]byte{[]byte("existing first\x00bytes"), []byte("existing second\nbytes")}
			var staged [][]byte
			for i, name := range names {
				writeProvenanceFile(t, filepath.Join(dest, name), string(old[i]))
				from := good
				if i == 1 && kind != "all-good" {
					from = bad
				}
				staged = append(staged, copyProvenanceFile(t, from, filepath.Join(stage, name)))
			}
			args := []string{"publish", root, stage, dest}
			if kind == "bypass" {
				args = append(args, "--allow-unprovable")
			}
			out, stderr, code := runProvenanceGuard(t, append(args, names...)...)
			if kind == "bad-second" {
				if code != 3 || out != "" || !strings.Contains(stderr, filepath.Join(stage, "second")) {
					t.Errorf("want bad second binary refusal: stdout %q, stderr %q, exit %d", out, stderr, code)
				}
				for i, name := range names {
					requireProvenanceBytes(t, filepath.Join(dest, name), old[i])
					requireProvenanceBytes(t, filepath.Join(stage, name), staged[i])
				}
			} else {
				if code != 0 || out != "" || stderr != "" {
					t.Errorf("want complete publication: stdout %q, stderr %q, exit %d", out, stderr, code)
				}
				for i, name := range names {
					requireProvenanceBytes(t, filepath.Join(dest, name), staged[i])
					if _, err := os.Lstat(filepath.Join(stage, name)); !os.IsNotExist(err) {
						t.Errorf("published stage file survived: %s (%v)", name, err)
					}
				}
			}
		})
	}
}

// Claim: invalid staged inputs or directory destinations refuse before an earlier good file is moved,
// including under the metadata bypass; destination and good staged bytes survive.
func TestProvenancePublishInvalidPaths(t *testing.T) {
	root := provenanceRepo(t)
	good := buildProvenanceBinary(t, root)
	for _, kind := range []string{"missing", "directory", "symlink", "destination-directory"} {
		for _, bypass := range []bool{false, true} {
			t.Run(kind+map[bool]string{false: "", true: "-bypass"}[bypass], func(t *testing.T) {
				stage, dest := t.TempDir(), t.TempDir()
				first := copyProvenanceFile(t, good, filepath.Join(stage, "first"))
				writeProvenanceFile(t, filepath.Join(dest, "first"), "existing")
				second := filepath.Join(stage, "second")
				switch kind {
				case "directory":
					if err := os.Mkdir(second, 0o700); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					if err := os.Symlink(good, second); err != nil {
						t.Fatal(err)
					}
				case "destination-directory":
					copyProvenanceFile(t, good, second)
					if err := os.Mkdir(filepath.Join(dest, "second"), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				args := []string{"publish", root, stage, dest}
				if bypass {
					args = append(args, "--allow-unprovable")
				}
				_, stderr, code := runProvenanceGuard(t, append(args, "first", "second")...)
				if code != 3 || !strings.Contains(stderr, "regular staged file or destination is a directory") {
					t.Errorf("want path refusal, got exit %d: %s", code, stderr)
				}
				requireProvenanceBytes(t, filepath.Join(dest, "first"), []byte("existing"))
				requireProvenanceBytes(t, filepath.Join(stage, "first"), first)
			})
		}
	}
}

// Claim: each nonempty Git repository/index override refuses every command, even bypassed publish,
// before any move; empty values remain valid. This tests refusal, not each variable's Git semantics.
func TestProvenanceGitEnvironmentOverrides(t *testing.T) {
	root := provenanceRepo(t)
	good := buildProvenanceBinary(t, root)
	for _, variable := range []string{"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE"} {
		t.Run(variable, func(t *testing.T) {
			stage, dest := t.TempDir(), t.TempDir()
			staged := copyProvenanceFile(t, good, filepath.Join(stage, "tool"))
			writeProvenanceFile(t, filepath.Join(dest, "tool"), "existing")
			for _, args := range [][]string{
				{"preflight", root}, {"verify", root, good},
				{"publish", root, stage, dest, "tool"},
				{"publish", root, stage, dest, "--allow-unprovable", "tool"},
			} {
				_, stderr, code := runProvenanceGuardEnv(t, []string{variable + "=override"}, args...)
				if code != 3 || !strings.Contains(stderr, "git environment override") {
					t.Errorf("%v: want git environment override refusal, got %d: %s", args, code, stderr)
				}
			}
			requireProvenanceBytes(t, filepath.Join(dest, "tool"), []byte("existing"))
			requireProvenanceBytes(t, filepath.Join(stage, "tool"), staged)
			for _, args := range [][]string{{"preflight", root}, {"verify", root, good}, {"publish", root, stage, dest, "tool"}} {
				out, stderr, code := runProvenanceGuardEnv(t, []string{variable + "="}, args...)
				if code != 0 || out != "" || stderr != "" {
					t.Errorf("empty override must pass: %v: %d %s", args, code, stderr)
				}
			}
		})
	}
}

// Claim: checkout A cannot admit B's distinct empty-commit revision through GIT_DIR/GIT_WORK_TREE,
// even when a real Go build under those overrides stamps B and the source trees match.
func TestProvenanceGitRedirectedCheckout(t *testing.T) {
	a := provenanceRepo(t)
	b := filepath.Join(t.TempDir(), "repo B")
	provenanceCommand(t, "", "git", "clone", "--no-local", a, b)
	provenanceCommand(t, b, "git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-m", "distinct B")
	shaA := provenanceCommand(t, a, "git", "rev-parse", "HEAD")
	shaB := provenanceCommand(t, b, "git", "rev-parse", "HEAD")
	if shaA == shaB || provenanceCommand(t, a, "git", "rev-parse", "HEAD^{tree}") != provenanceCommand(t, b, "git", "rev-parse", "HEAD^{tree}") {
		t.Fatal("A/B controls need distinct revisions and identical trees")
	}
	requireProvenancePass(t, "preflight", a)
	binary := filepath.Join(t.TempDir(), "redirected")
	overrides := []string{"GIT_DIR=" + filepath.Join(b, ".git"), "GIT_WORK_TREE=" + a}
	cmd := exec.Command("go", "build", "-o", binary, ".")
	cmd.Dir, cmd.Env = a, append(provenanceEnv(), overrides...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("redirected build: %v %s", err, out)
	}
	info := provenanceCommand(t, a, "go", "version", "-m", "-json", binary)
	var stamp struct{ Settings []struct{ Key, Value string } }
	if err := json.Unmarshal([]byte(info), &stamp); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, setting := range stamp.Settings {
		if setting.Key == "vcs.revision" && setting.Value == shaB {
			found = true
		}
	}
	if !found {
		t.Fatalf("real Go control did not stamp B: %s", info)
	}
	for _, args := range [][]string{{"preflight", a}, {"verify", a, binary}} {
		_, stderr, code := runProvenanceGuardEnv(t, overrides, args...)
		if code != 3 || !strings.Contains(stderr, "git environment override") {
			t.Errorf("redirected checkout must refuse: %v: %d %s", args, code, stderr)
		}
	}
	requireVerifyRefusal(t, a, binary)
	requireProvenancePass(t, "verify", a, buildProvenanceBinary(t, a))
}

// Claim: preflight compares the physical effective Git directory with ROOT/.git;
// a shim changes only the effective-directory answer, while other lookups use real Git.
func TestProvenanceEffectiveGitDirectory(t *testing.T) {
	root, other := provenanceRepo(t), provenanceRepo(t)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	fakeTool(t, tools, "git", `if [[ "$*" == *"rev-parse --absolute-git-dir" ]]; then
  printf '%s\n' "$PROVENANCE_TEST_GIT_DIR"
else
  exec "$PROVENANCE_REAL_GIT" "$@"
fi`)
	t.Setenv("PATH", tools+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PROVENANCE_REAL_GIT", realGit)
	t.Setenv("PROVENANCE_TEST_GIT_DIR", filepath.Join(root, ".git"))
	requireProvenancePass(t, "preflight", root)
	t.Setenv("PROVENANCE_TEST_GIT_DIR", filepath.Join(other, ".git"))
	requirePreflightRefusal(t, root, "not checkout git directory")
}
