package scripts_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type setupFixture struct {
	root, home, bin string
	env             []string
}

func newSetupFixture(t *testing.T, cache string) setupFixture {
	t.Helper()
	base := t.TempDir()
	f := setupFixture{root: filepath.Join(base, "source copy"), home: filepath.Join(base, "home"), bin: filepath.Join(base, "installed")}
	for _, dir := range []string{f.root, f.home, f.bin} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Copy the current candidate's tracked files, never its bin/, Git metadata or local state.
	files := provenanceCommand(t, "..", "git", "ls-files", "-z")
	for _, name := range strings.Split(files, "\x00") {
		if name == "" {
			continue
		}
		from, to := filepath.Join("..", name), filepath.Join(f.root, name)
		info, err := os.Stat(from)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(to), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, data, info.Mode().Perm()); err != nil {
			t.Fatal(err)
		}
	}
	f.env = append(provenanceEnv(), "HOME="+f.home, "BIN_DIR="+f.bin, "GOCACHE="+cache, "GOPATH="+filepath.Join(base, "gopath"))
	return f
}

func (f setupFixture) run(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("/bin/bash", append([]string{filepath.Join(f.root, "scripts/setup.sh")}, args...)...)
	cmd.Dir, cmd.Env = f.root, f.env
	output, err := cmd.CombinedOutput()
	code := 0
	if exit, ok := err.(*exec.ExitError); ok {
		code = exit.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	t.Logf("setup.sh %v: exit %d", args, code)
	return string(output), code
}

// setupTree records file bytes, permissions and symlink text without following links.
func setupTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if os.IsNotExist(err) && path == root {
			return nil
		}
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var data []byte
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			data = []byte(target)
		} else {
			data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		tree[rel] = fmt.Sprintf("%s:%s", info.Mode(), data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func globalSkillWrites(home string) []string {
	var found []string
	for _, name := range []string{".agents", ".claude", ".codex"} {
		if _, err := os.Lstat(filepath.Join(home, name)); !os.IsNotExist(err) {
			found = append(found, name)
		}
	}
	return found
}

func requireNoGlobalSkill(t *testing.T, home string) {
	t.Helper()
	if found := globalSkillWrites(home); len(found) != 0 {
		t.Fatalf("setup created global skill paths: %v", found)
	}
}

// Claim: scoped setup publishes only selected tools, preserves unselected bytes/links, and creates no global skills.
func TestSetupScopedInstall(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("setup requires macOS codesign")
	}
	cache := t.TempDir()
	t.Run("only-load-profile", func(t *testing.T) {
		f := newSetupFixture(t, cache)
		buildDir := filepath.Join(f.root, "bin")
		if err := os.Mkdir(buildDir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"mac-infra-core", "mac-keyvault", "mac-chrome-session", "unrelated"} {
			writeProvenanceFile(t, filepath.Join(buildDir, name), "old "+name+"\x00bytes")
			if err := os.Symlink(filepath.Join(buildDir, name), filepath.Join(f.bin, name)); err != nil {
				t.Fatal(err)
			}
		}
		// An existing keyvault link into another checkout must remain exactly as installed.
		if err := os.Remove(filepath.Join(f.bin, "mac-keyvault")); err != nil {
			t.Fatal(err)
		}
		other := filepath.Join(f.home, "other-keyvault")
		writeProvenanceFile(t, other, "other trusted keyvault")
		if err := os.Symlink(other, filepath.Join(f.bin, "mac-keyvault")); err != nil {
			t.Fatal(err)
		}
		beforeBuild, beforeLinks := setupTree(t, buildDir), setupTree(t, f.bin)
		// An ambient workspace must not influence listing, tests or builds.
		workspace := filepath.Join(f.home, "go.work")
		writeProvenanceFile(t, workspace, "deliberately invalid workspace\n")
		f.env = append(f.env, "GOWORK="+workspace)
		out, code := f.run(t, "--only", "mac-load-profile", "--allow-unprovable")
		if code != 0 {
			t.Fatalf("scoped setup: exit %d\n%s", code, out)
		}
		afterBuild, afterLinks := setupTree(t, buildDir), setupTree(t, f.bin)
		if len(afterBuild) != len(beforeBuild)+1 || len(afterLinks) != len(beforeLinks)+1 {
			t.Fatalf("unexpected published outputs or links: %v / %v", mapKeys(afterBuild), mapKeys(afterLinks))
		}
		binary := filepath.Join(buildDir, "mac-load-profile")
		if info, err := os.Stat(binary); err != nil || info.Mode().Perm()&0111 == 0 {
			t.Fatalf("selected binary not executable: %v", err)
		}
		link, err := os.Readlink(filepath.Join(f.bin, "mac-load-profile"))
		if err != nil || link != binary {
			t.Fatalf("selected link: %q (%v)", link, err)
		}
		delete(afterBuild, "mac-load-profile")
		delete(afterLinks, "mac-load-profile")
		if !reflect.DeepEqual(beforeBuild, afterBuild) || !reflect.DeepEqual(beforeLinks, afterLinks) {
			t.Fatal("unselected bytes, permissions or link targets changed")
		}
		requireProvenanceBytes(t, other, []byte("other trusted keyvault"))
		requireNoGlobalSkill(t, f.home)
		if _, err := os.Stat(filepath.Join(f.home, "Library/Application Support/mac-infra/browser-session")); !os.IsNotExist(err) {
			t.Fatalf("scoped setup installed heartbeat launcher: %v", err)
		}
		if strings.Count(out, "WARNING: --allow-unprovable:") != 2 {
			t.Fatalf("missing bypass warnings:\n%s", out)
		}
		t.Log("1 binary published and linked; 4 unselected files and links preserved; 0 global skill paths")
	})
	// Claim: invalid selections and unapproved keyvault selection refuse before testing, building or publishing.
	t.Run("refusals", func(t *testing.T) {
		cases := []struct {
			name string
			args []string
			code int
		}{
			{"unknown", []string{"--only", "mac-infra-core,unknown-tool"}, 2},
			{"missing", []string{"--only"}, 2},
			{"empty", []string{"--only", ""}, 2},
			{"trailing-comma", []string{"--only", "mac-load-profile,"}, 2},
			{"empty-element", []string{"--only", "mac-load-profile,,mac-security"}, 2},
			{"newline", []string{"--only", "mac-load-profile\nunknown"}, 2},
			{"keyvault", []string{"--only", "mac-keyvault"}, 1},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				f := newSetupFixture(t, cache)
				out, code := f.run(t, append(tc.args, "--allow-unprovable")...)
				if code != tc.code || strings.Contains(out, "Testing Go packages") || strings.Contains(out, "Building ") {
					t.Fatalf("wrong refusal: exit %d\n%s", code, out)
				}
				if len(setupTree(t, filepath.Join(f.root, "bin"))) != 0 || len(setupTree(t, f.bin)) != 0 {
					t.Fatal("refusal built or installed files")
				}
				requireNoGlobalSkill(t, f.home)
			})
		}
	})
	// Claim: scoped keyvault rebuild retains existing refusals for its build and installed-link destinations.
	t.Run("keyvault-rebuild-refusals", func(t *testing.T) {
		for _, target := range []string{"build", "installed-link"} {
			t.Run(target, func(t *testing.T) {
				f := newSetupFixture(t, cache)
				buildDir := filepath.Join(f.root, "bin")
				if err := os.Mkdir(buildDir, 0700); err != nil {
					t.Fatal(err)
				}
				// Each case has exactly one guarded target, so one guard cannot
				// stand in for the other: "build" has only the build binary,
				// "installed-link" only the installed target (the build guard
				// then decides to build and the link guard must refuse).
				if target == "build" {
					writeProvenanceFile(t, filepath.Join(buildDir, "mac-keyvault"), "trusted binary")
				} else {
					writeProvenanceFile(t, filepath.Join(f.bin, "mac-keyvault"), "installed trusted binary")
				}
				tools := t.TempDir()
				// A stub go records any invocation and fails, so a regressed
				// guard can never reach real package listing, tests or builds.
				goCalls := filepath.Join(tools, "go-calls")
				fakeTool(t, tools, "go", "echo \"$@\" >> '"+goCalls+"'; exit 77")
				f.env = append(f.env, "PATH="+tools+":"+os.Getenv("PATH"), "KEYVAULT_GUARD_LSOF="+fakeTool(t, tools, "lsof-denied", "echo denied >&2; exit 1"))
				beforeBuild, beforeLinks := setupTree(t, buildDir), setupTree(t, f.bin)
				out, code := f.run(t, "--only", "mac-keyvault", "--rebuild-keyvault", "--allow-unprovable")
				if code != 1 || !strings.Contains(out, "cannot tell whether a process uses it") || strings.Contains(out, "Testing Go packages") {
					t.Fatalf("guard bypassed: exit %d\n%s", code, out)
				}
				if calls, err := os.ReadFile(goCalls); err == nil {
					t.Fatalf("go ran before the guard refused: %q", calls)
				}
				if !reflect.DeepEqual(beforeBuild, setupTree(t, buildDir)) || !reflect.DeepEqual(beforeLinks, setupTree(t, f.bin)) {
					t.Fatal("guard refusal changed installed files")
				}
			})
		}
	})
	// Claim: an existing bin/mac-keyvault-kek is kept by a scoped run without
	// --rebuild-kek: no go build runs, its bytes and installed link are
	// unchanged. Its keys trust exactly that binary. A stub go answers list and
	// test (so no real keyvault test runs here) and records any build.
	t.Run("kek-kept", func(t *testing.T) {
		f := newSetupFixture(t, cache)
		buildDir := filepath.Join(f.root, "bin")
		if err := os.Mkdir(buildDir, 0700); err != nil {
			t.Fatal(err)
		}
		kek := filepath.Join(buildDir, "mac-keyvault-kek")
		writeProvenanceFile(t, kek, "trusted broker bytes")
		if err := os.Symlink(kek, filepath.Join(f.bin, "mac-keyvault-kek")); err != nil {
			t.Fatal(err)
		}
		tools := t.TempDir()
		goCalls := filepath.Join(tools, "go-calls")
		fakeTool(t, tools, "go", `[ "$1" = -C ] && shift 2
echo "$@" >> '`+goCalls+`'
case "$1" in
  list) echo github.com/relux-works/mac-infra/cmd/mac-keyvault-kek ;;
  test) exit 0 ;;
  *) exit 77 ;;
esac`)
		f.env = append(f.env, "PATH="+tools+":"+os.Getenv("PATH"))
		beforeBuild, beforeLinks := setupTree(t, buildDir), setupTree(t, f.bin)
		out, code := f.run(t, "--only", "mac-keyvault-kek", "--allow-unprovable")
		if code != 0 || !strings.Contains(out, "Keeping the existing bin/mac-keyvault-kek") || strings.Contains(out, "Building mac-keyvault-kek") {
			t.Fatalf("kek not kept: exit %d\n%s", code, out)
		}
		calls, _ := os.ReadFile(goCalls)
		if strings.Contains(string(calls), "build") {
			t.Fatalf("go build ran: %q", calls)
		}
		if !reflect.DeepEqual(beforeBuild, setupTree(t, buildDir)) || !reflect.DeepEqual(beforeLinks, setupTree(t, f.bin)) {
			t.Fatal("the kept broker or its link changed")
		}
		requireProvenanceBytes(t, kek, []byte("trusted broker bytes"))
	})
	// Claim: failures in either the selected command or an in-module dependency abort before staging or publication.
	t.Run("test-failure", func(t *testing.T) {
		for _, pkg := range []string{"cmd/mac-load-profile", "internal/loadprofile"} {
			t.Run(pkg, func(t *testing.T) {
				f := newSetupFixture(t, cache)
				packageName := "main"
				if strings.HasPrefix(pkg, "internal/") {
					packageName = "loadprofile"
				}
				writeProvenanceFile(t, filepath.Join(f.root, pkg, "setup_failure_test.go"), "package "+packageName+"\nimport \"testing\"\nfunc TestSetupRegressionWitness(t *testing.T) { t.Fatal(\"deliberate selected test failure\") }\n")
				out, code := f.run(t, "--only", "mac-load-profile", "--allow-unprovable")
				if code == 0 || !strings.Contains(out, "deliberate selected test failure") || strings.Contains(out, "Building ") {
					t.Fatalf("missing test-failure refusal: exit %d\n%s", code, out)
				}
				if _, err := os.Stat(filepath.Join(f.root, "bin")); !os.IsNotExist(err) {
					t.Fatalf("failure created build/staging directory: %v", err)
				}
				if len(setupTree(t, f.bin)) != 0 {
					t.Fatal("test failure installed links")
				}
				requireNoGlobalSkill(t, f.home)
			})
		}
	})
	// Claim: comma-separated and repeated names publish each selected binary once and leave unrelated failing tests unrun.
	t.Run("multiple", func(t *testing.T) {
		f := newSetupFixture(t, cache)
		writeProvenanceFile(t, filepath.Join(f.root, "cmd/mac-infra-core/setup_failure_test.go"), "package main\nimport \"testing\"\nfunc TestUnselectedFailure(t *testing.T) { t.Fatal(\"unselected test ran\") }\n")
		out, code := f.run(t, "--only", "mac-load-profile,mac-video-profile,mac-load-profile", "--allow-unprovable")
		if code != 0 {
			t.Fatalf("multiple selection: exit %d\n%s", code, out)
		}
		for _, dir := range []string{filepath.Join(f.root, "bin"), f.bin} {
			tree := setupTree(t, dir)
			if len(tree) != 2 || tree["mac-load-profile"] == "" || tree["mac-video-profile"] == "" {
				t.Fatalf("unexpected selected files in %s: %v", dir, mapKeys(tree))
			}
		}
		requireNoGlobalSkill(t, f.home)
	})
	// Claim: restoring the retired install block makes the same no-global-skill assertion fail (negative control).
	t.Run("negative-control", func(t *testing.T) {
		f := newSetupFixture(t, cache)
		path := filepath.Join(f.root, "scripts/setup.sh")
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		restored := `
SKILL_NAME="mac-infra"
SKILL_SOURCE="$PROJECT_ROOT/agents/skills/$SKILL_NAME"
SKILL_RUNTIME="$HOME/.agents/skills/$SKILL_NAME"
mkdir -p "$HOME/.agents/skills" "$HOME/.codex/skills" "$HOME/.claude/skills"
rm -rf "$SKILL_RUNTIME"
mkdir -p "$SKILL_RUNTIME"
cp -R "$SKILL_SOURCE/." "$SKILL_RUNTIME/"
find "$SKILL_RUNTIME" \( -name .git -o -name .gitignore -o -name .gitattributes -o -name .gitmodules \) -prune -exec rm -rf {} +
ln -sfn "$SKILL_RUNTIME" "$HOME/.codex/skills/$SKILL_NAME"
ln -sfn "$SKILL_RUNTIME" "$HOME/.claude/skills/$SKILL_NAME"
`
		if err := os.WriteFile(path, append(data, []byte(restored)...), 0700); err != nil {
			t.Fatal(err)
		}
		out, code := f.run(t, "--only", "mac-load-profile", "--allow-unprovable")
		if code != 0 {
			t.Fatalf("mutated setup did not reach skill installation: exit %d\n%s", code, out)
		}
		probe := exec.Command(os.Args[0], "-test.run=^TestSetupNoGlobalSkillAssertion$", "-test.v")
		probe.Env = append(f.env, "MAC_INFRA_SETUP_ASSERT_HOME="+f.home)
		result, err := probe.CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || !strings.Contains(string(result), "setup created global skill paths: [.agents .claude .codex]") {
			t.Fatalf("negative control did not fail the no-global-skill test: %v\n%s", err, result)
		}
		t.Logf("expected negative-control exit 1:\n%s", result)
	})
}

func mapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// Claim: full setup contains no global-skill write paths; static because executing its full test lane would run keyvault tests.
func TestSetupNoGlobalSkillsFullRun(t *testing.T) {
	data, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"$HOME/.agents", "$HOME/.claude", "$HOME/.codex", "SKILL_SOURCE", "SKILL_RUNTIME", "Installed skill:"} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("full setup still contains retired skill installation: %s", forbidden)
		}
	}
	if !strings.Contains(string(data), "else\n  go -C \"$PROJECT_ROOT\" test ./...\nfi") {
		t.Fatal("full test lane changed")
	}
}

// Claim: the shared no-global-skill assertion rejects a scratch HOME populated by the negative control.
func TestSetupNoGlobalSkillAssertion(t *testing.T) {
	if home := os.Getenv("MAC_INFRA_SETUP_ASSERT_HOME"); home != "" {
		requireNoGlobalSkill(t, home)
	}
}
