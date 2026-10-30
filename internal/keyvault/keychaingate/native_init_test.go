package keychaingate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// This is a review tripwire, not enforcement: a test cannot stop native code
// that runs before Go init. New native inputs require an explicit reviewed
// allowlist change. Use scripts/keyvault-test-confined.sh for that boundary.
// Inventory: git ls-files for native suffixes and Go imports of "C".
var reviewedNativeInputs = []string{
	"internal/audiodevice/device_darwin.go",
	"internal/chromectl/ax_darwin.go",
	"internal/chromectl/ax_darwin.m",
	"internal/keyvault/keychaingate/canary_darwin.go",
	"internal/keyvault/keychaingate/gate_darwin.go",
	"internal/keyvault/kek/inspect_darwin.c",
	"internal/keyvault/kek/inspect_darwin.go",
	"internal/keyvault/kek/inspect_darwin.h",
	"internal/keyvault/security_darwin.c",
	"internal/keyvault/security_darwin.go",
	"internal/keyvault/security_darwin.h",
	"internal/maccore/trust_acl_darwin.go",
	"internal/maccore/vpn_core_acl_darwin.go",
	"internal/toolsecret/native_darwin.go",
	"internal/toolsecret/native_darwin.m",
	"internal/toolsecret/testdata/fixture.m",
	"internal/toolsecretprobe/native_darwin.go",
}

func nativeSuffix(name string) bool {
	switch filepath.Ext(name) {
	case ".c", ".h", ".m", ".mm", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".inc", ".s", ".S", ".sx", ".syso":
		return true
	}
	return false
}

func importsC(path string) (bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return false, err
		}
		if name == "C" {
			return true, nil
		}
	}
	return false, nil
}

func nativeInputs(root string) ([]string, error) {
	var inputs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if inCheckoutState(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		// Do not silently omit source behind a symlink or another special file.
		if !entry.Type().IsRegular() {
			return fmt.Errorf("uninspected input: %s", path)
		}
		native := nativeSuffix(path)
		if filepath.Ext(path) == ".go" {
			native, err = importsC(path)
			if err != nil {
				return err
			}
		}
		if native {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			ref, err := checkoutStateReference(path)
			if err != nil {
				return fmt.Errorf("native input %s: %w", rel, err)
			}
			if ref != "" {
				return fmt.Errorf("native input %s names checkout state: %q", rel, ref)
			}
			inputs = append(inputs, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(inputs)
	return inputs, err
}

// checkoutState lists the root-level directories that hold a checkout's own
// state rather than source: version control, scratch and local tool state.
// The repository's .gitignore ignores each of them (TestCheckoutStateIsIgnored).
// Go can still build a package inside one when an import or an explicit
// argument names it, so the walk skips them only together with two checks: no
// package the build graph selects lies inside one (checkDependencyInputs), and
// no native input names one (checkoutStateReference). .git and .temp are
// skipped at any depth, as before.
var checkoutState = []string{".agents", ".claude", ".codex", ".git", ".local", ".planning", ".task-board", ".temp"}

// inCheckoutState reports whether a module-relative path lies in checkout
// state.
func inCheckoutState(rel string) bool {
	elements := strings.Split(filepath.ToSlash(rel), "/")
	if slices.Contains(checkoutState, elements[0]) {
		return true
	}
	return slices.Contains(elements, ".git") || slices.Contains(elements, ".temp")
}

// stateName matches a checkout-state directory name used as a whole name, so
// ".github" does not match ".git".
var stateName = func() *regexp.Regexp {
	names := make([]string, len(checkoutState))
	for i, name := range checkoutState {
		names[i] = regexp.QuoteMeta(name)
	}
	return regexp.MustCompile(`(?:` + strings.Join(names, "|") + `)(?:[^A-Za-z0-9_-]|$)`)
}()

// checkoutStateReference returns the first mention of a checkout-state
// directory in a native input, after joining backslash-continued lines. It
// matches text rather than parsing includes and flags, so a comment, a
// quoted or attached flag operand and a line-comment cgo preamble all count.
// It cannot see a name assembled by macro token pasting, nor include paths
// from CGO_CFLAGS or pkg-config; the confinement wrapper, not this review
// tripwire, bounds native startup.
func checkoutStateReference(path string) (string, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	source = bytes.ReplaceAll(source, []byte("\\\r\n"), nil)
	source = bytes.ReplaceAll(source, []byte("\\\n"), nil)
	return string(stateName.Find(source)), nil
}

func checkNativeInputs(root string, allowlist []string) error {
	inputs, err := nativeInputs(root)
	if err != nil {
		return err
	}
	for _, input := range inputs {
		if !slices.Contains(allowlist, input) {
			return fmt.Errorf("unreviewed native input: %s", input)
		}
	}
	for _, reviewed := range allowlist {
		if !slices.Contains(inputs, reviewed) {
			return fmt.Errorf("stale native allowlist entry: %s", reviewed)
		}
	}
	return nil
}

type listedPackage struct {
	ImportPath, Dir                            string
	Standard                                   bool
	CgoFiles, CFiles, CXXFiles, MFiles, HFiles []string
	SFiles, SysoFiles                          []string
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func dependencyNativeInputs(p listedPackage) []string {
	var inputs []string
	for _, files := range [][]string{p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.SysoFiles} {
		inputs = append(inputs, files...)
	}
	for _, name := range p.SFiles {
		// Go assembly (.s) in non-cgo packages is allowed: the Go assembler
		// emits Go functions, not native linker constructor sections. Uppercase
		// .S and .sx go through a native toolchain and are not exempt.
		if nativeSuffix(name) && (filepath.Ext(name) != ".s" || len(p.CgoFiles) != 0) {
			inputs = append(inputs, name)
		}
	}
	return inputs
}

// The module tree outside checkout state, including tag-excluded files and
// subdirectory headers, must match the reviewed native inventory, and no native
// input may name checkout state. This does not enforce confinement.
func TestNativeInputTripwire(t *testing.T) {
	if err := checkNativeInputs(moduleRoot(t), reviewedNativeInputs); err != nil {
		t.Fatal(err)
	}
}

// Default-build non-standard dependencies outside the module must not add native
// inputs, and no package of the module's build graph may lie in checkout state,
// which the inventory walk skips. Other build graphs need their own review; the
// wrapper enforces startup.
func TestDependencyNativeInputTripwire(t *testing.T) {
	if err := checkDependencyInputs(moduleRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func checkDependencyInputs(root string) error {
	cmd := exec.Command("go", "list", "-deps", "-test", "-json", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list: %v\n%s", err, stderr.Bytes())
	}
	var errs []error
	moduleSeen := false
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if p.Standard {
			continue
		}
		if p.Dir == "" {
			return fmt.Errorf("go list returned no directory for %q", p.ImportPath)
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return err
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			moduleSeen = true
			if inCheckoutState(rel) {
				errs = append(errs, fmt.Errorf("build graph selects %s from checkout state %s", p.ImportPath, filepath.ToSlash(rel)))
			}
			continue
		}
		if inputs := dependencyNativeInputs(p); len(inputs) != 0 {
			errs = append(errs, fmt.Errorf("unreviewed external native dependency %s: %v", p.ImportPath, inputs))
		}
	}
	if !moduleSeen {
		errs = append(errs, errors.New("go list returned no module packages; dependency inventory is incomplete"))
	}
	return errors.Join(errs...)
}

// Scan-only controls plant native inputs without compiling or executing them.
// Detection proves review admission, not prevention of native startup.
func TestNativeInputTripwireControls(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ordinary.go", "package ordinary\n")
	write(".temp/ignored.c", "ignored scratch")
	write(".git/ignored.h", "ignored metadata")
	if err := checkNativeInputs(root, nil); err != nil {
		t.Fatalf("pure Go control: %v", err)
	}
	for _, name := range []string{"excluded.c", "include/startup.h", "excluded.cc", "excluded.go", "excluded.syso", "other.m", "other.mm", "other.cpp", "other.cxx", "other.hh", "other.hpp", "other.inc", "other.s", "other.S", "other.sx"} {
		t.Run(name, func(t *testing.T) {
			source := "//go:build never_enabled_tripwire_fixture\n\n"
			if filepath.Ext(name) == ".go" {
				source += "package fixture\nimport (\n_ \"fmt\"\n`C`\n)\n"
			}
			write(name, source)
			if err := checkNativeInputs(root, nil); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("planted input was not rejected: %v", err)
			}
			if err := checkNativeInputs(root, []string{name}); err != nil {
				t.Fatalf("explicit review control: %v", err)
			}
			if err := os.Remove(filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := checkNativeInputs(root, []string{"missing.c"}); err == nil {
		t.Fatal("stale allowlist was accepted")
	}
}

// A checkout's local tool state in the named checkout-state directories (a
// board's C probe, a legacy install's symlinks) does not trip the scan, which
// is what a main checkout holds. Everything else still does: a symlink or an
// unlisted native file elsewhere, a dot-named file, and native files in any
// other dot-directory, nested or at the root, including testdata. A dot-named
// module root is scanned. An unreadable input reports its read error only.
func TestNativeInputTripwireCheckoutState(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(name string) {
		t.Helper()
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	write("ordinary.go", "package ordinary\n")
	write(".task-board/.resources/T/probe.c", "int probe;")
	write(".agents/.skills/pdf/SKILL.md", "skill")
	write(".agents/.configs/settings.json", "{}")
	for _, l := range [][2]string{{".agents/.skills/pdf", ".agents/skills/pdf"}, {".agents/.configs/settings.json", ".claude/settings.json"}} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l[1])), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, l[0]), filepath.Join(root, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	write("pkg/ok.c", "// see .github/workflows\n#include \"ok.h\"\n#include <Security/Security.h>\n#include \"../include/shared.h\"\n")
	if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err != nil {
		t.Fatalf("local tool state control: %v", err)
	}

	if err := os.Symlink(filepath.Join(root, "ordinary.go"), filepath.Join(root, "pkg/linked.go")); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err == nil || !strings.Contains(err.Error(), "uninspected input") {
		t.Fatalf("symlink in a package directory: %v", err)
	}
	remove("pkg/linked.go")

	for _, name := range []string{"pkg/unlisted.h", "pkg/.hidden.c", ".native/native.c", "pkg/.agents/nested.c", "testdata/.fixtures/native.c"} {
		write(name, "int x;")
		if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: %v", name, err)
		}
		remove(name)
	}

	write("pkg/unreadable.c", "int x;")
	if err := os.Chmod(filepath.Join(root, "pkg/unreadable.c"), 0); err != nil {
		t.Fatal(err)
	}
	err := checkNativeInputs(root, []string{"pkg/ok.c", "pkg/unreadable.c"})
	if !errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "checkout state") {
		t.Fatalf("unreadable input: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "pkg/unreadable.c"), 0o600); err != nil {
		t.Fatal(err)
	}
	remove("pkg/unreadable.c")

	dotRoot := filepath.Join(t.TempDir(), ".checkout")
	if err := os.MkdirAll(dotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dotRoot, "unlisted.c"), []byte("int x;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(dotRoot, nil); err == nil || !strings.Contains(err.Error(), "unlisted.c") {
		t.Fatalf("a dot-named module root was skipped: %v", err)
	}
}

// A native input that names checkout state is refused even when reviewed, in
// the forms PR82 review r1 found missed: line-comment cgo preambles, a
// backslash-continued include, attached and quoted flag operands, and
// ${SRCDIR} paths. A name used as a longer word (.github, .templates) and
// ordinary includes pass (controls). Limit: names assembled by macro token
// pasting, CGO_CFLAGS and pkg-config are not visible to a text scan.
func TestNativeInputTripwireStateReferences(t *testing.T) {
	refused := []struct{ name, source, ref string }{
		{"pkg/inc.c", "#include \"../.agents/evil.h\"\n", ".agents/"},
		{"pkg/next.h", "#  include_next <.task-board/evil.h>\n", ".task-board/"},
		{"pkg/line.go", "package pkg\n\n// #include \".claude/x.h\"\nimport \"C\"\n", ".claude/"},
		{"pkg/cont.c", "#include \".co\\\ndex/x.h\"\n", ".codex/"},
		{"pkg/joined.go", "package pkg\n\n// #cgo CFLAGS: -I.temp\nimport \"C\"\n", ".temp\n"},
		{"pkg/quoted.go", "package pkg\n\n/*\n#cgo CFLAGS: -I \".local\"\n*/\nimport \"C\"\n", ".local\""},
		{"pkg/srcdir.go", "package pkg\n\n/*\n#cgo CFLAGS: -iquote${SRCDIR}/.planning\n*/\nimport \"C\"\n", ".planning\n"},
		{"pkg/git.S", "#include \"../../.git/x.h\"\n", ".git/"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, c.name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(c.source), 0o600); err != nil {
				t.Fatal(err)
			}
			err := checkNativeInputs(root, []string{c.name})
			if err == nil || !strings.Contains(err.Error(), "names checkout state") || !strings.Contains(err.Error(), strconv.Quote(c.ref)) {
				t.Fatalf("not refused: %v", err)
			}
		})
	}
	root := t.TempDir()
	ok := "// see .github and .templates/x\n#include \"ok.h\"\n#include <Security/Security.h>\n#include \"../include/shared.h\"\n"
	if err := os.WriteFile(filepath.Join(root, "ok.c"), []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(root, []string{"ok.c"}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// A package of the module's build graph inside checkout state is refused, as
// PR82 review r1 showed Go builds an imported one; without that import the
// same module passes (control). Limit: a package built only by an explicit
// command-line argument is outside the build graph this checks.
func TestDependencyGraphCheckoutState(t *testing.T) {
	module := func(t *testing.T, main string) string {
		t.Helper()
		root := t.TempDir()
		files := map[string]string{
			"go.mod":         "module example.com/fixture\n\ngo 1.25\n",
			"main.go":        main,
			".agents/x/x.go": "package x\n\nconst X = 1\n",
			"lib/lib.go":     "package lib\n\nconst Y = 2\n",
		}
		for name, source := range files {
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	hidden := module(t, "package main\n\nimport (\n\t_ \"example.com/fixture/.agents/x\"\n\t_ \"example.com/fixture/lib\"\n)\n\nfunc main() {}\n")
	if err := checkDependencyInputs(hidden); err == nil || !strings.Contains(err.Error(), "from checkout state .agents/x") {
		t.Fatalf("hidden package not refused: %v", err)
	}
	plain := module(t, "package main\n\nimport _ \"example.com/fixture/lib\"\n\nfunc main() {}\n")
	if err := checkDependencyInputs(plain); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Every checkout-state directory except .git is ignored by the repository's
// .gitignore, so the list names only local state, never source; removing an
// ignore rule fails here until the list follows.
func TestCheckoutStateIsIgnored(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(moduleRoot(t), ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	rules := strings.Split(string(raw), "\n")
	for _, name := range checkoutState {
		if name == ".git" {
			continue
		}
		if !slices.Contains(rules, "/"+name+"/") && !slices.Contains(rules, name+"/") {
			t.Errorf("%s is not an ignored directory in .gitignore", name)
		}
	}
}

// External native fields are refused; pure Go assembly remains allowed.
func TestDependencyNativeInputControls(t *testing.T) {
	for _, p := range []listedPackage{
		{CgoFiles: []string{"native.go"}}, {CFiles: []string{"native.c"}},
		{CXXFiles: []string{"native.cc"}}, {MFiles: []string{"native.m"}},
		{HFiles: []string{"native.h"}}, {SFiles: []string{"native.S"}},
		{SFiles: []string{"native.sx"}}, {SysoFiles: []string{"native.syso"}},
	} {
		if inputs := dependencyNativeInputs(p); len(inputs) == 0 {
			t.Errorf("native dependency accepted: %+v", p)
		}
	}
	if inputs := dependencyNativeInputs(listedPackage{SFiles: []string{"go_asm.s"}}); len(inputs) != 0 {
		t.Fatalf("Go assembly control rejected: %v", inputs)
	}
}
