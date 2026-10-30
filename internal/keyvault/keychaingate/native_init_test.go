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
			// Go builds no package in a directory whose name begins with a
			// dot (module import paths cannot name one), so native files
			// there are never compiled: .git, .temp and a checkout's local
			// tool state. A reviewed input could still read a header from
			// one; dotDirReference refuses that.
			if path != root && strings.HasPrefix(entry.Name(), ".") {
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
			if ref, err := dotDirReference(path); err != nil || ref != "" {
				return errors.Join(err, fmt.Errorf("native input %s names a dot-directory: %q", rel, ref))
			}
			inputs = append(inputs, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(inputs)
	return inputs, err
}

var (
	includeLine = regexp.MustCompile(`(?m)^\s*#\s*(?:include|include_next|import)\s*[<"]([^>"]+)[>"]`)
	cgoLine     = regexp.MustCompile(`(?m)^\s*#cgo\b[^:\n]*:(.*)$`)
)

// dotDirReference returns the first include path or #cgo flag in a native
// input that names a dot-directory, which the walk does not inspect.
func dotDirReference(path string) (string, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var refs []string
	for _, m := range includeLine.FindAllSubmatch(source, -1) {
		refs = append(refs, string(m[1]))
	}
	for _, m := range cgoLine.FindAllSubmatch(source, -1) {
		refs = append(refs, strings.Fields(string(m[1]))...)
	}
	for _, ref := range refs {
		for _, element := range strings.Split(ref, "/") {
			if strings.HasPrefix(element, ".") && element != "." && element != ".." {
				return ref, nil
			}
		}
	}
	return "", nil
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

// The entire module tree outside dot-directories, including tag-excluded files
// and subdirectory headers, must match the reviewed native inventory, and no
// native input may reach into a dot-directory. This does not enforce
// confinement.
func TestNativeInputTripwire(t *testing.T) {
	if err := checkNativeInputs(moduleRoot(t), reviewedNativeInputs); err != nil {
		t.Fatal(err)
	}
}

// Default-build non-standard dependencies outside the module must not add native
// inputs. Other build graphs need their own review; the wrapper enforces startup.
func TestDependencyNativeInputTripwire(t *testing.T) {
	root := moduleRoot(t)
	cmd := exec.Command("go", "list", "-deps", "-test", "-json", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.Bytes())
	}
	moduleSeen := false
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Standard {
			continue
		}
		if p.Dir == "" {
			t.Fatalf("go list returned no directory for %q", p.ImportPath)
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			t.Fatal(err)
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			moduleSeen = true
			continue
		}
		inputs := dependencyNativeInputs(p)
		if len(inputs) != 0 {
			t.Errorf("unreviewed external native dependency %s: %v", p.ImportPath, inputs)
		}
	}
	if !moduleSeen {
		t.Fatal("go list returned no module packages; dependency inventory is incomplete")
	}
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

// A checkout's local tool state in dot-directories (a board's C probe, a
// legacy install's symlinks) does not trip the scan, which is what a main
// checkout holds. Everything else still does: a symlink or an unlisted native
// file outside them, and a dot-named file, which is not a directory. A native
// input that includes a header from a dot-directory, or points a #cgo flag at
// one, is refused even when reviewed; ordinary includes pass.
func TestNativeInputTripwireDotDirectories(t *testing.T) {
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
	if err := os.MkdirAll(filepath.Join(root, ".agents/skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, ".agents/.skills/pdf"), filepath.Join(root, ".agents/skills/pdf")); err != nil {
		t.Fatal(err)
	}
	write("pkg/ok.c", "#include \"ok.h\"\n#include <Security/Security.h>\n#include \"../include/shared.h\"\n")
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

	for _, name := range []string{"pkg/unlisted.h", "pkg/.hidden.c"} {
		write(name, "int x;")
		if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: %v", name, err)
		}
		remove(name)
	}

	for _, c := range []struct{ name, source, ref string }{
		{"pkg/inc.c", "#include \"../.agents/evil.h\"\n", "../.agents/evil.h"},
		{"pkg/next.h", "#  include_next <.inc/evil.h>\n", ".inc/evil.h"},
		{"pkg/cgo.go", "package pkg\n\n/*\n#cgo CFLAGS: -Wno-deprecated-declarations -I${SRCDIR}/.inc\n*/\nimport \"C\"\n", "-I${SRCDIR}/.inc"},
	} {
		write(c.name, c.source)
		err := checkNativeInputs(root, []string{"pkg/ok.c", c.name})
		if err == nil || !strings.Contains(err.Error(), "dot-directory") || !strings.Contains(err.Error(), c.ref) {
			t.Fatalf("%s: %v", c.name, err)
		}
		remove(c.name)
	}
	if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err != nil {
		t.Fatalf("control after removals: %v", err)
	}

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
