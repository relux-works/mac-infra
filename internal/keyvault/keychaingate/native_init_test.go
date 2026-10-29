package keychaingate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The sandbox starts at Go package initialization. Native code that runs
// earlier (a C/C++ constructor, an init_priority object, a mod_init_func
// section entry or an Objective-C +load method) is outside it and could reach
// the Keychain unconfined. No package linked into any test binary of this
// module may contain such an entry point; precompiled .syso objects cannot be
// inspected and are refused. This is a source check, so it only covers native
// code that a build in this module can see.
var nativePreMainEntry = regexp.MustCompile(`__attribute__\s*\(\(\s*(constructor|init_priority)\b|mod_init_func\b|(?m)^\s*\+\s*\(\s*void\s*\)\s*load\b`)

// cgoImport matches a Go file that uses cgo, whose preamble is native code.
var cgoImport = regexp.MustCompile(`(?m)^\s*import\s+(\(\s*)?"C"`)

type listedPackage struct {
	ImportPath, Dir                             string
	Standard                                    bool
	GoFiles, CgoFiles, CFiles, CXXFiles, MFiles []string
	HFiles, SFiles, SysoFiles, IgnoredGoFiles   []string
	IgnoredOtherFiles                           []string
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

// Every non-standard package linked into any test binary of the module, including files excluded by build tags, has no native pre-main entry point.
func TestNoNativePreMainEntryPoints(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "-test", "-json", "./...")
	cmd.Dir = moduleRoot(t)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.Bytes())
	}
	seen := map[string]bool{}
	var offenders []string
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Standard || seen[p.Dir] {
			continue
		}
		seen[p.Dir] = true
		for _, name := range p.SysoFiles {
			offenders = append(offenders, filepath.Join(p.Dir, name)+" (precompiled object)")
		}
		var files []string
		for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.IgnoredGoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.SFiles, p.IgnoredOtherFiles} {
			files = append(files, list...)
		}
		for _, name := range files {
			path := filepath.Join(p.Dir, name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(name, ".go") && !cgoImport.Match(data) {
				continue
			}
			if nativePreMainEntry.Match(data) {
				offenders = append(offenders, path)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("go list returned no module packages; the check inspected nothing")
	}
	if len(offenders) != 0 {
		t.Fatalf("native code that runs before the Keychain gate:\n%s", strings.Join(offenders, "\n"))
	}
}

// The matcher rejects each native pre-main form, including the r2 reviewer's posix_spawn probe, and accepts ordinary cgo.
func TestNativePreMainMatcher(t *testing.T) {
	for _, c := range []struct {
		name, source string
		want         bool
	}{
		{"r2 reviewer probe", "/*\n__attribute__((constructor)) static void reviewer_native_init(void) {\n  posix_spawn(&pid, argv[0], &actions, NULL, argv, environ);\n}\n*/\nimport \"C\"\n", true},
		{"spaced constructor with priority", "__attribute__ ((constructor(101))) static void early(void) {}\n", true},
		{"C++ init_priority", "Early early __attribute__((init_priority(101)));\n", true},
		{"mod_init_func section", "__attribute__((used, section(\"__DATA,__mod_init_func\"))) static void (*p)(void) = early;\n", true},
		{"Objective-C +load", "@implementation Early\n+ (void)load { }\n@end\n", true},
		{"ordinary cgo backend", "/*\n#include <Security/Security.h>\nstatic int list(void) { return 0; }\n*/\nimport \"C\"\n", false},
		{"ordinary Objective-C method", "@implementation Early\n- (void)loadView { }\n@end\n", false},
	} {
		if got := nativePreMainEntry.MatchString(c.source); got != c.want {
			t.Errorf("%s: matched=%v, want %v", c.name, got, c.want)
		}
	}
}
