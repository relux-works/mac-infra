package toolsecret

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Claim keeper delta 2: classification uses the standard library, and the package imports no other mac-infra packages.
func TestClassificationImports(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), entry.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(path, "github.com/relux-works/mac-infra/") || strings.HasPrefix(path, "internal/") || (entry.Name() == "model.go" && strings.Contains(strings.Split(path, "/")[0], ".")) {
				t.Errorf("classification/package dependency violation in %s: %s", entry.Name(), path)
			}
		}
	}
}

// Claim: all production sources reachable from the metadata CLI are free of secret-data APIs and the probe import.
func TestNoDataAPIs(t *testing.T) {
	forbidden := []string{"SecKeychainFindGenericPassword", "SecKeychainFindInternetPassword", "SecKeychainItemCopyContent", "SecKeychainItemCopyAttributesAndData", "SecItemExport", "SecKeychainItemExport", "kSecReturnData", "kSecValueData", "internal/toolsecretprobe"}
	checked := 0
	for _, root := range []string{".", "../../cmd/mac-tool-secret"} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".go" && ext != ".m" && ext != ".h" && ext != ".c" {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			checked++
			for _, symbol := range forbidden {
				if strings.Contains(string(b), symbol) {
					t.Errorf("forbidden data capability %s in %s", symbol, path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 8 {
		t.Fatalf("source assertion only checked %d files", checked)
	}
	b, err := os.ReadFile("native_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"SecTrustedApplicationCopyRequirement", "dlsym", "kSecUseAuthenticationUIFail", "kSecReturnAttributes", "kSecReturnRef"} {
		if !strings.Contains(string(b), marker) {
			t.Errorf("missing metadata safeguard %s", marker)
		}
	}
}

// SecKeychainItemSetAccess is called exactly once in the shipped sources, in native_darwin.m, directly behind the !allowUI refusal (incident 2026-10-29 11:30Z).
func TestSetAccessOnlyInAttendedRegion(t *testing.T) {
	const call = "SecKeychainItemSetAccess("
	const guard = "if (!allowUI) s=errSecInteractionNotAllowed;"
	calls := 0
	for _, dir := range []string{".", "../toolsecretprobe", "../../cmd/mac-tool-secret", "../../cmd/mac-tool-secret-probe"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || strings.HasSuffix(name, "_test.go") || !(strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".m") || strings.HasSuffix(name, ".c") || strings.HasSuffix(name, ".h")) {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			n := strings.Count(string(src), call)
			calls += n
			if n > 0 && filepath.Join(dir, name) != "native_darwin.m" {
				t.Errorf("%s calls SecKeychainItemSetAccess outside the attended region", filepath.Join(dir, name))
			}
		}
	}
	if calls != 1 {
		t.Fatalf("SecKeychainItemSetAccess calls in shipped sources: %d, want exactly 1", calls)
	}
	native, err := os.ReadFile("native_darwin.m")
	if err != nil {
		t.Fatal(err)
	}
	// Pin the attended block's whole control flow, not the proximity of a guard
	// string (PR61 review r2): the refusal, the terminal check chained by
	// else-if, UI enabled only in the final else, exactly one SetAccess call,
	// and UI disabled again afterwards. Whitespace is normalized; any other
	// structural edit fails, which is intended for this block.
	attended := normalizeSource(`if (!allowUI) s=errSecInteractionNotAllowed;
        else if (!isatty(3) || !isatty(4)) s=errSecInteractionNotAllowed;
        else {
            s=SecKeychainSetUserInteractionAllowed(true);
            if (!s) { TS_TRACE("set-access"); s=SecKeychainItemSetAccess(item,access); TS_TRACE("set-access-returned"); }
            SecKeychainSetUserInteractionAllowed(false);
        }`)
	src := normalizeSource(string(native))
	if strings.Count(src, attended) != 1 {
		t.Fatal("native_darwin.m no longer contains the pinned attended block exactly once")
	}
	block := strings.Index(src, attended)
	if c := strings.Index(src, call); c < block || c >= block+len(attended) {
		t.Fatal("the SetAccess call is outside the pinned attended block")
	}
}

// normalizeSource collapses every run of whitespace to one space.
func normalizeSource(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
