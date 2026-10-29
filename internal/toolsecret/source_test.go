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
