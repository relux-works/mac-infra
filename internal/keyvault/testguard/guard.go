// Package testguard is test-only infrastructure for suites that can reach the
// login Keychain or Secure Enclave. Production code must not import it.
package testguard

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const SkipEnv = "MAC_KEYVAULT_SKIP_KEYCHAIN"

// Enabled reports whether real Security.framework and helper tests are disabled.
func Enabled() bool { return os.Getenv(SkipEnv) != "" }

// Require must precede all real-backend setup, including helper compilation.
func Require(t testing.TB) {
	t.Helper()
	if Enabled() {
		t.Skip(SkipEnv + " set: real Keychain and Secure Enclave tests disabled")
	}
}

// Main checks every test source before any test executes, even with -run set.
func Main(m *testing.M) int {
	root, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			fmt.Fprintln(os.Stderr, "testguard: repository root not found")
			return 1
		}
		root = parent
	}
	if err := Check(root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return m.Run()
}

// Only these small entry points may reference real backends. Check also
// verifies their first statement (after t.Helper) is Require(t).
var entryPoints = map[string]map[string]bool{
	"internal/keyvault/security_darwin_test.go":       {"newGuardedSecurityStore": true},
	"internal/keyvault/enclave_helper_darwin_test.go": {"realEnclave": true},
	"cmd/mac-keyvault/real_backend_test.go":           {"newTestSecurityStore": true},
	"internal/keyvault/signerclient/client_test.go":   {"buildBinary": true, "runCLI": true},
}

// Check rejects real-backend references outside gated entry points, including
// function aliases, zero-value stores and C bridge access. All build tags are
// scanned. This is an accidental-regression guard, not a Go security sandbox.
func Check(root string) error {
	for _, dir := range []string{"internal/keyvault", "cmd/mac-keyvault"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return CheckSource(filepath.ToSlash(rel), data)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// CheckSource is exposed so negative controls can use inert source fixtures.
func CheckSource(path string, source []byte) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, source, 0)
	if err != nil {
		return err
	}
	for _, imp := range file.Imports {
		if imp.Path.Value == `"C"` {
			return fmt.Errorf("%s: test imports C bridge", path)
		}
	}
	for _, decl := range file.Decls {
		fn, isFunc := decl.(*ast.FuncDecl)
		allowed := isFunc && entryPoints[path][fn.Name.Name]
		if allowed && !startsWithGate(fn) {
			return fmt.Errorf("%s: %s must start with testguard.Require(t)", path, fn.Name.Name)
		}
		if allowed {
			continue
		}
		// Reading diagnostic methods through a type assertion does not construct
		// a store; its receiver still comes from the gated constructor.
		assertions := map[*ast.Ident]bool{}
		ast.Inspect(decl, func(n ast.Node) bool {
			if a, ok := n.(*ast.TypeAssertExpr); ok {
				if star, ok := a.Type.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok {
						assertions[id] = true
					}
				}
			}
			return true
		})
		ast.Inspect(decl, func(n ast.Node) bool {
			if err != nil {
				return false
			}
			id, ok := n.(*ast.Ident)
			if !ok || assertions[id] {
				return true
			}
			switch id.Name {
			case "NewSecurityStore", "SecurityStore", "ExecEnclaveHelper", "DefaultEnclaveStore", "C":
				err = fmt.Errorf("%s: real-backend reference %s outside a gated helper", fset.Position(id.Pos()), id.Name)
			}
			return true
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func startsWithGate(fn *ast.FuncDecl) bool {
	if fn.Body == nil {
		return false
	}
	for _, stmt := range fn.Body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		owner, ok := sel.X.(*ast.Ident)
		if !ok {
			return false
		}
		if owner.Name == "t" && sel.Sel.Name == "Helper" && len(call.Args) == 0 {
			continue
		}
		if owner.Name != "testguard" || sel.Sel.Name != "Require" || len(call.Args) != 1 {
			return false
		}
		arg, ok := call.Args[0].(*ast.Ident)
		return ok && arg.Name == "t"
	}
	return false
}
