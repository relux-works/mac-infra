package policyjournal

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// inputOperations is a deliberately closed source-review tripwire, not OS
// enforcement. It checks production observation code, not test fixture I/O.
func inputOperations(src string) []string {
	f, e := parser.ParseFile(token.NewFileSet(), "input.go", src, 0)
	if e != nil {
		return []string{"parse"}
	}
	allowed := map[string]bool{}
	for _, s := range strings.Fields(`json.NewEncoder errors.Is errors.New os.Lstat os.ReadDir os.NewFile os.Getuid filepath.Join filepath.Dir filepath.Base filepath.IsAbs filepath.Clean sort.Strings time.Now time.Since unix.Kqueue unix.CloseOnExec unix.Close unix.Lstat unix.Open unix.Fstat unix.Kevent unix.NsecToTimespec unix.Flock regexp.MustCompile`) {
		allowed[s] = true
	}
	methods := map[string]bool{}
	for _, s := range strings.Fields(`IsDir IsRegular Type Name Perm Mode Size ModTime Sys UTC Format IsZero Encode Lstat ReadDir Emit Scan Close Err Wait Sync MatchString ReportMissing`) {
		methods[s] = true
	}
	packages := map[string]bool{}
	for _, s := range strings.Fields(`json errors os filepath sort time unix io fs syscall context regexp`) {
		packages[s] = true
	}
	var bad []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if s, ok := call.Fun.(*ast.SelectorExpr); ok {
			if x, ok := s.X.(*ast.Ident); ok && packages[x.Name] {
				name := x.Name + "." + s.Sel.Name
				if !allowed[name] {
					bad = append(bad, name)
				}
			} else if !methods[s.Sel.Name] {
				bad = append(bad, "method."+s.Sel.Name)
			}
		}
		return true
	})
	return bad
}

// Proves current metadata/notification code uses only the reviewed operation
// vocabulary, paired with known forbidden read operations and allowed controls.
// It does not prove OS confinement or inspect future dynamically replaced code.
func TestInputOperationVocabulary(t *testing.T) {
	for _, path := range []string{"journal.go", "darwin.go"} {
		s, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if bad := inputOperations(string(s)); len(bad) > 0 {
			t.Fatalf("%s forbidden operations %v", path, bad)
		}
	}
	for _, control := range []struct {
		code string
		want string
	}{
		{`package p; func f(){ os.Lstat(p); os.ReadDir(root); unix.Kevent(q,nil,nil,nil) }`, ""},
		{`package p; func f(){ os.ReadFile(p) }`, "os.ReadFile"},
		{`package p; func f(){ unix.Read(fd,buf) }`, "unix.Read"},
		{`package p; func f(){ file.Read(buf) }`, "method.Read"},
		{`package p; func f(){ io.Copy(w,r) }`, "io.Copy"},
		{`package p; func f(){ regexp.MatchReader(re, r) }`, "regexp.MatchReader"},
	} {
		bad := strings.Join(inputOperations(control.code), ",")
		if bad != control.want {
			t.Fatalf("guard control got %q want %q", bad, control.want)
		}
	}
}
