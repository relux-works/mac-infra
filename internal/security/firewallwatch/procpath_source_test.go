package firewallwatch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// The actual cgo preamble applies offline validation before its sole signing
// metadata call, with all three offline/limited-hashing flags. This is a
// source-order regression check, not network-traffic or cancellation evidence.
func TestStaticInspectionOfflineOrder(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "procpath_darwin.go", nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var preamble string
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.IMPORT || g.Doc == nil {
			continue
		}
		for _, spec := range g.Specs {
			i := spec.(*ast.ImportSpec)
			name, _ := strconv.Unquote(i.Path.Value)
			if name == "C" {
				preamble = g.Doc.List[0].Text
			}
		}
	}
	// Remove line comments so quoted examples cannot satisfy call ordering.
	var code strings.Builder
	for _, line := range strings.Split(preamble, "\n") {
		code.WriteString(strings.SplitN(line, "//", 2)[0])
		code.WriteByte('\n')
	}
	source := strings.Join(strings.Fields(code.String()), " ")
	if !strings.Contains(source, "fwCheckFlags = kSecCSDoNotValidateExecutable | kSecCSDoNotValidateResources | kSecCSNoNetworkAccess;") {
		t.Fatal("signature checks lost their offline flags")
	}
	_, body, ok := strings.Cut(source, "static int fwCodeFacts(")
	if !ok {
		t.Fatal("missing production inspector")
	}
	check := strings.Index(body, "SecStaticCodeCheckValidity(code, fwCheckFlags, NULL)")
	metadata := strings.Index(body, "SecCodeCopySigningInformation(")
	if check < 0 || metadata < check || strings.Count(body, "SecCodeCopySigningInformation(") != 1 {
		t.Fatal("signing metadata can precede offline validation")
	}
}
