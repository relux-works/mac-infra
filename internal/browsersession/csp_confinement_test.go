package browsersession

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/testhang"
)

const reviewEscape = `0); })(), (++globalThis.__runs), (() => { const location={origin:"https://example.com"}; const __macGuard="works.relux.mac-infra/browser-session-guard/v1"; const __macValue=(42`

func requireJSC(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(javaScriptCorePath); errors.Is(err, os.ErrNotExist) {
		t.Skip("JavaScriptCore jsc is missing; confinement validation did not run")
	} else if err != nil {
		t.Fatal(err)
	}
}

// Claim: neither syntax checking nor origin drift runs caller code, including balanced escapes and hoisted declarations.
func TestJavaScriptCoreCSPConfinementOriginDrift(t *testing.T) {
	requireJSC(t)
	for name, source := range map[string]string{
		"review-exact":      reviewEscape,
		"close-inner":       `0); })(); ++globalThis.__runs; (() => { return (42`,
		"close-outer":       `0); })(); })(), (++globalThis.__runs), (() => { const location={origin:"https://example.com"}; const __macGuard="works.relux.mac-infra/browser-session-guard/v1"; const __macValue=(() => { return (42`,
		"top-level-return":  `return (++globalThis.__runs)`,
		"function-hoisting": `0); function location(){} (0`,
		"var-hoisting":      `0); var location = {origin:"https://example.com"}; (0`,
		"template":          "`unterminated ${++globalThis.__runs}",
		"comment":           `0 /* unterminated`,
		"html-comment":      "0); })(); ++globalThis.__runs; <!--",
		"line-comment":      `++globalThis.__runs // no newline`,
	} {
		t.Run(name, func(t *testing.T) {
			calls, runs := 0, 0
			result, err := ExecuteJavaScript(source, "https://example.com", func(wrapped string) (string, error) {
				calls++
				stub := pageStub
				if calls > 1 {
					stub = strings.ReplaceAll(stub, "https://example.com", "https://wrong.example")
				}
				out, engineErr := runJSCOutput(t, stub+blockedEvalStub+"\nprint(("+wrapped+"));print(globalThis.__runs);")
				if engineErr != nil {
					t.Fatalf("unexpected engine failure: %v: %s", engineErr, out)
				}
				lines := strings.Split(out, "\n")
				if len(lines) != 2 || lines[1] != "0" {
					runs++
					t.Errorf("caller side effect after origin drift: %s", out)
				}
				if calls == 1 {
					if _, err := ParseJavaScriptResult(lines[0], "https://example.com"); !errors.Is(err, ErrEvalBlocked) {
						t.Fatalf("first dispatch did not prove eval-blocked: %v", err)
					}
				}
				return lines[0], nil
			})
			if runs != 0 || calls > 2 || (!errors.Is(err, ErrCSPExpression) && !errors.Is(err, ErrOriginMismatch)) || result.Value != "" {
				t.Fatalf("result=%+v err=%v calls=%d runs=%d", result, err, calls, runs)
			}
		})
	}
}

// Claim: ordinary expressions retain values and run exactly once after the CSP probe; checking never executes them locally.
func TestJavaScriptCoreCSPConfinementPositive(t *testing.T) {
	requireJSC(t)
	for name, tc := range map[string]struct{ source, value string }{
		"title":          {`document.title`, "Example"},
		"object":         {`({answer:42})`, `{"answer":42}`},
		"iife":           {`(() => { const x=40; return x+2; })()`, "42"},
		"optional-chain": {`document?.title`, "Example"},
		"template":       {"`hello ${document.title}`", "hello Example"},
		"line-comment":   {`42 // no newline`, "42"},
		"html-comment":   {"42 <!-- ignored\n", "42"},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			source := "(++globalThis.__runs,\n" + tc.source + "\n)"
			if name == "line-comment" {
				source = "(++globalThis.__runs,42) // no newline"
			}
			result, err := ExecuteJavaScript(source, "https://example.com", func(wrapped string) (string, error) {
				calls++
				out := runJSC(t, pageStub+blockedEvalStub+`document.title="Example";`+"\nprint("+wrapped+");print(globalThis.__runs);")
				lines := strings.Split(out, "\n")
				wantRuns := fmt.Sprint(calls - 1)
				if len(lines) != 2 || lines[1] != wantRuns {
					t.Fatalf("calls=%d output=%s", calls, out)
				}
				return lines[0], nil
			})
			if err != nil || result.Value != tc.value || calls != 2 {
				t.Fatalf("result=%+v err=%v calls=%d", result, err, calls)
			}
		})
	}
}

// Claim: statements and hoisting admitted inside the inner body cannot shadow the outer guard or execute before it.
func TestJavaScriptCoreCSPInnerStatements(t *testing.T) {
	requireJSC(t)
	for _, source := range []string{
		`0); sideEffect(); (0`,
		`++globalThis.__runs, 0); function location(){} (0`,
		`++globalThis.__runs, 0); var location={origin:"https://wrong.example"}; (0`,
	} {
		t.Run(source, func(t *testing.T) {
			wrapped, err := WrapJavaScriptExpression(source, "https://example.com")
			if err != nil {
				t.Fatal(err)
			}
			for _, drift := range []bool{false, true} {
				stub := pageStub
				if drift {
					stub = strings.ReplaceAll(stub, "https://example.com", "https://wrong.example")
				}
				out := runJSC(t, stub+`function sideEffect(){++globalThis.__runs;}`+"\nprint("+wrapped+");print(globalThis.__runs);")
				lines := strings.Split(out, "\n")
				wantRuns := "0"
				if !drift && strings.Contains(source, "++globalThis.__runs") {
					wantRuns = "1"
				}
				if len(lines) != 2 || lines[1] != wantRuns {
					t.Fatalf("drift=%v output=%s", drift, out)
				}
				result, err := ParseJavaScriptResult(lines[0], "https://example.com")
				if drift {
					if !errors.Is(err, ErrOriginMismatch) {
						t.Fatal(err)
					}
				} else if err != nil || result.Value != "0" {
					t.Fatalf("result=%+v err=%v", result, err)
				}
			}
		})
	}
}

// Claim: JSC script validity alone is insufficient; the compile-only body check rejects the reviewer's balanced escape.
func TestJavaScriptCoreCSPFrameNeedsBodyCheck(t *testing.T) {
	requireJSC(t)
	path := filepath.Join(t.TempDir(), "frame.js")
	if err := os.WriteFile(path, []byte(expressionFrame(reviewEscape)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := runJSC(t, fmt.Sprintf("checkSyntax(%q); print('valid-script');", path)); got != "valid-script" {
		t.Fatal(got)
	}
	if err := checkExpressionFrame(expressionFrame(reviewEscape)); !errors.Is(err, ErrCSPExpression) {
		t.Fatalf("escape accepted: %v", err)
	}
}

// Claim: the checker reads byte-identical private frame bytes, and the temporary source is removed on every outcome.
func TestCSPCheckerExactFrameAndCleanup(t *testing.T) {
	for _, outcome := range []string{"confined", "invalid", "unexpected"} {
		t.Run(outcome, func(t *testing.T) {
			dir := t.TempDir()
			capture, pathCapture := filepath.Join(dir, "frame"), filepath.Join(dir, "path")
			checkerPath := filepath.Join(dir, "checker")
			script := fmt.Sprintf("#!/bin/sh\n[ \"$(stat -f %%Lp \"$4\")\" = 600 ] || exit 1\ncat \"$4\" > %q\nprintf '%%s' \"$4\" > %q\nprintf '%%s' %q\n", capture, pathCapture, outcome)
			if err := os.WriteFile(checkerPath, []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			checker := expressionSyntaxChecker{path: checkerPath, timeout: testhang.For(t, cspCheckerDrain)}
			const source = "document.title // no newline"
			checked := ""
			wrapped, err := wrapJavaScript(source, "https://example.com", func(frame string) error { checked = frame; return checker.check(frame) })
			data, readErr := os.ReadFile(capture)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(data) != checked || checked != "(() => { return (\n"+source+"\n  ); })();" {
				t.Fatalf("checker bytes differ: %q vs %q", data, checked)
			}
			if outcome == "confined" {
				if err != nil || !strings.Contains(wrapped, "const __macValue = "+string(data)) {
					t.Fatalf("checked frame differs from dispatch: %v\n%s", err, wrapped)
				}
			} else if !errors.Is(err, ErrCSPExpression) || wrapped != "" {
				t.Fatalf("failed checker accepted: %v", err)
			}
			path, err := os.ReadFile(pathCapture)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(string(path)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("private source remains: %v", err)
			}
		})
	}
}

// Claim: absent, timed-out, failed, and unrecognized checker results refuse without dispatching the expression wrapper.
func TestCSPCheckerUnavailablePreventsDispatch(t *testing.T) {
	dir := t.TempDir()
	for name, script := range map[string]string{
		"missing": "", "timeout": "#!/bin/sh\nwhile :; do :; done\n", "error": "#!/bin/sh\nexit 1\n", "unknown": "#!/bin/sh\nprintf unexpected\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if script != "" {
				if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			checker := expressionSyntaxChecker{path: path, timeout: 30 * time.Millisecond}
			calls := 0
			_, err := executeJavaScript("42", "https://example.com", func(string) (string, error) {
				calls++
				return guardEnvelope("eval-blocked", "https://example.com", ""), nil
			}, checker.check)
			if calls != 1 || !errors.Is(err, ErrCSPExpression) || !strings.Contains(err.Error(), "syntax check unavailable") {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}
