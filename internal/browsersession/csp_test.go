package browsersession

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/testhang"
)

const jscPath = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
const pageStub = `globalThis.location={origin:"https://example.com"}; globalThis.document={readyState:"complete"}; globalThis.__runs=0;`
const blockedEvalStub = `globalThis.eval=function(){throw new EvalError("CSP forbids unsafe-eval");};`

func runJSC(t *testing.T, program string) string {
	t.Helper()
	out, err := runJSCOutput(t, program)
	if err != nil {
		t.Fatalf("jsc: %v\n%s", err, out)
	}
	return out
}

func runJSCOutput(t *testing.T, program string) (string, error) {
	t.Helper()
	if _, err := os.Stat(jscPath); errors.Is(err, os.ErrNotExist) {
		t.Skip("JavaScriptCore jsc is missing at " + jscPath + "; CSP simulation did not run")
	} else if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "test.js")
	if err := os.WriteFile(path, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), testhang.For(t, cspCheckerDrain))
	defer cancel()
	out, err := exec.CommandContext(ctx, jscPath, path).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// cspCheckerDrain is the time reserved after stopping a checker: the jsc
// checker and the fake checkers start no child that keeps their pipes open.
const cspCheckerDrain = 0

// A hanging syntax checker in a test binary with -timeout 4s is reported by the test, not by the binary's timeout panic.
func TestCSPCheckerHangReportedBeforeBinaryDeadline(t *testing.T) {
	if os.Getenv("BROWSERSESSION_HANG_CHILD") == "1" {
		path := filepath.Join(t.TempDir(), "checker")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		err := (expressionSyntaxChecker{path: path, timeout: testhang.For(t, cspCheckerDrain)}).check("1")
		t.Fatalf("browser checker stopped by the hang guard: %v", err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCSPCheckerHangReportedBeforeBinaryDeadline$", "-test.timeout=4s", "-test.count=1")
	cmd.Env = append(os.Environ(), "BROWSERSESSION_HANG_CHILD=1")
	out, _ := cmd.CombinedOutput()
	if !strings.Contains(string(out), "browser checker stopped by the hang guard") || strings.Contains(string(out), "panic: test timed out") {
		t.Fatalf("hang near the binary deadline was not reported by the test:\n%s", out)
	}
}

// Claim: the fallback adds no dynamic code evaluation and places the source once, after the origin refusal.
func TestWrapJavaScriptExpressionHasNoDynamicCode(t *testing.T) {
	const payload = "globalThis.__payload()"
	for name, wrap := range map[string]func(string, string) (string, error){"eval": WrapJavaScript, "expression": WrapJavaScriptExpression} {
		t.Run(name, func(t *testing.T) {
			wrapped, err := wrap(payload, "https://example.com")
			if err != nil {
				t.Fatal(err)
			}
			guard := strings.Index(wrapped, `outcome:"origin-mismatch"`)
			source := strings.Index(wrapped, payload)
			if guard < 0 || source <= guard || strings.Count(wrapped, payload) != 1 {
				t.Fatalf("source is not guarded exactly once:\n%s", wrapped)
			}
			if name == "expression" {
				if !strings.Contains(wrapped, "(\n"+payload+"\n  )") {
					t.Fatal("source is not spliced as an expression")
				}
				for _, forbidden := range []string{"eval(", "Function(", "new Function", "setTimeout(", "setInterval("} {
					if strings.Contains(wrapped, forbidden) {
						t.Fatalf("fallback contains %q", forbidden)
					}
				}
			}
		})
	}
}

// Claim: both wrapper builders apply every blocked token guard to the original source.
func TestCSPWrappersRejectBlockedTokens(t *testing.T) {
	for _, wrap := range []func(string, string) (string, error){WrapJavaScript, WrapJavaScriptExpression} {
		for _, token := range BlockedJavaScriptTokens() {
			if _, err := wrap(strings.ToUpper(token), "https://example.com"); !errors.Is(err, ErrSensitiveJavaScript) {
				t.Fatalf("%s: %v", token, err)
			}
		}
	}
}

// Claim: the legacy route preserves statement completion values and the complete result envelope.
func TestJavaScriptCoreEvalPreservesStatements(t *testing.T) {
	wrapped, err := WrapJavaScript(`var answer=40; answer+2`, "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	result, err := ParseJavaScriptResult(runJSC(t, pageStub+"\nprint("+wrapped+");"), "https://example.com")
	if err != nil || result.Value != "42" || result.Origin != "https://example.com" || result.ReadyState != "complete" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

// Claim: simulated CSP produces eval-blocked without caller execution, then one expression dispatch executes once.
func TestJavaScriptCoreCSPRetryRunsSourceOnce(t *testing.T) {
	calls, runs := 0, 0
	result, err := ExecuteJavaScript(`(++globalThis.__runs, 42)`, "https://example.com", func(wrapped string) (string, error) {
		calls++
		out := runJSC(t, pageStub+blockedEvalStub+"\nprint("+wrapped+");print(globalThis.__runs);")
		lines := strings.Split(out, "\n")
		if len(lines) != 2 {
			t.Fatalf("jsc output=%q", out)
		}
		if calls == 1 {
			if lines[1] != "0" {
				t.Fatalf("caller ran before retry: %s", out)
			}
			if _, err := ParseJavaScriptResult(lines[0], "https://example.com"); !errors.Is(err, ErrEvalBlocked) {
				t.Fatalf("probe=%s err=%v", out, err)
			}
		} else {
			if lines[1] != "1" {
				t.Fatalf("expression did not run once: %s", out)
			}
			runs++
		}
		return lines[0], nil
	})
	if err != nil || calls != 2 || runs != 1 || result.Value != "42" || result.ReadyState != "complete" {
		t.Fatalf("result=%+v calls=%d runs=%d err=%v", result, calls, runs, err)
	}
}

// Claim: real syntax failures produce the expression diagnostic before any fallback dispatch.
func TestJavaScriptCoreCSPRequiresExpression(t *testing.T) {
	for _, source := range []string{`var x=1; x`, `document.readyState;`} {
		t.Run(source, func(t *testing.T) {
			calls := 0
			_, err := ExecuteJavaScript(source, "https://example.com", func(wrapped string) (string, error) {
				calls++
				out, err := runJSCOutput(t, pageStub+blockedEvalStub+"\nprint("+wrapped+");")
				return out, err
			})
			if calls != 1 || !errors.Is(err, ErrCSPExpression) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

// Claim: mismatched origins in both generated wrappers return before any caller side effect, even under CSP.
func TestJavaScriptCoreOriginRefusalPrecedesSource(t *testing.T) {
	for name, wrap := range map[string]func(string, string) (string, error){"eval": WrapJavaScript, "expression": WrapJavaScriptExpression} {
		t.Run(name, func(t *testing.T) {
			wrapped, err := wrap(`++globalThis.__runs`, "https://wrong.example")
			if err != nil {
				t.Fatal(err)
			}
			out := runJSC(t, pageStub+blockedEvalStub+"\nprint("+wrapped+");print(globalThis.__runs);")
			lines := strings.Split(out, "\n")
			if len(lines) != 2 || lines[1] != "0" {
				t.Fatalf("origin refusal ran source: %s", out)
			}
			if _, err := ParseJavaScriptResult(lines[0], "https://wrong.example"); !errors.Is(err, ErrOriginMismatch) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

// Claim: caller-thrown EvalError and ordinary errors never become an eval-blocked retry.
func TestJavaScriptCoreCallerErrorsAreNotRetried(t *testing.T) {
	for _, kind := range []string{"EvalError", "Error"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			_, err := ExecuteJavaScript(`(() => {++globalThis.__runs; throw new `+kind+`("caller failed");})()`, "https://example.com", func(wrapped string) (string, error) {
				calls++
				out := runJSC(t, pageStub+"\ntry {print("+wrapped+");} catch(e) {print(e.name);print(globalThis.__runs);}")
				if out != kind+"\n1" {
					t.Fatalf("caller failure was swallowed or repeated: %q", out)
				}
				return "", errors.New("page execution failed")
			})
			if err == nil || calls != 1 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		})
	}
}

// Claim: invalid, unsealed, unknown, and wrong-origin envelopes fail closed without permitting retry.
func TestParseJavaScriptResultCSPRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want error
	}{
		"empty":                {"", ErrUnreadableResponse},
		"missing-sentinel":     {`{"outcome":"eval-blocked","origin":"https://example.com"}`, ErrUnreadableResponse},
		"unknown":              {guardEnvelope("future", "https://example.com", ""), ErrUnreadableResponse},
		"wrong-origin":         {guardEnvelope("ok", "https://wrong.example", ""), ErrOriginMismatch},
		"blocked-wrong-origin": {guardEnvelope("eval-blocked", "https://wrong.example", ""), ErrOriginMismatch},
		"blocked":              {guardEnvelope("eval-blocked", "https://example.com", ""), ErrEvalBlocked},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseJavaScriptResult(tc.raw, "https://example.com"); !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
}

// Claim: dispatch count is bounded at two; only a verified eval-blocked result permits the second dispatch.
func TestExecuteJavaScriptRetryDecisions(t *testing.T) {
	blocked := guardEnvelope("eval-blocked", "https://example.com", "")
	ok := guardEnvelope("ok", "https://example.com", "42")
	for name, tc := range map[string]struct {
		first, second     string
		dispatchErr, want error
		calls             int
	}{
		"normal":             {first: ok, calls: 1},
		"retry":              {first: blocked, second: ok, calls: 2},
		"malformed":          {first: "not-json", want: ErrUnreadableResponse, calls: 1},
		"empty":              {want: ErrUnreadableResponse, calls: 1},
		"missing-sentinel":   {first: `{"outcome":"eval-blocked"}`, want: ErrUnreadableResponse, calls: 1},
		"unknown":            {first: guardEnvelope("future", "https://example.com", ""), want: ErrUnreadableResponse, calls: 1},
		"wrong-origin":       {first: guardEnvelope("eval-blocked", "https://wrong.example", ""), want: ErrOriginMismatch, calls: 1},
		"page-error":         {dispatchErr: errors.New("page error"), calls: 1},
		"no-third-dispatch":  {first: blocked, second: blocked, want: ErrCSPExpression, calls: 2},
		"retry-empty":        {first: blocked, want: ErrCSPExpression, calls: 2},
		"retry-origin-drift": {first: blocked, second: guardEnvelope("origin-mismatch", "https://wrong.example", ""), want: ErrOriginMismatch, calls: 2},
	} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			_, err := ExecuteJavaScript("42", "https://example.com", func(wrapped string) (string, error) {
				calls++
				if calls == 1 {
					return tc.first, tc.dispatchErr
				}
				return tc.second, nil
			})
			if calls != tc.calls {
				t.Fatalf("calls=%d want=%d", calls, tc.calls)
			}
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err=%v want=%v", err, tc.want)
				}
			} else if !errors.Is(err, tc.dispatchErr) {
				t.Fatalf("err=%v want=%v", err, tc.dispatchErr)
			}
		})
	}
}

func guardEnvelope(outcome, origin, value string) string {
	return fmt.Sprintf(`{"__macBrowserSessionGuard":%q,"outcome":%q,"origin":%q,"readyState":"complete","value":%q}`, guardSentinel, outcome, origin, value)
}
