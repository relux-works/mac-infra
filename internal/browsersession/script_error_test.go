package browsersession

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Execute the generated page wrapper in a real engine, with only synthetic page
// state. The injected frame checker admits these fixed expressions; production
// continues to use the separate JavaScriptCore confinement check.
func TestScriptExceptionsKeepCauseWithoutRetry(t *testing.T) {
	engine, err := exec.LookPath(jscPath)
	if err != nil {
		engine, err = exec.LookPath("node")
		if err != nil {
			t.Skip("no JavaScript engine available; exception execution not exercised")
		}
	}
	for _, csp := range []bool{false, true} {
		for _, tc := range []struct{ name, thrown, cause string }{
			{"type-error", `new TypeError("client is null")`, "TypeError: client is null"},
			{"caller-eval-error", `new EvalError("caller failed")`, "EvalError: caller failed"},
			{"string", `"caller failed"`, "caller failed"},
			{"null", `null`, "null"},
			{"unprintable", `({toString(){throw 1;},get name(){throw 1;}})`, "unprintable exception"},
		} {
			name := "eval/" + tc.name
			if csp {
				name = "csp/" + tc.name
			}
			t.Run(name, func(t *testing.T) {
				calls, runs := 0, 0
				source := `(() => { ++globalThis.__runs; throw ` + tc.thrown + `; })()`
				result, err := executeJavaScript(source, "https://example.com", func(wrapped string) (string, error) {
					calls++
					program := `globalThis.print = (...args) => console.log(...args);` + pageStub
					if engine == jscPath {
						program = pageStub
					}
					if csp {
						program += blockedEvalStub
					}
					program += "\nprint(" + wrapped + "); print(globalThis.__runs);"
					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					out, engineErr := exec.CommandContext(ctx, engine, "-e", program).CombinedOutput()
					if engineErr != nil {
						t.Fatalf("page exception escaped the wrapper: %v: %s", engineErr, out)
					}
					lines := strings.Split(strings.TrimSpace(string(out)), "\n")
					if len(lines) != 2 || (lines[1] != "0" && lines[1] != "1") {
						t.Fatalf("unexpected page result: %s", out)
					}
					if lines[1] == "1" {
						runs++
					}
					return lines[0], nil
				}, func(string) error { return nil })
				wantCalls := 1
				if csp {
					wantCalls = 2
				}
				if !errors.Is(err, ErrScriptException) || !strings.Contains(err.Error(), tc.cause) || errors.Is(err, ErrCSPExpression) || errors.Is(err, ErrEvalBlocked) || errors.Is(err, ErrUnreadableResponse) {
					t.Fatalf("script cause lost or misclassified: result=%+v err=%v", result, err)
				}
				if calls != wantCalls || runs != 1 || result != (ExecutionResult{}) {
					t.Fatalf("calls=%d want=%d runs=%d result=%+v", calls, wantCalls, runs, result)
				}
			})
		}
	}
}

func TestScriptErrorEnvelopesRequireSentinelAndExpectedOrigin(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		want      error
	}{
		{"verified", guardEnvelope("script-error", "https://example.com", "TypeError: client is null"), ErrScriptException},
		{"wrong-origin", guardEnvelope("script-error", "https://wrong.example", "TypeError: client is null"), ErrOriginMismatch},
		{"unsealed", `{"outcome":"script-error","origin":"https://example.com","value":"TypeError: client is null"}`, ErrUnreadableResponse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseJavaScriptResult(tc.raw, "https://example.com")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err=%v want=%v", err, tc.want)
			}
		})
	}
}
