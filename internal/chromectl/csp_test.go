package chromectl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

const cspOrigin = "https://example.com"
const cspBlocked = `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"eval-blocked","origin":"https://example.com","readyState":"complete","value":""}`
const cspOK = `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"complete"}`

// Claim: real session methods retry only a sealed eval-blocked result, keep exact targets, and reject secrets before dispatch.
func TestSessionCSPRetryWithFakeOsaScript(t *testing.T) {
	for _, mode := range []string{"run", "private"} {
		t.Run(mode, func(t *testing.T) {
			for name, tc := range map[string]struct {
				first, source string
				calls         int
				want          error
				secondError   bool
			}{
				"normal":              {first: cspOK, source: "document.readyState", calls: 1},
				"csp":                 {first: cspBlocked, source: "document.readyState", calls: 2},
				"fallback-page-error": {first: cspBlocked, source: "42", calls: 2, want: browsersession.ErrCSPExpression, secondError: true},
				"statements":          {first: cspBlocked, source: "var x=1; x", calls: 1, want: browsersession.ErrCSPExpression, secondError: true},
				"page-error":          {first: "PAGE_ERROR", source: "document.readyState", calls: 1},
				"caller-eval-error":   {first: "EvalError", source: "(() => { throw new EvalError(); })()", calls: 1},
				"malformed":           {first: "bad-json", source: "document.readyState", calls: 1, want: browsersession.ErrUnreadableResponse},
				"empty":               {source: "document.readyState", calls: 1, want: browsersession.ErrUnreadableResponse},
				"missing-sentinel":    {first: `{"outcome":"eval-blocked"}`, source: "42", calls: 1, want: browsersession.ErrUnreadableResponse},
				"wrong-origin":        {first: strings.Replace(cspBlocked, cspOrigin, "https://wrong.example", 1), source: "42", calls: 1, want: browsersession.ErrOriginMismatch},
				"blocked-token":       {first: cspOK, source: "document.cookie", calls: 0, want: browsersession.ErrSensitiveJavaScript},
			} {
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					capture := filepath.Join(dir, "calls")
					t.Setenv("CSP_CAPTURE", capture)
					t.Setenv("CSP_FIRST", tc.first)
					t.Setenv("CSP_SECOND_ERROR", map[bool]string{true: "yes", false: "no"}[tc.secondError])
					osa := writeFakeOsaScript(t, `printf 'DISPATCH\n' >> "$CSP_CAPTURE"
if [ "$CSP_MODE" = private ]; then
 cat >> "$CSP_CAPTURE"
else
 printf '%s\n' "$5" >> "$CSP_CAPTURE"
 printf 'TARGET:%s/%s\n' "$3" "$4" >> "$CSP_CAPTURE"
fi
if [ ! -f "$CSP_CAPTURE.first" ]; then
 touch "$CSP_CAPTURE.first"
 case "$CSP_FIRST" in PAGE_ERROR|EvalError) printf '%s' "$CSP_FIRST" >&2; exit 1;; esac
 if [ "$CSP_MODE" = private ]; then emit_guard "$CSP_FIRST"; else printf '%s' "$CSP_FIRST"; fi
else
 if [ "$CSP_SECOND_ERROR" = yes ]; then
  if [ "$CSP_MODE" = private ]; then seal_outcome execute-failed; else printf 'SyntaxError: unexpected var' >&2; exit 1; fi
 elif [ "$CSP_MODE" = private ]; then emit_value complete
 else guard_value complete
 fi
fi`)
					t.Setenv("CSP_MODE", mode)
					session := Session{OsaScriptPath: osa}
					var value string
					var err error
					if mode == "private" {
						result, privateErr := session.runJavaScriptPrivate(context.Background(), "11", "22", cspOrigin, tc.source)
						value, err = result.Value, privateErr
					} else {
						value, err = session.RunJavaScript(context.Background(), "11", "22", cspOrigin, tc.source)
					}
					data, readErr := os.ReadFile(capture)
					if tc.calls == 0 {
						if !errors.Is(readErr, os.ErrNotExist) {
							t.Fatalf("blocked source dispatched: %s err=%v", data, readErr)
						}
					} else if readErr != nil {
						t.Fatal(readErr)
					}
					if got := strings.Count(string(data), "DISPATCH\n"); got != tc.calls {
						t.Fatalf("calls=%d want=%d; %s", got, tc.calls, data)
					}
					if tc.want != nil {
						if !errors.Is(err, tc.want) {
							t.Fatalf("err=%v want=%v", err, tc.want)
						}
					} else if strings.HasSuffix(name, "error") {
						if err == nil {
							t.Fatal("page error accepted")
						}
					} else if err != nil || value != "complete" {
						t.Fatalf("value=%q err=%v", value, err)
					}
					if tc.secondError && (err == nil || !strings.Contains(err.Error(), "single expression (use an IIFE for statements)")) {
						t.Fatalf("missing expression diagnostic: %v", err)
					}
					if tc.calls > 0 {
						if mode == "run" {
							if strings.Count(string(data), "TARGET:11/22") != tc.calls {
								t.Fatalf("exact target changed: %s", data)
							}
						} else {
							for _, target := range []string{`windowID="11"`, `tabID="22"`} {
								if strings.Count(string(data), target) != tc.calls {
									t.Fatalf("private exact target changed: %s", data)
								}
							}
						}
					}
					if tc.calls == 2 && !tc.secondError {
						if !strings.Contains(strings.NewReplacer(`\n`, "\n", `\u003e`, ">").Replace(string(data)), "const __macValue = (() => { return (\n"+tc.source+"\n") {
							t.Fatalf("fallback did not splice source: %s", data)
						}
					}
				})
			}
		})
	}
}
