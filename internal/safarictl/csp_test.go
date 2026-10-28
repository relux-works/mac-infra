package safarictl

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
	for _, mode := range []string{"run", "check"} {
		t.Run(mode, func(t *testing.T) {
			for name, tc := range map[string]struct {
				first, source string
				calls         int
				want          error
				secondError   bool
			}{
				"normal":            {first: cspOK, source: "document.readyState", calls: 1},
				"csp":               {first: cspBlocked, source: "document.readyState", calls: 2},
				"statements":        {first: cspBlocked, source: "var x=1; x", calls: 2, want: browsersession.ErrCSPExpression, secondError: true},
				"page-error":        {first: "PAGE_ERROR", source: "document.readyState", calls: 1},
				"caller-eval-error": {first: "EvalError", source: "(() => { throw new EvalError(); })()", calls: 1},
				"malformed":         {first: "bad-json", source: "document.readyState", calls: 1, want: browsersession.ErrUnreadableResponse},
				"empty":             {source: "document.readyState", calls: 1, want: browsersession.ErrUnreadableResponse},
				"missing-sentinel":  {first: `{"outcome":"eval-blocked"}`, source: "42", calls: 1, want: browsersession.ErrUnreadableResponse},
				"wrong-origin":      {first: strings.Replace(cspBlocked, cspOrigin, "https://wrong.example", 1), source: "42", calls: 1, want: browsersession.ErrOriginMismatch},
				"blocked-token":     {first: cspOK, source: "document.cookie", calls: 0, want: browsersession.ErrSensitiveJavaScript},
			} {
				if mode == "check" && name != "normal" && name != "csp" && name != "malformed" && name != "empty" {
					continue
				}
				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					capture := filepath.Join(dir, "calls")
					t.Setenv("CSP_CAPTURE", capture)
					t.Setenv("CSP_FIRST", tc.first)
					t.Setenv("CSP_SECOND_ERROR", map[bool]string{true: "yes", false: "no"}[tc.secondError])
					osa := writeFakeSafariOsaScript(t, `printf 'DISPATCH\n' >> "$CSP_CAPTURE"
cat "$3" >> "$CSP_CAPTURE"
printf '\nTARGET:%s\n' "${4-check}" >> "$CSP_CAPTURE"
if [ ! -f "$CSP_CAPTURE.first" ]; then
 touch "$CSP_CAPTURE.first"
 case "$CSP_FIRST" in PAGE_ERROR|EvalError) printf '%s' "$CSP_FIRST" >&2; exit 1;; esac
 printf '%s' "$CSP_FIRST"
else
 if [ "$CSP_SECOND_ERROR" = yes ]; then printf 'SyntaxError: unexpected var' >&2; exit 1; fi
 printf '%s' '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"complete"}'
fi`)
					session := New(filepath.Join(dir, "artifacts"))
					session.OsaScriptPath = osa
					session.TargetWindowID = 123
					session.ExpectedOrigin = cspOrigin
					var value string
					var err error
					if mode == "check" {
						value, err = session.CheckJavaScript(context.Background())
					} else {
						value, err = session.RunJavaScript(context.Background(), tc.source)
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
						target := "TARGET:123"
						if mode == "check" {
							target = "TARGET:check"
						}
						if strings.Count(string(data), target) != tc.calls {
							t.Fatalf("exact target changed: %s", data)
						}
					}
					if tc.calls == 2 && !tc.secondError {
						if !strings.Contains(string(data), "const __macValue = (\n"+tc.source+"\n") {
							t.Fatalf("fallback did not splice source: %s", data)
						}
					}
				})
			}
		})
	}
}

// Claim: Safari's built-in payloads parse as guarded expressions without running on the wrong origin.
func TestSafariBuiltinsAreCSPExpressions(t *testing.T) {
	const jsc = "/System/Library/Frameworks/JavaScriptCore.framework/Versions/Current/Helpers/jsc"
	if _, err := os.Stat(jsc); errors.Is(err, os.ErrNotExist) {
		t.Skip("JavaScriptCore jsc is missing; built-in CSP expression validation did not run")
	} else if err != nil {
		t.Fatal(err)
	}
	for name, source := range map[string]string{
		"snapshot":    SnapshotJavaScript(10, 1),
		"start-fetch": StartFetchJavaScript("/file", 10),
		"poll-fetch":  PollFetchJavaScript(),
		"read-chunk":  ReadFetchChunkJavaScript(0, true),
	} {
		t.Run(name, func(t *testing.T) {
			wrapped, err := browsersession.WrapJavaScriptExpression(source, cspOrigin)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "builtin.js")
			program := `globalThis.location={origin:"https://wrong.example"};print(` + wrapped + `);`
			if err := os.WriteFile(path, []byte(program), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(jsc, path).CombinedOutput()
			if err != nil {
				t.Fatalf("builtin expression parse: %v: %s", err, out)
			}
			if _, err := browsersession.ParseJavaScriptResult(strings.TrimSpace(string(out)), cspOrigin); !errors.Is(err, browsersession.ErrOriginMismatch) {
				t.Fatalf("builtin guard: %v", err)
			}
		})
	}
}
