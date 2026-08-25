package main

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/chromectl"
)

// fetchFileFixedMessages is this command's own transcription of the closed
// diagnostic vocabulary. Comparing against chromectl's Message() would be
// self-referential: a change on both sides would pass silently.
var fetchFileFixedMessages = map[chromectl.FetchFileDiagnosticCode]string{
	chromectl.FetchFileUnverifiable:         "fetch-file failed safely",
	chromectl.FetchFileUsage:                "fetch-file invocation was refused",
	chromectl.FetchFileRequestUnreadable:    "fetch-file request could not be verified",
	chromectl.FetchFileRequestRefused:       "fetch-file request was refused",
	chromectl.FetchFileTargetMissing:        "browser target is no longer available",
	chromectl.FetchFileOriginMismatch:       "browser target origin changed",
	chromectl.FetchFileTransportUnavailable: "Chrome page-context transport is unavailable",
	chromectl.FetchFileTransportFailed:      "Chrome page-context transport failed",
	chromectl.FetchFileResponseUnverifiable: "Chrome page-context response could not be verified",
	chromectl.FetchFileBusy:                 "another sealed fetch is already running",
	chromectl.FetchFileSizeLimit:            "fetch response exceeded the configured size limit",
	chromectl.FetchFileTimeout:              "fetch response exceeded the configured timeout",
	chromectl.FetchFileHTTPStatus:           "authenticated fetch returned a non-success status",
	chromectl.FetchFileRedirectRefused:      "authenticated fetch redirect was refused",
	chromectl.FetchFilePageFailed:           "authenticated page-context fetch failed",
	chromectl.FetchFileOutputPrepare:        "private output could not be prepared",
	chromectl.FetchFileOutputWrite:          "private output could not be published",
}

// fetchFileCaptureStdin records every sealed program the child receives while
// keeping $source scoped to the current call. The start program is the only one
// that carries the protected resource, so an accumulating capture would make the
// positive control pass for the wrong reason.
const fetchFileCaptureStdin = `cat > "$CALL_PATH"
cat "$CALL_PATH" >> "$STDIN_PATH"
source=$(cat "$CALL_PATH")`

// fetchFileDiagnosticArgs is the standard production invocation used by the
// tests below. Only the explicit output path varies.
func fetchFileDiagnosticArgs(outPath string) []string {
	return []string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}
}

// assertFetchFileDiagnosticLine is the invariant every fetch-file failure must
// satisfy at the real CLI boundary: stdout stays empty, stderr is exactly one
// line consisting of the fixed prefix plus the fixed literal for the expected
// code, and none of the forbidden byte sources appears anywhere.
func assertFetchFileDiagnosticLine(t *testing.T, stdout, stderr string, code chromectl.FetchFileDiagnosticCode, forbidden ...string) {
	t.Helper()
	if stdout != "" {
		t.Fatalf("a failure wrote to stdout: %q", stdout)
	}
	fixed, ok := fetchFileFixedMessages[code]
	if !ok {
		t.Fatalf("code %d has no pinned literal", code)
	}
	want := "fetch-file: " + fixed + "\n"
	if stderr != want {
		t.Fatalf("stderr=%q want exactly %q", stderr, want)
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(stderr, value) {
			t.Fatalf("diagnostic leaked %q: %q", value, stderr)
		}
	}
}

// TestFetchFileProductionEntryNeverRendersOutputPreflightDetail reproduces the
// exact defect the revision-4 review demonstrated against both the source entry
// and the installed binary: a synthetic file-as-directory output path made
// runFetchFile print the private path and the underlying lstat text. The fixed
// output-prepare code must be the entire diagnostic now.
func TestFetchFileProductionEntryNeverRendersOutputPreflightDetail(t *testing.T) {
	const marker = "PRIVATE_PATH_MARKER_fake_case_token"
	for name, build := range map[string]func(t *testing.T) string{
		"file-used-as-directory": func(t *testing.T) string {
			dir := t.TempDir()
			blocker := filepath.Join(dir, marker)
			if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(blocker, "secret-output.bin")
		},
		"destination-is-a-directory": func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), marker)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			return dir
		},
		"unwritable-parent": func(t *testing.T) string {
			dir := filepath.Join(t.TempDir(), marker)
			if err := os.MkdirAll(dir, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			return filepath.Join(dir, "secret-output.bin")
		},
	} {
		t.Run(name, func(t *testing.T) {
			executed := filepath.Join(t.TempDir(), "executed")
			t.Setenv("MARKER", executed)
			osa := writeFetchFileCLIExecutable(t, `cat >/dev/null; touch "$MARKER"; exit 99`)
			oldNew := newChromeSession
			newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
			defer func() { newChromeSession = oldNew }()

			outPath := build(t)
			var stdout, stderr bytes.Buffer
			restoreStdin := withFetchFileStdin(t, "/statements?documentId=preflight-fake-token", 16, 60000)
			code := run(fetchFileDiagnosticArgs(outPath), &stdout, &stderr)
			restoreStdin()
			if code != 1 {
				t.Fatalf("output preflight failure code=%d want=1 stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			assertFetchFileDiagnosticLine(t, stdout.String(), stderr.String(), chromectl.FetchFileOutputPrepare,
				marker, outPath, "lstat", "mkdir", "not a directory", "permission denied", "is a directory", "inspect path", "prepare output", "preflight-fake-token", "documentId")
			if _, err := os.Stat(executed); !os.IsNotExist(err) {
				t.Fatalf("a failed output preflight still reached the browser production call: %v", err)
			}
		})
	}
}

// stubOutputArtifact drives the production commit branch through the same
// prepareRunJSOutput seam runFetchFile itself uses. The real atomic artifact's
// commit errors quote the temporary and final paths, which is precisely what
// must not be rendered.
type stubOutputArtifact struct {
	err      error
	aborted  bool
	commits  int
	finalDir string
}

func (a *stubOutputArtifact) Commit(string) error { a.commits++; return a.err }
func (a *stubOutputArtifact) Abort()              { a.aborted = true }

// TestFetchFileProductionEntryNeverRendersOutputCommitDetail attacks the last
// failure surface in runFetchFile. A commit error carries filesystem paths, so
// only the fixed output-write code may reach the operator, and the destination
// must be left exactly as it was.
func TestFetchFileProductionEntryNeverRendersOutputCommitDetail(t *testing.T) {
	const marker = "COMMIT_PATH_MARKER_fake_case_token"
	osa := writeFetchFileCLIExecutable(t, `
source=$(cat)
case "$source" in
  *contentType:String*) value='{"state":"done","status":200,"bytes":3,"chunkCount":1,"contentType":"application/pdf"}' ;;
  *job.chunks*) value='{"state":"chunk","index":0,"data":"b25l"}' ;;
  *different-job*) value='cleared' ;;
  *) value='started' ;;
esac
emit_value "$value"
`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()

	dir := t.TempDir()
	outPath := filepath.Join(dir, marker+".bin")
	if err := os.WriteFile(outPath, []byte("previous"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := &stubOutputArtifact{err: errors.New("rename " + filepath.Join(dir, ".mac-chrome-session-run-js-123") + " -> " + outPath + ": permission denied")}
	oldPrepare := prepareRunJSOutput
	prepareRunJSOutput = func(path string) (runJSOutputArtifact, error) { return artifact, nil }
	defer func() { prepareRunJSOutput = oldPrepare }()

	var stdout, stderr bytes.Buffer
	restoreStdin := withFetchFileStdin(t, "/statements?documentId=commit-fake-token", 16, 60000)
	code := run(fetchFileDiagnosticArgs(outPath), &stdout, &stderr)
	restoreStdin()
	if code != 1 {
		t.Fatalf("commit failure code=%d want=1 stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	// Positive control: absence proves nothing unless the commit branch really
	// ran and really returned the marked error.
	if artifact.commits != 1 {
		t.Fatalf("the production commit branch did not run: commits=%d", artifact.commits)
	}
	assertFetchFileDiagnosticLine(t, stdout.String(), stderr.String(), chromectl.FetchFileOutputWrite,
		marker, outPath, "rename", "permission denied", "write output", "mac-chrome-session-run-js", "commit-fake-token", "documentId")
	data, err := os.ReadFile(outPath)
	if err != nil || string(data) != "previous" {
		t.Fatalf("a failed commit replaced the destination: data=%q err=%v", data, err)
	}
}

// TestFetchFileProductionEntryOwnsItsFlagDiagnostics proves the flag package is
// no longer a second fetch-file formatter. The retired --resource path is the
// motivating case: its value is a protected reference, and flag's own error and
// usage output used to go straight to stderr.
func TestFetchFileProductionEntryOwnsItsFlagDiagnostics(t *testing.T) {
	const marker = "flag-argv-fake-document-token"
	executed := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", executed)
	osa := writeFetchFileCLIExecutable(t, `cat >/dev/null; touch "$MARKER"; exit 99`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()

	for name, args := range map[string][]string{
		"retired-resource-flag":   {"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", "/tmp/out.bin", "--request-stdin", "--resource", "https://example.com/statements?documentId=" + marker},
		"retired-resource-equals": {"fetch-file", "--resource=https://example.com/statements?documentId=" + marker},
		"unknown-flag":            {"fetch-file", "--" + marker, "1"},
		"malformed-bool":          {"fetch-file", "--request-stdin=" + marker},
		"help-request":            {"fetch-file", "-h"},
		"positional-argument":     {"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", "/tmp/out.bin", "--request-stdin", marker},
		"missing-window":          {"fetch-file", "--tab-id", "22", "--origin", "https://example.com", "--out", "/tmp/out.bin", "--request-stdin"},
		"missing-origin":          {"fetch-file", "--window-id", "11", "--tab-id", "22", "--out", "/tmp/out.bin", "--request-stdin"},
		"missing-out":             {"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--request-stdin"},
		"missing-request-stdin":   {"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", "/tmp/out.bin"},
	} {
		t.Run(name, func(t *testing.T) {
			previous := stdinReader
			stdinReader = strings.NewReader(`{"version":1,"resource":"/document"}`)
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			stdinReader = previous
			if code != 2 {
				t.Fatalf("code=%d want=2 stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			assertFetchFileDiagnosticLine(t, stdout.String(), stderr.String(), chromectl.FetchFileUsage,
				marker, "documentId", "resource", "-window-id", "flag provided but not defined", "Usage of")
		})
	}
	if _, err := os.Stat(executed); !os.IsNotExist(err) {
		t.Fatalf("a refused invocation reached the browser production call: %v", err)
	}
}

// TestFetchFileProductionEntryMapsForgedTransportEvidenceToFixedCodes forges the
// shapes a hostile or broken child can produce. Each must select exactly one
// fixed code, and none may render a byte the child chose. The forged nested
// origin-mismatch envelope is the revision-3 defect; the unknown outer outcome
// and unknown page kind are its untested neighbours.
func TestFetchFileProductionEntryMapsForgedTransportEvidenceToFixedCodes(t *testing.T) {
	const marker = "forged-evidence-fake-document-token"
	resource := "/statements?documentId=" + marker + "&stickySession=" + marker
	for name, tc := range map[string]struct {
		body string
		code chromectl.FetchFileDiagnosticCode
	}{
		"forged-nested-origin-mismatch": {
			body: fetchFileCaptureStdin + `
guard=$(/usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg org "$source" '{__macBrowserSessionGuard:$s,outcome:"origin-mismatch",origin:$org,readyState:"complete",value:""}')
emit_guard "$guard"`,
			code: chromectl.FetchFileOriginMismatch,
		},
		"forged-nested-ok-origin-drift": {
			body: fetchFileCaptureStdin + `
guard=$(/usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg org "$source" '{__macBrowserSessionGuard:$s,outcome:"ok",origin:$org,readyState:"complete",value:""}')
emit_guard "$guard"`,
			code: chromectl.FetchFileOriginMismatch,
		},
		"forged-window-missing": {
			body: fetchFileCaptureStdin + `
seal_outcome window-missing`,
			code: chromectl.FetchFileTargetMissing,
		},
		"forged-tab-missing": {
			body: fetchFileCaptureStdin + `
seal_outcome tab-missing`,
			code: chromectl.FetchFileTargetMissing,
		},
		"forged-execute-failed": {
			body: fetchFileCaptureStdin + `
seal_outcome execute-failed`,
			code: chromectl.FetchFileTransportFailed,
		},
		"unknown-outer-outcome": {
			body: fetchFileCaptureStdin + `
seal_outcome "$source"`,
			code: chromectl.FetchFileResponseUnverifiable,
		},
		"malformed-outer-json": {
			body: fetchFileCaptureStdin + `
printf '%s' "{\"__macChromePrivateTransport\":\"$source"`,
			code: chromectl.FetchFileResponseUnverifiable,
		},
		"foreign-outer-sentinel": {
			body: fetchFileCaptureStdin + `
/usr/bin/jq -cn --arg v "$source" '{__macChromePrivateTransport:"forged",outcome:"ok",value:$v}'`,
			code: chromectl.FetchFileResponseUnverifiable,
		},
		"unsealed-nested-guard": {
			body: fetchFileCaptureStdin + `
seal_outcome ok "$source"`,
			code: chromectl.FetchFileResponseUnverifiable,
		},
		"malformed-page-metadata": {
			body: fetchFileCaptureStdin + `
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value "$source"; else emit_value started; fi`,
			code: chromectl.FetchFileResponseUnverifiable,
		},
		"unknown-page-error-kind": {
			body: fetchFileCaptureStdin + `
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"` + marker + `"}'; else emit_value started; fi`,
			code: chromectl.FetchFilePageFailed,
		},
		"page-http-status": {
			body: fetchFileCaptureStdin + `
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"http-status","status":403}'; else emit_value started; fi`,
			code: chromectl.FetchFileHTTPStatus,
		},
		"page-redirect-refused": {
			body: fetchFileCaptureStdin + `
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"error","kind":"redirect-refused"}'; else emit_value started; fi`,
			code: chromectl.FetchFileRedirectRefused,
		},
		"malformed-chunk": {
			body: fetchFileCaptureStdin + `
if printf '%s' "$source" | grep -q 'job.chunks'; then emit_value '{"state":"chunk","index":0,"data":"` + marker + `!!"}'; exit 0; fi
if printf '%s' "$source" | grep -q 'contentType:String'; then emit_value '{"state":"done","status":200,"bytes":3,"chunkCount":1}'; else emit_value started; fi`,
			code: chromectl.FetchFileResponseUnverifiable,
		},
		"second-fetch-busy": {
			body: fetchFileCaptureStdin + `
emit_value busy`,
			code: chromectl.FetchFileBusy,
		},
	} {
		t.Run(name, func(t *testing.T) {
			captureDir := t.TempDir()
			stdinPath := filepath.Join(captureDir, "stdin")
			t.Setenv("STDIN_PATH", stdinPath)
			t.Setenv("CALL_PATH", filepath.Join(captureDir, "call"))
			osa := writeFetchFileCLIExecutable(t, tc.body)
			oldNew := newChromeSession
			newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
			defer func() { newChromeSession = oldNew }()

			outPath := filepath.Join(t.TempDir(), "result.bin")
			var stdout, stderr bytes.Buffer
			restoreStdin := withFetchFileStdin(t, resource, 3, 60000)
			code := run(fetchFileDiagnosticArgs(outPath), &stdout, &stderr)
			restoreStdin()
			if code != 1 {
				t.Fatalf("forged evidence code=%d want=1 stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			// Positive control: the child must actually have received the
			// resource-bearing program, otherwise the absence below is vacuous.
			seen, readErr := os.ReadFile(stdinPath)
			if readErr != nil {
				t.Fatalf("could not read the sealed stdin program, so absence proves nothing: %v", readErr)
			}
			if !strings.Contains(string(seen), marker) {
				t.Fatalf("the child never received the protected resource; this check would be vacuous: %d bytes", len(seen))
			}
			assertFetchFileDiagnosticLine(t, stdout.String(), stderr.String(), tc.code,
				marker, "documentId", "stickySession", "/statements", "__macChromeFetchFileV1", "__macBrowserSessionGuard", "__macChromePrivateTransport", "credentials", "location.href")
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("a forged transport response published output: %v", err)
			}
		})
	}
}

// TestFetchFileProductionEntryEmitsExactlyOneDiagnosticLinePerFailure is the
// single-owner invariant expressed as behavior: whatever the failure, stderr is
// one line and stdout is empty. A second surviving print site — the shape of
// every earlier revision — makes this fail.
func TestFetchFileProductionEntryEmitsExactlyOneDiagnosticLinePerFailure(t *testing.T) {
	osa := writeFetchFileCLIExecutable(t, `printf '%s' "$source" >&2; exit 1`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()
	for name, tc := range map[string]struct {
		args     []string
		envelope string
	}{
		"usage":              {args: []string{"fetch-file", "--window-id", "11"}, envelope: `{"version":1,"resource":"/x"}`},
		"request-unreadable": {args: nil, envelope: `not-json`},
		"request-refused":    {args: nil, envelope: `{"version":1,"resource":"https://other.example/x"}`},
		"transport-failed":   {args: nil, envelope: `{"version":1,"resource":"/x"}`},
	} {
		t.Run(name, func(t *testing.T) {
			captureDir := t.TempDir()
			t.Setenv("STDIN_PATH", filepath.Join(captureDir, "stdin"))
			t.Setenv("CALL_PATH", filepath.Join(captureDir, "call"))
			outPath := filepath.Join(t.TempDir(), "result.bin")
			args := tc.args
			if args == nil {
				args = fetchFileDiagnosticArgs(outPath)
			}
			previous := stdinReader
			stdinReader = strings.NewReader(tc.envelope)
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			stdinReader = previous
			if code == 0 {
				t.Fatalf("failure %q reported success: stdout=%q", name, stdout.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("failure %q wrote to stdout: %q", name, stdout.String())
			}
			if lines := strings.Count(stderr.String(), "\n"); lines != 1 {
				t.Fatalf("failure %q emitted %d stderr lines, so more than one output site survives: %q", name, lines, stderr.String())
			}
			if !strings.HasPrefix(stderr.String(), "fetch-file: ") {
				t.Fatalf("failure %q did not go through the single emitter: %q", name, stderr.String())
			}
		})
	}
}

// TestRunFetchFileHasNoSecondDiagnosticOutputSite is the static half of the
// single-owner invariant. The behavioral test above proves one line is printed
// today; this proves there is structurally no other place in runFetchFile that
// could print, so a future branch cannot quietly become the next leak.
func TestRunFetchFileHasNoSecondDiagnosticOutputSite(t *testing.T) {
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]*ast.FuncDecl{}
	for _, decl := range parsed.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil {
			bodies[fn.Name.Name] = fn
		}
	}
	runFetchFileDecl, ok := bodies["runFetchFile"]
	if !ok {
		t.Fatal("runFetchFile is not declared in main.go; this guard would be vacuous")
	}
	// Positive control: the same scan must find the print sites of a command
	// that legitimately formats errors, otherwise an empty result proves nothing.
	if calls := packageQualifiedCalls(bodies["runUpload"], "fmt"); len(calls) == 0 {
		t.Fatal("the scan found no fmt call in runUpload, so it cannot detect one in runFetchFile")
	}
	if calls := packageQualifiedCalls(runFetchFileDecl, "fmt"); len(calls) != 0 {
		t.Fatalf("runFetchFile formats output directly through %v; every failure must go through emitFetchFileDiagnostic", calls)
	}
	for _, banned := range []string{"FormatAutomationError", "FormatBrowserError"} {
		if usesIdentifier(runFetchFileDecl, banned) {
			t.Fatalf("runFetchFile calls %s; a generic error formatter can render any lower-layer detail", banned)
		}
	}
	emitter, ok := bodies["emitFetchFileDiagnostic"]
	if !ok {
		t.Fatal("emitFetchFileDiagnostic is not declared in main.go")
	}
	if calls := packageQualifiedCalls(emitter, "fmt"); len(calls) != 1 || calls[0] != "fmt.Fprintln" {
		t.Fatalf("the emitter has %v; exactly one non-formatting print is allowed", calls)
	}
	// The emitter must take the closed diagnostic type only: no error, no
	// format string, no stage label.
	params := emitter.Type.Params.List
	if len(params) != 2 {
		t.Fatalf("the emitter takes %d parameter groups; only (io.Writer, chromectl.FetchFileDiagnostic) is allowed", len(params))
	}
	if got := types.ExprString(params[1].Type); got != "chromectl.FetchFileDiagnostic" {
		t.Fatalf("the emitter's second parameter is %q; only the closed diagnostic type is allowed", got)
	}
	if emitter.Type.Params.List[0].Names == nil || len(params[0].Names) != 1 {
		t.Fatalf("the emitter takes a variadic or grouped writer parameter; only a single writer is allowed")
	}
}

func packageQualifiedCalls(fn *ast.FuncDecl, pkg string) []string {
	var found []string
	if fn == nil {
		return found
	}
	ast.Inspect(fn, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := selector.X.(*ast.Ident)
		if !ok || ident.Name != pkg {
			return true
		}
		found = append(found, pkg+"."+selector.Sel.Name)
		return true
	})
	return found
}

func usesIdentifier(fn *ast.FuncDecl, name string) bool {
	used := false
	ast.Inspect(fn, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && ident.Name == name {
			used = true
		}
		return !used
	})
	return used
}
