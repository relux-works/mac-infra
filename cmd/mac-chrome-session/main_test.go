package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/chromectl"
)

func TestUsageDocumentsGuardedAndHeartbeatLifecycle(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code = %d stderr=%s", code, stderr.String())
	}
	for _, want := range []string{"run-js", "atomic 0600 --out PATH", "trusted-input", "trusted text", "upload", "native file upload", "slack-read", "extract", "focus", "origin-guarded", "close", "heartbeat start|restart|status|stop|list", "Chrome/Safari"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("usage missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestVisibleCommandHelpDocumentsAuthorizationBoundary(t *testing.T) {
	for _, tc := range []struct {
		command string
		wants   []string
	}{
		{command: "focus", wants: []string{"-window-id string", "-tab-id string", "-origin string", "-human-authorized", "explicitly authorized"}},
		{command: "trusted-input", wants: []string{"-window-id string", "-tab-id string", "-origin string", "-human-authorized", "-request-stdin", "versioned JSON"}},
		{command: "upload", wants: []string{"-window-id string", "-tab-id string", "-origin string", "-human-authorized", "-request-stdin", "versioned JSON"}},
	} {
		t.Run(tc.command, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run([]string{tc.command, "--help"}, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d want=2 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			for _, want := range tc.wants {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("%s help missing %q:\n%s", tc.command, want, stderr.String())
				}
			}
		})
	}
}

func TestUploadRequiresExplicitAuthorizationAndKeepsPathsOutOfOutput(t *testing.T) {
	file := filepath.Join(t.TempDir(), "evidence.pdf")
	if err := os.WriteFile(file, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{
		"version": chromectl.UploadVersion, "inputSelector": "#file", "paths": []string{file},
		"allowedExtensions": []string{".pdf"}, "maxFileBytes": 1024, "maxTotalBytes": 1024,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	oldInput, oldUpload := stdinReader, uploadChromeFiles
	defer func() { stdinReader, uploadChromeFiles = oldInput, oldUpload }()
	called := false
	uploadChromeFiles = func(_ context.Context, _, _, origin string, got chromectl.UploadRequest) (chromectl.UploadResult, error) {
		called = true
		if len(got.Paths) != 1 || got.Paths[0] != file {
			t.Fatalf("request paths were not delivered privately")
		}
		return chromectl.UploadResult{Version: chromectl.UploadVersion, OK: true, Origin: origin, Count: 1, Files: []string{"evidence.pdf"}}, nil
	}
	var stdout, stderr bytes.Buffer
	for name, args := range map[string][]string{
		"missing-human-authorization": {"upload", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--request-stdin"},
		"missing-window":              {"upload", "--tab-id", "2", "--origin", "https://example.com", "--human-authorized", "--request-stdin"},
		"missing-tab":                 {"upload", "--window-id", "1", "--origin", "https://example.com", "--human-authorized", "--request-stdin"},
		"missing-origin":              {"upload", "--window-id", "1", "--tab-id", "2", "--human-authorized", "--request-stdin"},
		"missing-private-request":     {"upload", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--human-authorized"},
	} {
		t.Run(name, func(t *testing.T) {
			called = false
			stdinReader = bytes.NewReader(requestJSON)
			stdout.Reset()
			stderr.Reset()
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("missing gate code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if called {
				t.Fatalf("upload executed with missing gate %s", name)
			}
		})
	}
	stdinReader = bytes.NewReader(requestJSON)
	stdout.Reset()
	stderr.Reset()
	called = false
	authorized := []string{"upload", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--human-authorized", "--request-stdin"}
	if code := run(authorized, &stdout, &stderr); code != 0 {
		t.Fatalf("authorized code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !called || !strings.Contains(stdout.String(), "evidence.pdf") || strings.Contains(stdout.String(), file) || strings.Contains(stderr.String(), file) {
		t.Fatalf("upload output/path boundary failed called=%v stdout=%q stderr=%q", called, stdout.String(), stderr.String())
	}
}

func TestUploadProductionEntryDoesNotReflectPrivateUnknownFieldNames(t *testing.T) {
	const privateMarker = "/private/task/private-upload-source.pdf"
	oldInput, oldUpload := stdinReader, uploadChromeFiles
	defer func() { stdinReader, uploadChromeFiles = oldInput, oldUpload }()
	called := false
	uploadChromeFiles = func(context.Context, string, string, string, chromectl.UploadRequest) (chromectl.UploadResult, error) {
		called = true
		return chromectl.UploadResult{}, nil
	}
	stdinReader = strings.NewReader(`{"version":1,"inputSelector":"#file","paths":["/tmp/evidence.pdf"],"allowedExtensions":[".pdf"],"maxFileBytes":1024,"maxTotalBytes":1024,"` + privateMarker + `":true}`)
	var stdout, stderr bytes.Buffer
	args := []string{"upload", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--human-authorized", "--request-stdin"}
	if code := run(args, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown private field code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("malformed private request reached upload execution")
	}
	if strings.Contains(stdout.String(), privateMarker) || strings.Contains(stderr.String(), privateMarker) {
		t.Fatalf("private request field was reflected: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestFocusProductionEntryRequiresHumanAuthorizationAndOriginBeforeExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()
	for name, args := range map[string][]string{
		"missing-authorization": {"focus", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com"},
		"missing-origin":        {"focus", "--window-id", "11", "--tab-id", "22", "--human-authorized"},
		"missing-tab":           {"focus", "--window-id", "11", "--origin", "https://example.com", "--human-authorized"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("unauthorized or unguarded focus reached osascript: %v", err)
	}
}

func TestFocusProductionEntryRejectsNonExactTargetBeforeExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()

	for name, target := range map[string][3]string{
		"non-canonical-window": {"01", "22", "https://example.com"},
		"non-numeric-tab":      {"11", "tab", "https://example.com"},
		"origin-with-path":     {"11", "22", "https://example.com/path"},
		"origin-with-query":    {"11", "22", "https://example.com?drift=1"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := []string{"focus", "--window-id", target[0], "--tab-id", target[1], "--origin", target[2], "--human-authorized"}
			if code := run(args, &stdout, &stderr); code != 1 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("non-exact target reached osascript: %v", err)
	}
}

func TestFocusProductionEntryUsesExactOriginGuardAndVerifiedEnvelope(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "osascript")
	body := `#!/bin/sh
printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"ok","origin":"https://example.com","title":"Example page","active":true}'
`
	if err := os.WriteFile(fake, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session {
		return chromectl.Session{
			OsaScriptPath: fake,
		}
	}
	defer func() { newChromeSession = oldNew }()
	var stdout, stderr bytes.Buffer
	args := []string{"focus", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--human-authorized"}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{"focused-window-id: 11", "focused-tab-id: 22", "origin: https://example.com"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("focus output missing %q: %s", want, stdout.String())
		}
	}
}

func TestTrustedInputProductionEntryRequiresAllAuthorizationGatesBeforeExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	oldInput := stdinReader
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() {
		newChromeSession = oldNew
		stdinReader = oldInput
	}()
	request := `{"version":1,"inputSelector":"input[type=search]","text":"safe test"}`
	for name, args := range map[string][]string{
		"missing-human-authorization": {"trusted-input", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--request-stdin"},
		"missing-origin":              {"trusted-input", "--window-id", "11", "--tab-id", "22", "--human-authorized", "--request-stdin"},
		"missing-request-stdin":       {"trusted-input", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--human-authorized"},
	} {
		t.Run(name, func(t *testing.T) {
			stdinReader = strings.NewReader(request)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("missing trusted-input gate reached osascript: %v", err)
	}
}

func TestTrustedInputProductionEntryEmitsOnlyBoundedAttestation(t *testing.T) {
	const text = "non-secret test text"
	const option = "Named option"
	fake := filepath.Join(t.TempDir(), "osascript")
	pressMarker := filepath.Join(t.TempDir(), "pressed")
	t.Setenv("PRESS_MARKER", pressMarker)
	body := `#!/bin/sh
case "$*" in
  *chrome-exact-target*)
    printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"ok","origin":"https://example.com","title":"Example page","active":true}'
    ;;
  *)
    source=$(cat)
    case "$source" in
      *oldInputAria*) value='ready' ;;
      *trustedOptionClick*)
        if [ -f "$PRESS_MARKER" ]; then value='{"outcome":"selected"}'; else value='{"outcome":"option-ready"}'; fi
        ;;
      *) value='cleaned' ;;
    esac
    guard=$(/usr/bin/jq -cn --arg v "$value" '{__macBrowserSessionGuard:"works.relux.mac-infra/browser-session-guard/v1",outcome:"ok",origin:"https://example.com",readyState:"complete",value:$v}')
    /usr/bin/jq -cn --arg v "$guard" '{__macChromePrivateTransport:"works.relux.mac-infra/chrome-private-transport/v1",outcome:"ok",value:$v}'
    ;;
esac
`
	if err := os.WriteFile(fake, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	oldInput := stdinReader
	newChromeSession = func() chromectl.Session {
		return chromectl.Session{
			OsaScriptPath: fake,
			AXProcessID:   func() (int, error) { return 123, nil },
			AXTypeText:    func(pid int, description, value string) error { return nil },
			AXPress: func(pid int, description string) error {
				return os.WriteFile(pressMarker, nil, 0o600)
			},
		}
	}
	stdinReader = strings.NewReader(`{"version":1,"inputSelector":"input[type=search]","text":"` + text + `","optionSelector":"[role=option]","optionText":"` + option + `","timeoutMs":1000}`)
	defer func() {
		newChromeSession = oldNew
		stdinReader = oldInput
	}()
	var stdout, stderr bytes.Buffer
	args := []string{"trusted-input", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--human-authorized", "--request-stdin"}
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), text) || strings.Contains(stdout.String(), option) || strings.Contains(stderr.String(), text) || strings.Contains(stderr.String(), option) {
		t.Fatalf("trusted-input output leaked supplied values: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	for _, want := range []string{`"version": 1`, `"ok": true`, `"origin": "https://example.com"`, `"typed": true`, `"selected": true`} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("attestation missing %q: %s", want, stdout.String())
		}
	}
}

func TestTrustedInputProductionEntryRejectsMalformedAndDriftedEvidenceWithoutValues(t *testing.T) {
	const text = "private field value"
	for name, body := range map[string]string{
		"drifted": `#!/bin/sh
printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"origin-mismatch","origin":"https://drift.example"}'
`,
		"unexpected-page-attestation": `#!/bin/sh
case "$*" in
  *chrome-exact-target*) printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"ok","origin":"https://example.com","title":"Example page","active":true}' ;;
  *) cat >/dev/null; printf '%s\n' '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"selected"}' ;;
esac
`,
		"malformed": `#!/bin/sh
printf '%s\n' '{}'
`,
	} {
		t.Run(name, func(t *testing.T) {
			fake := filepath.Join(t.TempDir(), "osascript")
			if err := os.WriteFile(fake, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			oldNew := newChromeSession
			oldInput := stdinReader
			newChromeSession = func() chromectl.Session {
				return chromectl.Session{
					OsaScriptPath: fake,
					AXProcessID:   func() (int, error) { return 123, nil },
					AXTypeText:    func(int, string, string) error { return nil },
					AXPress:       func(int, string) error { return nil },
				}
			}
			stdinReader = strings.NewReader(`{"version":1,"inputSelector":"input","text":"` + text + `","timeoutMs":1000}`)
			defer func() {
				newChromeSession = oldNew
				stdinReader = oldInput
			}()
			var stdout, stderr bytes.Buffer
			args := []string{"trusted-input", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--human-authorized", "--request-stdin"}
			if code := run(args, &stdout, &stderr); code != 1 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || strings.Contains(stderr.String(), text) {
				t.Fatalf("refusal leaked field value: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestRunJSHelpDocumentsScriptFileAndPrivateOutputParity(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run-js", "--help"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d want=2 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{"-script string", "-file string", "-out string", "atomically", "0600", "instead of stdout"} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("run-js help missing %q:\n%s", want, stderr.String())
		}
	}
}

func TestRunJSProductionEntryWritesPrivateAtomicOutputForScriptAndFileWithoutPayloadOnStdout(t *testing.T) {
	const pageResult = "private-page-result"
	result := `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"` + pageResult + `"}`
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '"+result+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()

	scriptFile := filepath.Join(t.TempDir(), "read.js")
	if err := os.WriteFile(scriptFile, []byte("document.readyState"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		input    []string
		existing bool
	}{
		{name: "script-replaces-existing", input: []string{"--script", "document.readyState"}, existing: true},
		{name: "file-creates-parent", input: []string{"--file", scriptFile}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "nested", "result.txt")
			if tc.existing {
				if err := os.MkdirAll(filepath.Dir(outPath), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(outPath, []byte("old-result\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			args := []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com"}
			args = append(args, tc.input...)
			args = append(args, "--out", outPath)
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 0 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if strings.Contains(stdout.String(), pageResult) || stdout.String() != "out: "+outPath+"\n" {
				t.Fatalf("stdout duplicated page payload or omitted artifact path: %q", stdout.String())
			}
			data, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(data), pageResult+"\n"; got != want {
				t.Fatalf("artifact=%q want=%q", got, want)
			}
			info, err := os.Stat(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Fatalf("artifact mode=%#o want=0600", got)
			}
			entries, err := os.ReadDir(filepath.Dir(outPath))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || entries[0].Name() != filepath.Base(outPath) {
				t.Fatalf("temporary output was not cleaned up: %v", entries)
			}
		})
	}
}

func TestRunJSProductionEntryFailsClosedOnMissingInvalidAndUnwritableOutput(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	oldPrepare := prepareRunJSOutput
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() {
		newChromeSession = oldNew
		prepareRunJSOutput = oldPrepare
	}()
	base := []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--script", "document.readyState"}
	directoryTarget := t.TempDir()
	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "missing-value", args: append(append([]string{}, base...), "--out"), code: 2},
		{name: "blank-path", args: append(append([]string{}, base...), "--out", "  "), code: 2},
		{name: "directory-target", args: append(append([]string{}, base...), "--out", directoryTarget), code: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, &stdout, &stderr); code != tc.code {
				t.Fatalf("code=%d want=%d stdout=%s stderr=%s", code, tc.code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("failed output path leaked stdout: %q", stdout.String())
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("failed output path dispatched page JavaScript; marker err=%v", err)
			}
		})
	}

	prepareRunJSOutput = func(string) (runJSOutputArtifact, error) {
		return nil, errors.New("permission denied")
	}
	var stdout, stderr bytes.Buffer
	if code := run(append(append([]string{}, base...), "--out", filepath.Join(t.TempDir(), "result.txt")), &stdout, &stderr); code != 1 {
		t.Fatalf("unwritable code=%d want=1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "prepare output: permission denied") {
		t.Fatalf("unwritable path did not fail closed: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("unwritable output dispatched page JavaScript; marker err=%v", err)
	}
}

type failingRunJSOutputArtifact struct{}

func (failingRunJSOutputArtifact) Commit(string) error { return errors.New("publish denied") }
func (failingRunJSOutputArtifact) Abort()              {}

func TestRunJSProductionEntryDoesNotFallbackToStdoutWhenAtomicPublishFails(t *testing.T) {
	const pageResult = "private-page-result"
	result := `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"` + pageResult + `"}`
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '"+result+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	oldPrepare := prepareRunJSOutput
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	prepareRunJSOutput = func(string) (runJSOutputArtifact, error) { return failingRunJSOutputArtifact{}, nil }
	defer func() {
		newChromeSession = oldNew
		prepareRunJSOutput = oldPrepare
	}()
	var stdout, stderr bytes.Buffer
	args := []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--script", "document.readyState", "--out", filepath.Join(t.TempDir(), "result.txt")}
	if code := run(args, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d want=1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), pageResult) || stdout.Len() != 0 {
		t.Fatalf("publish failure leaked page result to stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "write output: publish denied") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}

func TestSlackReadProductionEntryRejectsWritesAndInvalidGuardsBeforeExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	oldInput := stdinReader
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() {
		newChromeSession = oldNew
		stdinReader = oldInput
	}()
	cases := []struct {
		name      string
		origin    string
		workspace string
		request   string
		kind      string
		code      int
	}{
		{name: "write", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"chat.postMessage","args":{}}`, kind: "method-not-allowed", code: 2},
		{name: "unknown-method", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"admin.users.list","args":{}}`, kind: "method-not-allowed", code: 2},
		{name: "unknown-argument", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"users.list","args":{"token":"forged"}}`, kind: "invalid-arguments", code: 2},
		{name: "out-of-range-pagination", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"conversations.history","args":{"channel":"C12345678","limit":101}}`, kind: "invalid-arguments", code: 2},
		{name: "invalid-conversation-id", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"conversations.info","args":{"channel":"general"}}`, kind: "invalid-arguments", code: 2},
		{name: "invalid-timestamp", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"conversations.replies","args":{"channel":"C12345678","ts":"yesterday"}}`, kind: "invalid-arguments", code: 2},
		{name: "secret-shaped-argument", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"search.messages","args":{"query":"Bearer abcdefghijklmnop"}}`, kind: "invalid-arguments", code: 2},
		{name: "cross-workspace-team", origin: chromectl.SlackOrigin, workspace: "T073GL82HJB", request: `{"version":1,"method":"users.list","args":{"team_id":"T12345678"}}`, kind: "invalid-arguments", code: 1},
		{name: "wrong-origin", origin: "https://evil.example", workspace: "T073GL82HJB", request: `{"version":1,"method":"auth.test","args":{}}`, kind: "invalid-origin", code: 1},
		{name: "invalid-workspace", origin: chromectl.SlackOrigin, workspace: "../T073GL82HJB", request: `{"version":1,"method":"auth.test","args":{}}`, kind: "invalid-workspace", code: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdinReader = strings.NewReader(tc.request)
			var stdout, stderr bytes.Buffer
			args := []string{"slack-read", "--window-id", "1", "--tab-id", "2", "--origin", tc.origin, "--workspace-id", tc.workspace, "--request-stdin"}
			if code := run(args, &stdout, &stderr); code != tc.code {
				t.Fatalf("code=%d want=%d stdout=%s stderr=%s", code, tc.code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), `"ok": false`) || !strings.Contains(stdout.String(), `"kind": "`+tc.kind+`"`) {
				t.Fatalf("stable refusal missing %q: %s", tc.kind, stdout.String())
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("refused Slack input reached osascript; marker err=%v", err)
	}
}

func TestSlackReadProductionEntryEmitsVersionedSanitizedEnvelope(t *testing.T) {
	response := `{"ok":true,"token":"composite xoxc-12345678-secret value","message":"REF-SYN-4242 before xoxc-12345678-secret middle Bearer abcdefghijklmnop after","xoxb-87654321-keyvalue":{"Bearer zyxwvutsrqponmlk":"ordinary"}}`
	code, stdout, stderr := runSlackReadResponse(t, response)
	if code != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{`"version": 1`, `"ok": true`, `"method": "auth.test"`, `"token": "[redacted]"`, `"message": "REF-SYN-4242 before [redacted] middle [redacted] after"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("output missing %q: %s", want, stdout)
		}
	}
	if strings.Count(stdout, `"[redacted]"`) < 3 {
		t.Fatalf("sanitized object keys missing from production envelope: %s", stdout)
	}
	for _, forbidden := range []string{"xoxc-", "xoxb-", "Bearer "} {
		if strings.Contains(stdout, forbidden) {
			t.Fatalf("secret-shaped bytes %q leaked from production output: %s", forbidden, stdout)
		}
	}
}

func TestSlackReadProductionEntryFailsClosedOnKeyCollisionWithoutLeakingKeys(t *testing.T) {
	const secretKey = "xoxb-87654321-keyvalue"
	response := `{"` + secretKey + `":"secret-shaped","[redacted]":"safe-original"}`
	code, stdout, stderr := runSlackReadResponse(t, response)
	if code != 1 {
		t.Fatalf("code=%d want=1 stdout=%s stderr=%s", code, stdout, stderr)
	}
	for _, want := range []string{`"version": 1`, `"ok": false`, `"kind": "response-key-collision"`, `"message": "Slack response was refused by the bounded output policy"`} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("collision envelope missing %q: %s", want, stdout)
		}
	}
	if strings.Contains(stdout, secretKey) || strings.Contains(stdout, "safe-original") {
		t.Fatalf("collision envelope leaked response material: %s", stdout)
	}
}

func TestSlackReadProductionEntryFailsClosedOnDuplicateMembersWithoutLeakingResponseMaterial(t *testing.T) {
	const secretKey = "xoxb-87654321-keyvalue"
	cases := []struct {
		name      string
		response  string
		kind      string
		forbidden []string
	}{
		{
			name:      "identical-secret-shaped-key",
			response:  `{"` + secretKey + `":"first-value","` + secretKey + `":"second-value"}`,
			kind:      "response-key-collision",
			forbidden: []string{secretKey, "first-value", "second-value"},
		},
		{
			name:      "equivalent-escaped-key",
			response:  `{"` + secretKey + `":"literal","xoxb-87654321-\u006beyvalue":"escaped"}`,
			kind:      "response-key-collision",
			forbidden: []string{secretKey, "literal", "escaped"},
		},
		{
			name:     "raw-node-bound",
			response: `{` + strings.TrimSuffix(strings.Repeat(`"a":0,`, 20_001), ",") + `}`,
			kind:     "response-too-complex",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.response) > chromectl.MaxSlackResponseBytes {
				t.Fatalf("response bytes = %d, exceeds %d-byte response ceiling", len(tc.response), chromectl.MaxSlackResponseBytes)
			}
			code, stdout, stderr := runSlackReadResponse(t, tc.response)
			if code != 1 {
				t.Fatalf("code=%d want=1 stdout=%s stderr=%s", code, stdout, stderr)
			}
			for _, want := range []string{`"version": 1`, `"ok": false`, `"kind": "` + tc.kind + `"`, `"message": "Slack response was refused by the bounded output policy"`} {
				if !strings.Contains(stdout, want) {
					t.Fatalf("refusal envelope missing %q: %s", want, stdout)
				}
			}
			for _, forbidden := range tc.forbidden {
				if strings.Contains(stdout, forbidden) {
					t.Fatalf("refusal envelope leaked response material %q: %s", forbidden, stdout)
				}
			}
		})
	}
}

func runSlackReadResponse(t *testing.T, response string) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	startData, err := json.Marshal(map[string]any{"__macSlackSealedRead": "works.relux.mac-infra/slack-sealed-read/v1", "outcome": "started"})
	if err != nil {
		t.Fatal(err)
	}
	pollData, err := json.Marshal(map[string]any{"__macSlackSealedRead": "works.relux.mac-infra/slack-sealed-read/v1", "outcome": "ok", "response": response})
	if err != nil {
		t.Fatal(err)
	}
	startPath := filepath.Join(dir, "start")
	pollPath := filepath.Join(dir, "poll")
	if err := os.WriteFile(startPath, append(startData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pollPath, append(pollData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "osascript")
	script := "#!/bin/sh\nset -eu\nsource=$(cat)\ncase \"$source\" in\n  *localConfig_v2*) /bin/cat \"" + startPath + "\" ;;\n  *) /bin/cat \"" + pollPath + "\" ;;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	oldInput := stdinReader
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	stdinReader = strings.NewReader(`{"version":1,"method":"auth.test","args":{}}`)
	defer func() {
		newChromeSession = oldNew
		stdinReader = oldInput
	}()
	var stdout, stderr bytes.Buffer
	args := []string{"slack-read", "--window-id", "1", "--tab-id", "2", "--origin", chromectl.SlackOrigin, "--workspace-id", "T073GL82HJB", "--request-stdin"}
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunJSProductionEntryRejectsSecretScriptAndFileWithoutExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()
	secretFile := filepath.Join(t.TempDir(), "secret.js")
	if err := os.WriteFile(secretFile, []byte("navigator.credentials.get({})"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args    []string
		outPath string
	}{
		{args: []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--script", "document.cookie"}, outPath: filepath.Join(t.TempDir(), "script-result.txt")},
		{args: []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--file", secretFile}, outPath: filepath.Join(t.TempDir(), "file-result.txt")},
	}
	for _, tc := range cases {
		var stdout, stderr bytes.Buffer
		args := append(tc.args, "--out", tc.outPath)
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Fatalf("run(%v) unexpectedly passed", args)
		}
		if !strings.Contains(stderr.String(), "blocked token") {
			t.Fatalf("stderr missing secret refusal: %s", stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("secret refusal leaked stdout: %q", stdout.String())
		}
		if _, err := os.Stat(tc.outPath); !os.IsNotExist(err) {
			t.Fatalf("secret refusal published output artifact; err=%v", err)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("secret payload reached osascript; marker err=%v", err)
	}
}

func TestRunJSProductionEntryDoesNotPublishOutputOnOriginRefusal(t *testing.T) {
	result := `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"origin-mismatch","origin":"https://drifted.example"}`
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '"+result+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()
	outPath := filepath.Join(t.TempDir(), "result.txt")
	var stdout, stderr bytes.Buffer
	args := []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://expected.example", "--script", "document.readyState", "--out", outPath}
	if code := run(args, &stdout, &stderr); code != 1 {
		t.Fatalf("code=%d want=1 stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "browser target origin changed") {
		t.Fatalf("origin refusal was not fail-closed: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("origin refusal published output artifact; err=%v", err)
	}
}

func TestRunJSProductionEntryCoversEveryBlockedToken(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()
	blockedTokens := []string{
		"document.cookie",
		"cookiestore",
		"localstorage",
		"sessionstorage",
		"indexeddb",
		"navigator.credentials",
		"opendatabase",
	}
	for _, token := range blockedTokens {
		var stdout, stderr bytes.Buffer
		args := []string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--script", "void " + token}
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Fatalf("production run-js admitted blocked token %q", token)
		}
		if !strings.Contains(stderr.String(), token) {
			t.Fatalf("refusal for %q was not specific: %s", token, stderr.String())
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a blocked token reached osascript; marker err=%v", err)
	}
}

func TestRunJSWithoutOriginSaysItIsUnguarded(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "osascript")
	result := `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"complete"}`
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '"+result+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
	defer func() { newChromeSession = oldNew }()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run-js", "--window-id", "1", "--tab-id", "2", "--script", "document.readyState"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "guard: unguarded") {
		t.Fatalf("unguarded call not disclosed: %s", stderr.String())
	}
}

func TestRunJSRequiresExactIDsAndOneScriptSource(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"run-js", "--script", "document.title"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "--window-id") || !strings.Contains(stderr.String(), "--tab-id") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestHeartbeatStartRequiresBrowserOriginAndSafariRejectsTabID(t *testing.T) {
	for name, args := range map[string][]string{
		"missing-origin": {"heartbeat", "start", "--name", "test", "--browser", "safari", "--window-id", "1", "--ttl", "1h"},
		"safari-tab":     {"heartbeat", "start", "--name", "test", "--browser", "safari", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--ttl", "1h"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestHeartbeatStartProductionEntryRequiresFiniteDeadline(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"heartbeat", "start", "--name", "deadline-gate", "--browser", "chrome", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "exactly one of a positive --ttl or --deadline") {
		t.Fatalf("missing deadline code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestHeartbeatLifecycleTimeoutPreservesSerializedAppleEventBudget(t *testing.T) {
	if heartbeatLifecycleTimeout != 11*time.Minute {
		t.Fatalf("heartbeat lifecycle timeout = %s, want 11m", heartbeatLifecycleTimeout)
	}
}

func TestListReportsPositionalArgumentError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"list", "unexpected"}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stderr.String(), "does not accept positional") {
		t.Fatalf("stderr=%q", stderr.String())
	}
}
