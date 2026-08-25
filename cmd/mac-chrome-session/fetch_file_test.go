package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/chromectl"
)

func TestFetchFileProductionEntrySupportsSequentialAtomicDownloadsWithoutLeakingResourceURLs(t *testing.T) {
	dir := t.TempDir()
	argvPath := filepath.Join(dir, "argv")
	statePath := filepath.Join(dir, "state")
	t.Setenv("ARGV_PATH", argvPath)
	t.Setenv("STATE_PATH", statePath)
	osa := writeFetchFileCLIExecutable(t, `
source=$(cat)
printf '%s\n' "$*" >> "$ARGV_PATH"
case "$source" in *https://example.com*) ;; *) printf 'origin guard missing\n' >&2; exit 98 ;; esac
case "$source" in
  *first-cli-fake-token*) printf 'one' > "$STATE_PATH"; value='started' ;;
  *second-cli-fake-token*) printf 'two' > "$STATE_PATH"; value='started' ;;
  *contentType:String*) value='{"state":"done","status":200,"bytes":3,"chunkCount":1,"contentType":"application/pdf"}' ;;
  *job.chunks*)
    state=$(cat "$STATE_PATH")
    if [ "$state" = one ]; then value='{"state":"chunk","index":0,"data":"b25l"}'; else value='{"state":"chunk","index":0,"data":"dHdv"}'; fi
    ;;
  *different-job*) value='cleared' ;;
  *) value='unknown' ;;
esac
emit_value "$value"
`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()

	for _, tc := range []struct {
		resource string
		want     string
		name     string
	}{
		{resource: "/first?token=first-cli-fake-token", want: "one", name: "first.pdf"},
		{resource: "https://example.com/second?signature=second-cli-fake-token", want: "two", name: "second.pdf"},
	} {
		outPath := filepath.Join(dir, tc.name)
		var stdout, stderr bytes.Buffer
		restoreStdin := withFetchFileStdin(t, tc.resource, 16, 60000)
		args := []string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}
		code := run(args, &stdout, &stderr)
		restoreStdin()
		if code != 0 {
			t.Fatalf("run(%s) code=%d stdout=%s stderr=%s", tc.name, code, stdout.String(), stderr.String())
		}
		data, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != tc.want {
			t.Fatalf("%s data=%q want=%q", tc.name, data, tc.want)
		}
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode=%#o want=0600", tc.name, info.Mode().Perm())
		}
		combined := stdout.String() + stderr.String()
		if !strings.Contains(stdout.String(), "saved: "+outPath) || !strings.Contains(stdout.String(), "bytes: 3") || !strings.Contains(stdout.String(), "status: 200") {
			t.Fatalf("sanitized metadata missing: stdout=%q", stdout.String())
		}
		for _, forbidden := range []string{tc.resource, "first-cli-fake-token", "second-cli-fake-token", "authorization", "cookie"} {
			if strings.Contains(strings.ToLower(combined), strings.ToLower(forbidden)) {
				t.Fatalf("fetch-file output leaked %q: %q", forbidden, combined)
			}
		}
	}
	argv, err := os.ReadFile(argvPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"first-cli-fake-token", "second-cli-fake-token", "example.com/first", "example.com/second"} {
		if strings.Contains(string(argv), forbidden) {
			t.Fatalf("production fetch-file put resource in osascript argv: %q", argv)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mac-chrome-session-run-js-") {
			t.Fatalf("atomic temporary output was left behind: %s", entry.Name())
		}
	}
}

func TestFetchFileProductionEntryRefusesUnsafeURLBeforeBrowserExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	osa := writeFetchFileCLIExecutable(t, `touch "$MARKER"; exit 99`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()
	for name, resource := range map[string]string{
		"cross-origin":   "https://other.example/document",
		"suffix-host":    "https://com/document",
		"host-substring": "https://notexample.com/document",
		"port-drift":     "https://example.com:8443/document",
		"credential":     "https://user:pass@example.com/document",
		"fragment":       "/document#fake-secret",
		"unsafe-scheme":  "javascript:alert(1)",
	} {
		t.Run(name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "result.bin")
			var stdout, stderr bytes.Buffer
			restoreStdin := withFetchFileStdin(t, resource, 0, 0)
			args := []string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}
			code := run(args, &stdout, &stderr)
			restoreStdin()
			if code != 1 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if stdout.Len() != 0 || strings.Contains(stderr.String(), resource) {
				t.Fatalf("unsafe URL refusal leaked input: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("unsafe URL published output: %v", err)
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("unsafe URL reached browser production call: %v", err)
	}
}

func TestFetchFileProductionEntryPreservesExistingOutputOnOriginTargetSizeAndTimeoutRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want string
	}{
		"origin-drift": {body: `cat >/dev/null; emit_guard '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"origin-mismatch","origin":"https://drift.example"}'`, want: "browser target origin changed"},
		"target-loss":  {body: `cat >/dev/null; seal_outcome tab-missing`, want: "browser target is no longer available"},
		"size-limit":   {body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then value='{"state":"error","kind":"size-limit"}'; else value='started'; fi; emit_value "$value"`, want: "configured size limit"},
		"timeout":      {body: `source=$(cat); if printf '%s' "$source" | grep -q 'contentType:String'; then value='{"state":"running"}'; else value='started'; fi; emit_value "$value"`, want: "configured timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			osa := writeFetchFileCLIExecutable(t, tc.body)
			oldNew := newChromeSession
			newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
			defer func() { newChromeSession = oldNew }()
			outPath := filepath.Join(t.TempDir(), "result.bin")
			if err := os.WriteFile(outPath, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			timeoutMS := 60000
			if name == "timeout" {
				timeoutMS = 500
			}
			restoreStdin := withFetchFileStdin(t, "/document", 3, timeoutMS)
			args := []string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}
			code := run(args, &stdout, &stderr)
			restoreStdin()
			if code != 1 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			data, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "old" || stdout.Len() != 0 {
				t.Fatalf("refusal changed output or emitted success: data=%q stdout=%q stderr=%q", data, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("refusal kind was not preserved: want=%q stderr=%q", tc.want, stderr.String())
			}
		})
	}
}

func writeFetchFileCLIExecutable(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+fetchFileCLIPrelude+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// withFetchFileStdin installs one bounded versioned fetch-file envelope on the
// production stdin reader used by runFetchFile, and returns a restore func.
func withFetchFileStdin(t *testing.T, resource string, maxBytes int64, timeoutMS int) func() {
	t.Helper()
	envelope := map[string]any{"version": chromectl.FetchFileVersion, "resource": resource}
	if maxBytes != 0 {
		envelope["maxBytes"] = maxBytes
	}
	if timeoutMS != 0 {
		envelope["timeoutMs"] = timeoutMS
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	previous := stdinReader
	stdinReader = bytes.NewReader(encoded)
	return func() { stdinReader = previous }
}

// TestFetchFileProductionEntryRefusesMalformedStdinEnvelopes attacks the repaired
// private input path itself: every envelope below must fail closed at
// runFetchFile before prepareRunJSOutput or any browser call, and no refusal may
// echo the envelope content.
func TestFetchFileProductionEntryRefusesMalformedStdinEnvelopes(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	osa := writeFetchFileCLIExecutable(t, `touch "$MARKER"; exit 99`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()
	for name, tc := range map[string]struct {
		body string
		code int
	}{
		"empty":              {body: "", code: 2},
		"blank":              {body: "   \n", code: 2},
		"not-json":           {body: "/document?documentId=raw-fake-token", code: 2},
		"missing-version":    {body: `{"resource":"/document"}`, code: 2},
		"wrong-version":      {body: `{"version":2,"resource":"/document"}`, code: 2},
		"unknown-field":      {body: `{"version":1,"resource":"/document","cookie":"cookie-fake-token"}`, code: 2},
		"trailing-envelope":  {body: `{"version":1,"resource":"/a"}{"version":1,"resource":"/b?documentId=trailing-fake-token"}`, code: 2},
		"oversized-envelope": {body: `{"version":1,"resource":"/` + strings.Repeat("a", 9000) + `"}`, code: 2},
		"oversized-resource": {body: `{"version":1,"resource":"/` + strings.Repeat("b", 5000) + `"}`, code: 2},
		"negative-timeout":   {body: `{"version":1,"resource":"/document","timeoutMs":-1}`, code: 2},
		"timeout-too-long":   {body: `{"version":1,"resource":"/document","timeoutMs":600000}`, code: 2},
		"empty-resource":     {body: `{"version":1,"resource":""}`, code: 1},
		"cross-origin":       {body: `{"version":1,"resource":"https://other.example/document"}`, code: 1},
		"newline-injection":  {body: `{"version":1,"resource":"/document\nsecond?documentId=nl-fake-token"}`, code: 1},
		"max-bytes-too-big":  {body: `{"version":1,"resource":"/document","maxBytes":1099511627776}`, code: 1},
		"max-bytes-negative": {body: `{"version":1,"resource":"/document","maxBytes":-1}`, code: 1},
	} {
		t.Run(name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "result.bin")
			previous := stdinReader
			stdinReader = strings.NewReader(tc.body)
			var stdout, stderr bytes.Buffer
			code := run([]string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}, &stdout, &stderr)
			stdinReader = previous
			if code != tc.code {
				t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, tc.code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, "fake-token") || strings.Contains(combined, strings.Repeat("a", 64)) || strings.Contains(combined, strings.Repeat("b", 64)) {
				t.Fatalf("refusal echoed envelope content: %q", combined)
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("refused envelope published output: %v", err)
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("a refused envelope reached the browser production call: %v", err)
	}
}

// TestFetchFileProductionEntryRequiresRequestStdin proves the private input path
// is mandatory: without --request-stdin the command must refuse rather than fall
// back to any argv-carried resource.
func TestFetchFileProductionEntryRequiresRequestStdin(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "result.bin")
	previous := stdinReader
	stdinReader = strings.NewReader(`{"version":1,"resource":"/document"}`)
	defer func() { stdinReader = previous }()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath}, &stdout, &stderr); code != 2 {
		t.Fatalf("code=%d want=2 stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(outPath); !os.IsNotExist(err) {
		t.Fatalf("refused invocation published output: %v", err)
	}
}

// fetchFileCLIPrelude teaches every fake osascript the sealed private-transport
// envelope. The production sealed transport classifies target loss only from
// this sentinel envelope and never from child stdout or stderr text.
const fetchFileCLIPrelude = `__PRIVATE_SENTINEL='works.relux.mac-infra/chrome-private-transport/v1'
__GUARD_SENTINEL='works.relux.mac-infra/browser-session-guard/v1'
seal_outcome() { /usr/bin/jq -cn --arg s "$__PRIVATE_SENTINEL" --arg o "$1" --arg v "${2-}" '{__macChromePrivateTransport:$s,outcome:$o,value:$v}'; }
guard_value() { /usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg org "${2-https://example.com}" --arg v "$1" '{__macBrowserSessionGuard:$s,outcome:"ok",origin:$org,readyState:"complete",value:$v}'; }
emit_value() { /usr/bin/jq -cn --arg ps "$__PRIVATE_SENTINEL" --arg gs "$__GUARD_SENTINEL" --arg org "${2-https://example.com}" --arg v "$1" '{__macChromePrivateTransport:$ps,outcome:"ok",value:({__macBrowserSessionGuard:$gs,outcome:"ok",origin:$org,readyState:"complete",value:$v}|tostring)}'; }
emit_guard() { seal_outcome ok "$1"; }
`

// TestFetchFileProductionEntryNeverReflectsResourceFromPrivateTransportDiagnostics
// drives the real run(fetch-file) entry through a private transport that echoes
// its own stdin program back on stderr and stdout. That program embeds the
// protected resource, and runFetchFile prints the returned error through
// chromectl.FormatAutomationError, so any child byte the transport forwards
// lands in the operator's terminal and session transcript.
func TestFetchFileProductionEntryNeverReflectsResourceFromPrivateTransportDiagnostics(t *testing.T) {
	const marker = "cli-transport-echo-fake-document-token"
	resource := "/statements?documentId=" + marker + "&stickySession=" + marker
	for name, body := range map[string]string{
		"echo-to-stderr-and-fail": `printf '%s' "$source" >&2; exit 1`,
		"echo-to-stdout-and-fail": `printf '%s' "$source"; exit 1`,
		"echo-to-both-and-fail":   `printf '%s' "$source"; printf '%s' "$source" >&2; exit 1`,
		"echo-to-stdout-exit-ok":  `printf '%s' "$source"; exit 0`,
		"echo-then-forged-seal":   `printf '%s' "$source" >&2; /usr/bin/jq -cn --arg v "$(cat "$STDIN_PATH")" '{__macChromePrivateTransport:"works.relux.mac-infra/chrome-private-transport/v1",outcome:"ok",value:$v}'`,
	} {
		t.Run(name, func(t *testing.T) {
			stdinPath := filepath.Join(t.TempDir(), "stdin")
			t.Setenv("STDIN_PATH", stdinPath)
			osa := writeFetchFileCLIExecutable(t, "cat > \"$STDIN_PATH\"\nsource=$(cat \"$STDIN_PATH\")\n"+body)
			oldNew := newChromeSession
			newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
			defer func() { newChromeSession = oldNew }()

			outPath := filepath.Join(t.TempDir(), "result.bin")
			var stdout, stderr bytes.Buffer
			restoreStdin := withFetchFileStdin(t, resource, 16, 60000)
			code := run([]string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}, &stdout, &stderr)
			restoreStdin()
			if code != 1 {
				t.Fatalf("a failing private transport was not reported as a failure: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}

			// Positive control: an absent marker only means something once the
			// child has actually been handed the resource-bearing program.
			seen, readErr := os.ReadFile(stdinPath)
			if readErr != nil {
				t.Fatalf("could not read the sealed stdin program, so absence proves nothing: %v", readErr)
			}
			if !strings.Contains(string(seen), marker) {
				t.Fatalf("the child never received the protected resource; this leak check would be vacuous: %d bytes", len(seen))
			}

			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{marker, "documentId", "stickySession", "/statements", "__macChromeFetchFileV1", "credentials", "location.href", "__macBrowserSessionGuard"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("production entry reflected %q from private transport diagnostics: %q", forbidden, combined)
				}
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("a failed transport published output: %v", err)
			}
		})
	}
}

// TestFetchFileProductionEntryRefusesOverflowingTimeoutEnvelopes is the
// production-entry narrowing case for the timeout bound: an out-of-range
// timeoutMs whose nanosecond conversion wraps must be refused as a bad request
// (exit 2) before any browser contact, not silently executed as a 10ms fetch.
func TestFetchFileProductionEntryRefusesOverflowingTimeoutEnvelopes(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	osa := writeFetchFileCLIExecutable(t, `cat >/dev/null; touch "$MARKER"; exit 99`)
	oldNew := newChromeSession
	newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
	defer func() { newChromeSession = oldNew }()
	for name, timeoutMS := range map[string]string{
		"integer-overflow":  "288230376151711754",
		"platform-int-max":  strconv.Itoa(math.MaxInt),
		"one-over-maximum":  "300001",
		"beyond-int64":      "99999999999999999999",
		"negative-overflow": "-288230376151711754",
	} {
		t.Run(name, func(t *testing.T) {
			outPath := filepath.Join(t.TempDir(), "result.bin")
			previous := stdinReader
			stdinReader = strings.NewReader(`{"version":1,"resource":"/document?documentId=timeout-fake-token","timeoutMs":` + timeoutMS + `}`)
			var stdout, stderr bytes.Buffer
			code := run([]string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}, &stdout, &stderr)
			stdinReader = previous
			if code != 2 {
				t.Fatalf("out-of-range timeoutMs=%s was not refused as a bad request: code=%d stdout=%q stderr=%q", timeoutMS, code, stdout.String(), stderr.String())
			}
			combined := stdout.String() + stderr.String()
			if strings.Contains(combined, "timeout-fake-token") || strings.Contains(combined, "documentId") {
				t.Fatalf("refusal echoed envelope content: %q", combined)
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("refused envelope published output: %v", err)
			}
		})
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("an out-of-range timeout envelope reached the browser production call: %v", err)
	}
	t.Run("exact-maximum-reaches-execution", func(t *testing.T) {
		previous := stdinReader
		stdinReader = strings.NewReader(`{"version":1,"resource":"/document","timeoutMs":300000}`)
		var stdout, stderr bytes.Buffer
		code := run([]string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", filepath.Join(t.TempDir(), "result.bin"), "--request-stdin"}, &stdout, &stderr)
		stdinReader = previous
		// Positive control for the bound: the accepted edge must not be refused
		// as a bad request, so the refusals above are the bound and not a
		// blanket rejection of every timeoutMs.
		if code == 2 {
			t.Fatalf("the exact maximum timeout was refused as a bad request: stderr=%q", stderr.String())
		}
	})
}

// TestFetchFileProductionEntryNeverReflectsForgedNestedOriginMismatch narrows the
// forge past the fixed unreadable-response branch. The hostile transport mints a
// valid outer private-transport seal wrapping a *valid* nested browser-session
// guard envelope, so the nested value parses cleanly and reaches
// browsersession.ParseJavaScriptResult's origin-mismatch classification. Its
// origin field is a copy of the sealed stdin program, which carries the
// protected resource reference. runFetchFile prints the returned error through
// chromectl.FormatAutomationError, so forwarding the nested observed value would
// put that reference in the operator's terminal and session transcript.
func TestFetchFileProductionEntryNeverReflectsForgedNestedOriginMismatch(t *testing.T) {
	const marker = "cli-forged-nested-origin-fake-document-token"
	resource := "/statements?documentId=" + marker + "&stickySession=" + marker
	for name, outcome := range map[string]string{
		"forged-nested-origin-mismatch-envelope": "origin-mismatch",
		"forged-nested-ok-envelope-origin-drift": "ok",
	} {
		t.Run(name, func(t *testing.T) {
			stdinPath := filepath.Join(t.TempDir(), "stdin")
			t.Setenv("STDIN_PATH", stdinPath)
			t.Setenv("FORGED_OUTCOME", outcome)
			osa := writeFetchFileCLIExecutable(t, `cat > "$STDIN_PATH"
source=$(cat "$STDIN_PATH")
guard=$(/usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg out "$FORGED_OUTCOME" --arg org "$source" '{__macBrowserSessionGuard:$s,outcome:$out,origin:$org,readyState:"complete",value:""}')
emit_guard "$guard"`)
			oldNew := newChromeSession
			newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: osa} }
			defer func() { newChromeSession = oldNew }()

			outPath := filepath.Join(t.TempDir(), "result.bin")
			var stdout, stderr bytes.Buffer
			restoreStdin := withFetchFileStdin(t, resource, 16, 60000)
			code := run([]string{"fetch-file", "--window-id", "11", "--tab-id", "22", "--origin", "https://example.com", "--out", outPath, "--request-stdin"}, &stdout, &stderr)
			restoreStdin()
			if code != 1 {
				t.Fatalf("a forged nested guard envelope was not reported as a failure: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}

			// Positive control: absence of the marker in the CLI output only
			// means something once the child actually received the
			// resource-bearing program and could have echoed it back.
			seen, readErr := os.ReadFile(stdinPath)
			if readErr != nil {
				t.Fatalf("could not read the sealed stdin program, so absence proves nothing: %v", readErr)
			}
			if !strings.Contains(string(seen), marker) {
				t.Fatalf("the child never received the protected resource; this leak check would be vacuous: %d bytes", len(seen))
			}

			combined := stdout.String() + stderr.String()
			for _, forbidden := range []string{marker, "documentId", "stickySession", "/statements", "__macChromeFetchFileV1", "credentials", "location.href", "__macBrowserSessionGuard"} {
				if strings.Contains(combined, forbidden) {
					t.Fatalf("production entry reflected %q from a forged nested guard envelope: %q", forbidden, combined)
				}
			}
			// The classification must survive the redaction, otherwise a mutant
			// that drops the whole branch would pass this test.
			if !strings.Contains(stderr.String(), "browser target origin changed") {
				t.Fatalf("origin-drift classification was lost: stderr=%q", stderr.String())
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("a forged nested guard envelope published output: %v", err)
			}
		})
	}
}
