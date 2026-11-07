package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/chromectl"
)

func TestRunJSScriptExceptionKeepsExitAndDoesNotPublishOrRetry(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("Node unavailable; generated wrapper execution not exercised")
	}
	for _, message := range []string{"feature turned off", "AppleScript parser failed"} {
		t.Run(message, func(t *testing.T) {
			dir := t.TempDir()
			callsPath := filepath.Join(dir, "calls")
			t.Setenv("CHROME_TEST_CALLS", callsPath)
			fake := filepath.Join(dir, "synthetic-automation")
			// Execute the real generated wrapper against synthetic page state only.
			body := `#!/bin/sh
printf 'call\n' >> "$CHROME_TEST_CALLS"
exec node -e 'globalThis.location={origin:"https://example.com"};globalThis.document={readyState:"complete"};globalThis.__runs=0;console.log(eval(process.argv[1]));if(globalThis.__runs!==1)process.exit(42);' "$5"
`
			if err := os.WriteFile(fake, []byte(body), 0o700); err != nil {
				t.Fatal(err)
			}
			oldNew := newChromeSession
			newChromeSession = func() chromectl.Session { return chromectl.Session{OsaScriptPath: fake} }
			defer func() { newChromeSession = oldNew }()
			outPath := filepath.Join(dir, "result.txt")
			var stdout, stderr bytes.Buffer
			script := fmt.Sprintf(`(() => { ++globalThis.__runs; throw new Error(%q); })()`, message)
			code := run([]string{"run-js", "--window-id", "1", "--tab-id", "2", "--origin", "https://example.com", "--script", script, "--out", outPath}, &stdout, &stderr)
			want := "page JavaScript threw an exception: Error: " + message + "\n"
			if code != 1 || stdout.Len() != 0 || stderr.String() != want {
				t.Fatalf("code=%d stdout=%q stderr=%q want=%q", code, stdout.String(), stderr.String(), want)
			}
			if _, err := os.Stat(outPath); !os.IsNotExist(err) {
				t.Fatalf("failed script published output: %v", err)
			}
			calls, err := os.ReadFile(callsPath)
			if err != nil || strings.Count(string(calls), "call\n") != 1 {
				t.Fatalf("script exception retried: calls=%q err=%v", calls, err)
			}
		})
	}
}
