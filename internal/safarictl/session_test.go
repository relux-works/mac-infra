package safarictl

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodePageStatusLinesIncludesTargetWindowID(t *testing.T) {
	status := decodePageStatusLines("Page title\nhttps://example.com/private\ncomplete\n12345")
	if status.WindowID != 12345 {
		t.Fatalf("WindowID = %d, want 12345", status.WindowID)
	}
	if status.URL != "https://example.com/private" {
		t.Fatalf("URL = %q", status.URL)
	}
}

func TestOpenBackgroundAppleScriptPinsCreatedDocumentAndWindow(t *testing.T) {
	source := openBackgroundAppleScript(true, 3)
	for _, want := range []string{
		"set targetDocument to make new document",
		"set targetWindow to front window",
		"set miniaturized of targetWindow to true",
		`do JavaScript "document.readyState" in targetDocument`,
		"id of targetWindow as text",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("openBackgroundAppleScript missing %q:\n%s", want, source)
		}
	}
}

func TestRunJavaScriptAppleScriptUsesExactTargetWindow(t *testing.T) {
	source := runJavaScriptAppleScript()
	for _, want := range []string{
		"set targetWindowID to item 2 of argv as integer",
		"every window whose id is targetWindowID",
		"do JavaScript jsSource in current tab of targetWindow",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("runJavaScriptAppleScript missing %q:\n%s", want, source)
		}
	}
}

func TestGuardJavaScriptRejectsBrowserSecretReads(t *testing.T) {
	for _, source := range []string{
		"document.cookie",
		"window.cookieStore.getAll()",
		"localStorage.getItem('token')",
		"sessionStorage.key(0)",
	} {
		t.Run(source, func(t *testing.T) {
			err := GuardJavaScript(source)
			if !errors.Is(err, ErrSensitiveJavaScript) {
				t.Fatalf("GuardJavaScript error = %v, want ErrSensitiveJavaScript", err)
			}
		})
	}
}

func TestGuardJavaScriptAllowsPageContextFetchWithCredentials(t *testing.T) {
	source := `fetch("/api/file", { credentials: "include" }).then((r) => r.blob())`
	if err := GuardJavaScript(source); err != nil {
		t.Fatalf("GuardJavaScript rejected safe fetch: %v", err)
	}
}

func TestStartFetchJavaScriptUsesCredentialsIncludeAndChunks(t *testing.T) {
	source := StartFetchJavaScript("/api/private.pdf", 12345)
	for _, want := range []string{
		`fetch(endpoint, { credentials: "include" })`,
		"chunks.push",
		"chunkSize = 12345",
		"__macSafariSessionFetchJob",
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("StartFetchJavaScript missing %q:\n%s", want, source)
		}
	}
}

func TestPollFetchJavaScriptDoesNotReturnChunks(t *testing.T) {
	source := PollFetchJavaScript()
	for _, want := range []string{"const { chunks, ...meta } = job", "JSON.stringify(meta)"} {
		if !strings.Contains(source, want) {
			t.Fatalf("PollFetchJavaScript missing %q:\n%s", want, source)
		}
	}
}

func TestSanitizeHeadersDropsSensitiveHeaders(t *testing.T) {
	got := SanitizeHeaders(map[string]string{
		"Content-Type":  "application/pdf",
		"Set-Cookie":    "secret",
		"Authorization": "Bearer secret",
		"X-CSRF-Token":  "secret",
	})
	if got["content-type"] != "application/pdf" {
		t.Fatalf("content-type = %q", got["content-type"])
	}
	for _, blocked := range []string{"set-cookie", "authorization", "x-csrf-token"} {
		if _, ok := got[blocked]; ok {
			t.Fatalf("sensitive header %q survived: %#v", blocked, got)
		}
	}
}
