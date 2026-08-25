package safarictl

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browsersession"
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

func TestDecodePageStatusLinesRedactsOAuthQueryValues(t *testing.T) {
	status := decodePageStatusLines("Sign in\nhttps://example.com/callback?code=secret&state=another-secret&next=profile\ncomplete")
	if strings.Contains(status.URL, "secret") || strings.Contains(status.URL, "another-secret") || strings.Contains(status.URL, "profile") {
		t.Fatalf("status URL leaked sensitive values: %q", status.URL)
	}
	if status.URL != "https://example.com/callback?[redacted-query]" {
		t.Fatalf("status URL = %q", status.URL)
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

func TestSharedGuardAllowsPageContextFetchWithCredentials(t *testing.T) {
	source := `fetch("/api/file", { credentials: "include" }).then((r) => r.blob())`
	if err := browsersession.GuardJavaScript(source); err != nil {
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

func TestSilentSafariScriptsNeverFocusOrSelect(t *testing.T) {
	for name, source := range map[string]string{
		"run-js":   runJavaScriptAppleScript(),
		"check-js": checkJavaScriptAppleScript(),
		"status":   statusAppleScript(),
		"close":    closeWindowAppleScript(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, forbidden := range []string{"activate", "frontmost", "set index", "set visible", "System Events"} {
				if strings.Contains(source, forbidden) {
					t.Fatalf("silent Safari script contains focus mutation %q:\n%s", forbidden, source)
				}
			}
		})
	}
	for _, want := range []string{"set index", "activate"} {
		if !strings.Contains(focusWindowAppleScript(), want) {
			t.Fatalf("explicit focus script missing %q", want)
		}
	}
}

func TestRunJavaScriptOriginMismatchIsTypedWindowDriftRefusal(t *testing.T) {
	osa := writeFakeSafariOsaScript(t, `printf '%s\n' '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"origin-mismatch","origin":"https://wrong.example"}'`)
	session := New(t.TempDir())
	session.OsaScriptPath = osa
	session.TargetWindowID = 123
	session.ExpectedOrigin = "https://expected.example"
	_, err := session.RunJavaScript(context.Background(), "window.__payloadExecuted = true")
	if !errors.Is(err, browsersession.ErrOriginMismatch) {
		t.Fatalf("error = %v, want ErrOriginMismatch", err)
	}
}

func TestRunJavaScriptRefusesMissingWindowWithoutFrontDocumentFallback(t *testing.T) {
	session := New(t.TempDir())
	session.TargetWindowID = 0
	session.ExpectedOrigin = "https://example.com"
	_, err := session.RunJavaScript(context.Background(), "document.readyState")
	if err == nil || !strings.Contains(err.Error(), "exact Safari window id") {
		t.Fatalf("error = %v, want exact-window refusal", err)
	}
	if strings.Contains(runJavaScriptAppleScript(), "front document") {
		t.Fatalf("Safari run-js has a front-document fallback:\n%s", runJavaScriptAppleScript())
	}
}

func TestRunJavaScriptMissingTargetIsTyped(t *testing.T) {
	osa := writeFakeSafariOsaScript(t, `printf '%s\n' 'Safari target window 123 is no longer open' >&2; exit 1`)
	session := New(t.TempDir())
	session.OsaScriptPath = osa
	session.TargetWindowID = 123
	session.ExpectedOrigin = "https://example.com"
	_, err := session.RunJavaScript(context.Background(), "document.readyState")
	if !errors.Is(err, browsersession.ErrTargetMissing) {
		t.Fatalf("error = %v, want ErrTargetMissing", err)
	}
}

func TestSnapshotRedactsEveryReturnedURL(t *testing.T) {
	value, err := json.Marshal(Snapshot{
		Title: "Private",
		URL:   "https://example.com/page?code=secret#private",
		Links: []SnapshotLink{{Text: "next", Href: "https://example.com/next?token=secret#private"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RESULT", guardedSafariResult(t, string(value)))
	osa := writeFakeSafariOsaScript(t, `printf '%s\n' "$RESULT"`)
	session := New(t.TempDir())
	session.OsaScriptPath = osa
	session.TargetWindowID = 123
	session.ExpectedOrigin = "https://example.com"
	snapshot, err := session.Snapshot(context.Background(), 100, 10)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snapshot.URL, "secret") || strings.Contains(snapshot.URL, "private") || strings.Contains(snapshot.Links[0].Href, "secret") || strings.Contains(snapshot.Links[0].Href, "private") {
		t.Fatalf("snapshot leaked URL material: %#v", snapshot)
	}
}

func TestPollFetchSanitizesEveryMetadataOutput(t *testing.T) {
	value, err := json.Marshal(FetchMeta{
		State:    "done",
		Endpoint: "https://example.com/file?code=secret#private",
		URL:      "https://cdn.example.com/file?token=secret#private",
		Headers: map[string]string{
			"Content-Type":  "application/pdf",
			"Set-Cookie":    "secret",
			"Authorization": "Bearer secret",
		},
		Stack: "PRIVATE STACK",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RESULT", guardedSafariResult(t, string(value)))
	osa := writeFakeSafariOsaScript(t, `printf '%s\n' "$RESULT"`)
	session := New(t.TempDir())
	session.OsaScriptPath = osa
	session.TargetWindowID = 123
	session.ExpectedOrigin = "https://example.com"
	meta, err := session.PollFetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(meta.Endpoint, "secret") || strings.Contains(meta.Endpoint, "private") || strings.Contains(meta.URL, "secret") || strings.Contains(meta.URL, "private") {
		t.Fatalf("fetch metadata leaked URL material: %#v", meta)
	}
	if _, ok := meta.Headers["set-cookie"]; ok {
		t.Fatalf("set-cookie survived: %#v", meta.Headers)
	}
	if _, ok := meta.Headers["authorization"]; ok {
		t.Fatalf("authorization survived: %#v", meta.Headers)
	}
	if meta.Stack != "" {
		t.Fatalf("fetch stack survived output sanitization: %q", meta.Stack)
	}
}

func guardedSafariResult(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"__macBrowserSessionGuard": "works.relux.mac-infra/browser-session-guard/v1",
		"outcome":                  "ok",
		"origin":                   "https://example.com",
		"readyState":               "complete",
		"value":                    value,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeFakeSafariOsaScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
