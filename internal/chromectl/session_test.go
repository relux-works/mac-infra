package chromectl

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

func TestAutomationScriptsUseExactIDsWithoutActivation(t *testing.T) {
	for name, source := range map[string]string{
		"list":    listJXA(),
		"execute": executeAppleScript(),
		"close":   closeJXA(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, forbidden := range []string{"activate", "frontmost", "activeTabIndex", "System Events", "set visible"} {
				if strings.Contains(source, forbidden) {
					t.Fatalf("silent script contains focus mutation %q:\n%s", forbidden, source)
				}
			}
		})
	}
	for _, want := range []string{"every window whose id", "every tab of targetWindow whose id", "execute targetTab javascript"} {
		if !strings.Contains(executeAppleScript(), want) {
			t.Fatalf("execute script missing %q", want)
		}
	}
	for _, want := range []string{"const windows=c.windows()", "targetWindow.tabs()", "targetWindow.activeTabIndex=targetIndex+1", "targetWindow.index=1", "c.activate()", "frontExact", "activeTabIndex())-1", "origin-mismatch"} {
		if !strings.Contains(exactTargetJXA(), want) {
			t.Fatalf("explicit focus script missing %q", want)
		}
	}
	for _, forbidden := range []string{"tabs.whose", ".index()", "title()"} {
		if strings.Contains(exactTargetJXA(), forbidden) {
			t.Fatalf("focus script still uses stale Chrome tab proxy operation %q", forbidden)
		}
	}
}

func TestFocusProductionMethodVerifiesExactOriginAndEnvelope(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "argv.txt")
	osa := writeFakeOsaScript(t, `printf '%s\n' "$@" >> "$CAPTURE"; printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"ok","origin":"https://example.com","title":"Example page","active":true}'`)
	t.Setenv("CAPTURE", capture)
	session := Session{OsaScriptPath: osa}
	if err := session.Focus(context.Background(), "11", "22", "https://example.com"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"JavaScript", "11", "22", "https://example.com"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("focus production argv missing %q:\n%s", want, data)
		}
	}
	if strings.Count(string(data), "chrome-exact-target") != 2 {
		t.Fatalf("focus must select and then reattest the exact front window: %s", data)
	}
}

func TestFocusFailsClosedWhenExactWindowIsNotFrontAfterSelection(t *testing.T) {
	countPath := filepath.Join(t.TempDir(), "count")
	t.Setenv("COUNT_PATH", countPath)
	osa := writeFakeOsaScript(t, `count=0; if [ -f "$COUNT_PATH" ]; then count=$(cat "$COUNT_PATH"); fi; count=$((count+1)); printf '%s' "$count" > "$COUNT_PATH"; if [ "$count" -eq 1 ]; then active=true; else active=false; fi; printf '%s\n' "{\"__macChromeExactTarget\":\"works.relux.mac-infra/chrome-exact-target/v1\",\"outcome\":\"ok\",\"origin\":\"https://example.com\",\"title\":\"Duplicate title\",\"active\":$active}"`)
	err := (Session{OsaScriptPath: osa}).Focus(context.Background(), "11", "22", "https://example.com")
	if !errors.Is(err, browsersession.ErrTargetMissing) {
		t.Fatalf("front-window drift error=%v want ErrTargetMissing", err)
	}
}

func TestExactTargetFinalAttestationReResolvesTabIDAfterPossibleReorder(t *testing.T) {
	source := exactTargetJXA()
	selection := strings.Index(source, "if(selectTab)")
	if selection < 0 {
		t.Fatal("exact-target selection is missing")
	}
	finalAttestation := source[selection:]
	for _, want := range []string{"verifiedIndexes=[]", "String(verifiedTabs[i].id())===tabID", "verifiedIndexes.length!==1", "verifiedTabs[verifiedIndex]", "activeIndex===verifiedIndex"} {
		if !strings.Contains(finalAttestation, want) {
			t.Fatalf("final exact-target attestation does not re-resolve the fresh tab ID via %q", want)
		}
	}
	if strings.Contains(finalAttestation, "verifiedTabs[targetIndex]") {
		t.Fatal("final exact-target origin attestation reused the pre-selection tab index")
	}
}

func TestFocusOriginDriftAndUnreadableAttestationFailClosed(t *testing.T) {
	for name, body := range map[string]string{
		"origin-drift": `printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"origin-mismatch","origin":"https://drift.example"}'`,
		"malformed":    `printf '%s\n' 'focused'`,
	} {
		t.Run(name, func(t *testing.T) {
			osa := writeFakeOsaScript(t, body)
			err := (Session{OsaScriptPath: osa}).Focus(context.Background(), "11", "22", "https://example.com")
			if name == "origin-drift" && !errors.Is(err, browsersession.ErrOriginMismatch) {
				t.Fatalf("error=%v want ErrOriginMismatch", err)
			}
			if name == "malformed" && !errors.Is(err, browsersession.ErrUnreadableResponse) {
				t.Fatalf("error=%v want ErrUnreadableResponse", err)
			}
		})
	}
}

func TestRunJavaScriptInjectsAtomicGuardAndPayloadInOneCall(t *testing.T) {
	capture := filepath.Join(t.TempDir(), "argv.txt")
	osa := writeFakeOsaScript(t, `printf '%s\n' "$@" > "$CAPTURE"; printf '%s\n' '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://example.com","readyState":"complete","value":"complete"}'`)
	t.Setenv("CAPTURE", capture)
	session := Session{OsaScriptPath: osa}
	result, err := session.RunJavaScript(context.Background(), "11", "22", "https://example.com", "document.readyState")
	if err != nil {
		t.Fatal(err)
	}
	if result != "complete" {
		t.Fatalf("result = %q", result)
	}
	data, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	captured := string(data)
	if strings.Count(captured, "works.relux.mac-infra/browser-session-guard/v1") != 1 || !strings.Contains(captured, "document.readyState") || !strings.Contains(captured, "location.origin !== __macExpectedOrigin") {
		t.Fatalf("origin guard and payload were not injected atomically:\n%s", captured)
	}
}

func TestRunJavaScriptOriginMismatchIsTypedRefusal(t *testing.T) {
	osa := writeFakeOsaScript(t, `printf '%s\n' '{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"origin-mismatch","origin":"https://wrong.example"}'`)
	_, err := (Session{OsaScriptPath: osa}).RunJavaScript(context.Background(), "11", "22", "https://expected.example", "window.__payloadExecuted = true")
	if !errors.Is(err, browsersession.ErrOriginMismatch) {
		t.Fatalf("error = %v, want ErrOriginMismatch", err)
	}
}

func TestRunJavaScriptRefusesMalformedAndEmptyAutomationOutput(t *testing.T) {
	for name, body := range map[string]string{"empty": `:`, "malformed": `printf '%s\n' 'not-json'`} {
		t.Run(name, func(t *testing.T) {
			osa := writeFakeOsaScript(t, body)
			_, err := (Session{OsaScriptPath: osa}).RunJavaScript(context.Background(), "11", "22", "https://example.com", "document.readyState")
			if !errors.Is(err, browsersession.ErrUnreadableResponse) {
				t.Fatalf("error = %v, want ErrUnreadableResponse", err)
			}
		})
	}
}

func TestRunJavaScriptMissingTargetIsTypedAndNeverFallsBack(t *testing.T) {
	osa := writeFakeOsaScript(t, `printf '%s\n' 'Chrome target tab is no longer open' >&2; exit 1`)
	_, err := (Session{OsaScriptPath: osa}).RunJavaScript(context.Background(), "11", "999", "https://example.com", "document.readyState")
	if !errors.Is(err, browsersession.ErrTargetMissing) {
		t.Fatalf("error = %v, want ErrTargetMissing", err)
	}
	if strings.Contains(executeAppleScript(), "active tab") {
		t.Fatalf("exact-target path contains active-tab fallback: %s", executeAppleScript())
	}
}

func TestListRedactsSensitiveURLValuesAndFragment(t *testing.T) {
	osa := writeFakeOsaScript(t, `printf '%s\n' '[{"id":"1","tabs":[{"id":"2","title":"Page","url":"https://example.com/path?code=secret&next=ok#private"}]}]'`)
	tabs, err := (Session{OsaScriptPath: osa}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tabs) != 1 {
		t.Fatalf("tabs = %#v", tabs)
	}
	if strings.Contains(tabs[0].URL, "secret") || strings.Contains(tabs[0].URL, "private") {
		t.Fatalf("list leaked sensitive URL: %q", tabs[0].URL)
	}
}

// Regression: an authenticated statement tab and its download tab carried
// opaque document and sticky identifiers under site-specific query parameter
// names, and Session.List (internal/chromectl/session.go, the production path
// behind `mac-chrome-session list`) emitted both query strings verbatim. A
// parameter-name denylist admitted every one of them, so the guard here is that
// no query byte at all survives List.
func TestListNeverEmitsAuthenticatedQueryIdentifiersUnderUnknownParameterNames(t *testing.T) {
	const (
		documentID = "9f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8"
		stickyID   = "SBOL-STICKY-4242-0007"
	)
	statementURL := "https://bank.example/private/statement?docNumber=" + documentID + "&stickyId=" + stickyID
	downloadURL := "https://download.bank.example:8443/v1/file?" + documentID + "=1&fileHash=" + stickyID
	osa := writeFakeOsaScript(t, `printf '%s
' '[{"id":"1","tabs":[{"id":"2","title":"Statement","url":"`+statementURL+`"},{"id":"3","title":"Download","url":"`+downloadURL+`"}]}]'`)
	tabs, err := (Session{OsaScriptPath: osa}).List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tabs) != 2 {
		t.Fatalf("tabs = %#v", tabs)
	}
	encoded, err := json.Marshal(tabs)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{documentID, stickyID, "9f3a2b1c", "SBOL-STICKY", "docNumber", "stickyId", "fileHash"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("list emitted authenticated query identifier %q: %s", leaked, encoded)
		}
	}
	if tabs[0].URL != "https://bank.example/private/statement?[redacted-query]" || tabs[1].URL != "https://download.bank.example:8443/v1/file?[redacted-query]" {
		t.Fatalf("list URLs = %q, %q", tabs[0].URL, tabs[1].URL)
	}
	if tabs[0].Origin != "https://bank.example" || tabs[1].Origin != "https://download.bank.example:8443" {
		t.Fatalf("origins lost routability: %q, %q", tabs[0].Origin, tabs[1].Origin)
	}
}

func writeFakeOsaScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "osascript")
	content := "#!/bin/sh\nset -eu\n" + fakeOsaScriptPrelude + body + "\n"
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// fakeOsaScriptPrelude gives every fake osascript the sealed private-transport
// envelope helpers. The production sealed transport no longer accepts a bare
// guard envelope on stdout, and never classifies a failure from child text, so
// fakes must speak the same sentinel-sealed envelope Chrome's JXA program does.
const fakeOsaScriptPrelude = `__PRIVATE_SENTINEL='works.relux.mac-infra/chrome-private-transport/v1'
__GUARD_SENTINEL='works.relux.mac-infra/browser-session-guard/v1'
seal_outcome() { /usr/bin/jq -cn --arg s "$__PRIVATE_SENTINEL" --arg o "$1" --arg v "${2-}" '{__macChromePrivateTransport:$s,outcome:$o,value:$v}'; }
guard_value() { /usr/bin/jq -cn --arg s "$__GUARD_SENTINEL" --arg org "${2-https://example.com}" --arg v "$1" '{__macBrowserSessionGuard:$s,outcome:"ok",origin:$org,readyState:"complete",value:$v}'; }
emit_value() { /usr/bin/jq -cn --arg ps "$__PRIVATE_SENTINEL" --arg gs "$__GUARD_SENTINEL" --arg org "${2-https://example.com}" --arg v "$1" '{__macChromePrivateTransport:$ps,outcome:"ok",value:({__macBrowserSessionGuard:$gs,outcome:"ok",origin:$org,readyState:"complete",value:$v}|tostring)}'; }
emit_guard() { seal_outcome ok "$1"; }
`
