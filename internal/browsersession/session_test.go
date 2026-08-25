package browsersession

import (
	"errors"
	"strings"
	"testing"
)

func TestGuardJavaScriptRejectsEveryBlockedToken(t *testing.T) {
	expected := []string{
		"document.cookie",
		"cookiestore",
		"localstorage",
		"sessionstorage",
		"indexeddb",
		"navigator.credentials",
		"opendatabase",
	}
	actual := BlockedJavaScriptTokens()
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		t.Fatalf("BlockedJavaScriptTokens() = %#v, want literal contract %#v", actual, expected)
	}
	for _, token := range expected {
		t.Run(token, func(t *testing.T) {
			if err := GuardJavaScript("void " + token); !errors.Is(err, ErrSensitiveJavaScript) {
				t.Fatalf("GuardJavaScript(%q) error = %v, want ErrSensitiveJavaScript", token, err)
			}
		})
	}
}

func TestWrapJavaScriptKeepsOriginGuardAndPayloadAtomic(t *testing.T) {
	source, err := WrapJavaScript("document.readyState", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"location.origin !== __macExpectedOrigin", "document.readyState", guardSentinel, "eval("} {
		if !strings.Contains(source, want) {
			t.Fatalf("wrapped source missing %q:\n%s", want, source)
		}
	}
}

func TestParseJavaScriptResultRefusesMalformedEmptyAndMissingSentinel(t *testing.T) {
	for _, raw := range []string{"", "not-json", `{"outcome":"ok","value":"forged"}`} {
		if _, err := ParseJavaScriptResult(raw, ""); !errors.Is(err, ErrUnreadableResponse) {
			t.Fatalf("ParseJavaScriptResult(%q) error = %v, want ErrUnreadableResponse", raw, err)
		}
	}
}

func TestParseJavaScriptResultReturnsTypedOriginRefusal(t *testing.T) {
	raw := `{"__macBrowserSessionGuard":"` + guardSentinel + `","outcome":"origin-mismatch","origin":"https://wrong.example"}`
	if _, err := ParseJavaScriptResult(raw, "https://expected.example"); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("error = %v, want ErrOriginMismatch", err)
	}
}

func TestParseJavaScriptResultRefusesSentinelValidOKWithWrongOrigin(t *testing.T) {
	raw := `{"__macBrowserSessionGuard":"` + guardSentinel + `","outcome":"ok","origin":"https://wrong.example","value":"forged-success"}`
	if _, err := ParseJavaScriptResult(raw, "https://expected.example"); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("error = %v, want ErrOriginMismatch", err)
	}
}

func TestRedactSensitiveURLCoversQueryAndFragment(t *testing.T) {
	got := RedactSensitiveURL("https://user:password@example.com/path?code=secret&api_key=api-secret&signature=signed-secret&next=ok#private")
	if strings.Contains(got, "secret") || strings.Contains(got, "private") || strings.Contains(got, "password") || strings.Contains(got, "user@") {
		t.Fatalf("redacted URL leaked: %q", got)
	}
	if got := RedactSensitiveURL("https://example.com/%zz?code=secret"); got != "[redacted-invalid-url]" {
		t.Fatalf("malformed URL was not refused: %q", got)
	}
	for _, want := range []string{"https://example.com/path?[redacted-query]", "#%5Bredacted%5D"} {
		if !strings.Contains(got, want) {
			t.Fatalf("redacted URL missing %q: %q", want, got)
		}
	}
}

// The Chrome download regression this guards: an authenticated statement tab
// carried opaque document and sticky identifiers under site-specific parameter
// names, so a name denylist admitted every one of them into `list` output.
func TestRedactSensitiveURLRemovesValuesUnderUnknownParameterNamesAndNonstandardPorts(t *testing.T) {
	const (
		documentID = "9f3a2b1c-4d5e-6f70-8192-a3b4c5d6e7f8"
		stickyID   = "SBOL-STICKY-4242-0007"
	)
	for name, rawURL := range map[string]string{
		"unknown-names":      "https://bank.example/private/statement?docNumber=" + documentID + "&stickyId=" + stickyID,
		"nonstandard-port":   "https://bank.example:8443/private/statement?docNumber=" + documentID + "&stickyId=" + stickyID,
		"semicolon-pairs":    "https://bank.example/private/statement?docNumber=" + documentID + ";stickyId=" + stickyID,
		"repeated-name":      "https://bank.example/private/statement?id=" + documentID + "&id=" + stickyID,
		"encoded-value":      "https://bank.example/private/statement?payload=%39f3a2b1c%2D4d5e",
		"bare-value":         "https://bank.example/private/statement?" + documentID,
		"empty-name":         "https://bank.example/private/statement?=" + documentID,
		"identifier-as-name": "https://bank.example/private/statement?" + documentID + "=1",
		"fragment-only":      "https://bank.example/private/statement#" + documentID,
	} {
		t.Run(name, func(t *testing.T) {
			got := RedactSensitiveURL(rawURL)
			for _, leaked := range []string{documentID, stickyID, "9f3a2b1c", "SBOL-STICKY", "%39f3a2b1c", "docNumber", "stickyId", "payload"} {
				if strings.Contains(got, leaked) {
					t.Fatalf("redacted URL leaked %q: %q", leaked, got)
				}
			}
			if !strings.HasPrefix(got, "https://bank.example") || !strings.Contains(got, "/private/statement") {
				t.Fatalf("redaction destroyed the routable prefix: %q", got)
			}
		})
	}
	if got := RedactSensitiveURL("https://bank.example:8443/private/statement?docNumber=" + documentID); got != "https://bank.example:8443/private/statement?[redacted-query]" {
		t.Fatalf("nonstandard port was not preserved alongside a closed query: %q", got)
	}
	if got := RedactSensitiveURL("https://bank.example/private/statement"); got != "https://bank.example/private/statement" {
		t.Fatalf("query-free URL must stay byte-identical: %q", got)
	}
}

func TestRedactSensitiveURLRefusesPayloadCarryingOpaqueURLs(t *testing.T) {
	for name, rawURL := range map[string]string{
		"data":        "data:text/plain;base64,c2VjcmV0LXBheWxvYWQ=",
		"javascript":  "javascript:fetch('/steal?cookie=secret-payload')",
		"view-source": "view-source:https://bank.example/private?docNumber=secret-payload",
		"mailto":      "mailto:secret-payload@example.com",
	} {
		t.Run(name, func(t *testing.T) {
			got := RedactSensitiveURL(rawURL)
			if got != "[redacted-opaque-url]" {
				t.Fatalf("opaque URL was disclosed: %q", got)
			}
		})
	}
	if got := RedactSensitiveURL("about:blank"); got != "about:blank" {
		t.Fatalf("about:blank should stay identifiable: %q", got)
	}
	if got := RedactSensitiveURL("blob:https://bank.example/2f1c"); got != "blob:https://bank.example/2f1c" {
		t.Fatalf("blob URL should stay identifiable: %q", got)
	}
}

func TestSanitizeHeadersDropsSensitiveHeaders(t *testing.T) {
	got := SanitizeHeaders(map[string]string{
		"Content-Type":  "application/pdf",
		"Set-Cookie":    "secret",
		"Authorization": "Bearer secret",
		"X-CSRF-Token":  "secret",
		"X-API-Key":     "secret",
	})
	if got["content-type"] != "application/pdf" {
		t.Fatalf("content-type = %q", got["content-type"])
	}
	for _, key := range []string{"set-cookie", "authorization", "x-csrf-token", "x-api-key"} {
		if _, ok := got[key]; ok {
			t.Fatalf("sensitive header %q survived: %#v", key, got)
		}
	}
}
