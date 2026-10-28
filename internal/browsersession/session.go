package browsersession

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

const (
	guardSentinel            = "works.relux.mac-infra/browser-session-guard/v1"
	redactedValuePlaceholder = "[redacted]"
	redactedQueryPlaceholder = "[redacted-query]"
)

var (
	ErrSensitiveJavaScript = errors.New("javascript appears to read browser secrets")
	ErrOriginMismatch      = errors.New("browser target origin changed")
	ErrTargetMissing       = errors.New("browser target is no longer available")
	ErrUnreadableResponse  = errors.New("browser response could not be verified")
	ErrEvalBlocked         = errors.New("page blocks eval")
	ErrCSPExpression       = errors.New("page blocks eval; under this CSP the source must be a single expression (use an IIFE for statements)")
)

type Browser string

const (
	BrowserChrome Browser = "chrome"
	BrowserSafari Browser = "safari"
)

type Target struct {
	Browser  Browser `json:"browser"`
	WindowID string  `json:"windowId"`
	TabID    string  `json:"tabId,omitempty"`
	Origin   string  `json:"origin"`
}

type PageStatus struct {
	Title      string `json:"title"`
	URL        string `json:"url"`
	ReadyState string `json:"readyState,omitempty"`
	WindowID   int64  `json:"windowId,omitempty"`
}

type ExecutionResult struct {
	Value      string `json:"value"`
	Origin     string `json:"origin"`
	ReadyState string `json:"readyState"`
}

type OriginMismatchError struct {
	Expected string
	Observed string
}

func (e *OriginMismatchError) Error() string {
	return fmt.Sprintf("%v: got %q, want %q", ErrOriginMismatch, e.Observed, e.Expected)
}

func (e *OriginMismatchError) Unwrap() error { return ErrOriginMismatch }

type TargetMissingError struct {
	Browser Browser
	Target  string
	Detail  string
}

func (e *TargetMissingError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("%v: %s", ErrTargetMissing, e.Detail)
	}
	return fmt.Sprintf("%v: %s %s", ErrTargetMissing, e.Browser, e.Target)
}

func (e *TargetMissingError) Unwrap() error { return ErrTargetMissing }

func BlockedJavaScriptTokens() []string {
	return []string{
		"document.cookie",
		"cookiestore",
		"localstorage",
		"sessionstorage",
		"indexeddb",
		"navigator.credentials",
		"opendatabase",
	}
}

func GuardJavaScript(source string) error {
	lower := strings.ToLower(source)
	for _, needle := range BlockedJavaScriptTokens() {
		if strings.Contains(lower, needle) {
			return fmt.Errorf("%w: blocked token %q; do not export cookies or browser storage", ErrSensitiveJavaScript, needle)
		}
	}
	return nil
}

// WrapJavaScript puts the origin check and caller payload in one page-context
// evaluation. ParseJavaScriptResult refuses any response that does not carry the
// matching sentinel, so an empty or malformed automation response cannot pass.
func WrapJavaScript(source, expectedOrigin string) (string, error) {
	return wrapJavaScript(source, expectedOrigin, false)
}

// WrapJavaScriptExpression embeds a single expression without string-to-code
// evaluation. Statements must be expressed as an IIFE on this CSP-safe route.
func WrapJavaScriptExpression(source, expectedOrigin string) (string, error) {
	return wrapJavaScript(source, expectedOrigin, true)
}

func wrapJavaScript(source, expectedOrigin string, expression bool) (string, error) {
	if err := GuardJavaScript(source); err != nil {
		return "", err
	}
	sourceJSON, err := json.Marshal(source)
	if err != nil {
		return "", fmt.Errorf("encode javascript source: %w", err)
	}
	originJSON, err := json.Marshal(strings.TrimSpace(expectedOrigin))
	if err != nil {
		return "", fmt.Errorf("encode expected origin: %w", err)
	}
	sentinelJSON, _ := json.Marshal(guardSentinel)
	evaluation := fmt.Sprintf(`
  // Probe separately: a caller-thrown EvalError must never cause a retry.
  try { eval("void 0"); }
  catch (__macError) {
    if (!(__macError instanceof EvalError)) throw __macError;
    return JSON.stringify({__macBrowserSessionGuard:__macGuard,outcome:"eval-blocked",origin:String(location.origin || ""),readyState:String(document.readyState || ""),value:""});
  }
  const __macValue = eval(%s);`, string(sourceJSON))
	if expression {
		evaluation = "\n  const __macValue = (\n" + source + "\n  );"
	}
	return fmt.Sprintf(`(() => {
  const __macGuard = %s;
  const __macExpectedOrigin = %s;
  if (__macExpectedOrigin && location.origin !== __macExpectedOrigin) {
    return JSON.stringify({__macBrowserSessionGuard:__macGuard,outcome:"origin-mismatch",origin:String(location.origin || "")});
  }
%s
  let __macText = "";
  if (__macValue !== undefined) {
    if (typeof __macValue === "string") __macText = __macValue;
    else {
      try { __macText = JSON.stringify(__macValue); }
      catch (_) { __macText = String(__macValue); }
    }
  }
  return JSON.stringify({
    __macBrowserSessionGuard:__macGuard,
    outcome:"ok",
    origin:String(location.origin || ""),
    readyState:String(document.readyState || ""),
    value:__macText
  });
})()`, string(sentinelJSON), string(originJSON), evaluation), nil
}

// ExecuteJavaScript retries exactly once, only after a verified eval-blocked
// envelope from a probe that ran no caller code. Each dispatch repeats the guard.
func ExecuteJavaScript(source, expectedOrigin string, execute func(string) (string, error)) (ExecutionResult, error) {
	wrapped, err := WrapJavaScript(source, expectedOrigin)
	if err != nil {
		return ExecutionResult{}, err
	}
	raw, err := execute(wrapped)
	if err != nil {
		return ExecutionResult{}, err
	}
	result, err := ParseJavaScriptResult(raw, expectedOrigin)
	if !errors.Is(err, ErrEvalBlocked) {
		return result, err
	}
	wrapped, err = WrapJavaScriptExpression(source, expectedOrigin)
	if err != nil {
		return ExecutionResult{}, err
	}
	raw, err = execute(wrapped)
	if err == nil {
		result, err = ParseJavaScriptResult(raw, expectedOrigin)
	}
	if err != nil && !errors.Is(err, ErrOriginMismatch) && !errors.Is(err, ErrTargetMissing) {
		return ExecutionResult{}, fmt.Errorf("%w: expression execution failed: %w", ErrCSPExpression, err)
	}
	return result, err
}

func ParseJavaScriptResult(raw, expectedOrigin string) (ExecutionResult, error) {
	if strings.TrimSpace(raw) == "" {
		return ExecutionResult{}, fmt.Errorf("%w: empty automation output", ErrUnreadableResponse)
	}
	var envelope struct {
		Sentinel   string `json:"__macBrowserSessionGuard"`
		Outcome    string `json:"outcome"`
		Origin     string `json:"origin"`
		ReadyState string `json:"readyState"`
		Value      string `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return ExecutionResult{}, fmt.Errorf("%w: malformed guard envelope: %v", ErrUnreadableResponse, err)
	}
	if envelope.Sentinel != guardSentinel {
		return ExecutionResult{}, fmt.Errorf("%w: missing guard sentinel", ErrUnreadableResponse)
	}
	switch envelope.Outcome {
	case "origin-mismatch":
		return ExecutionResult{}, &OriginMismatchError{Expected: strings.TrimSpace(expectedOrigin), Observed: envelope.Origin}
	case "eval-blocked":
		if strings.TrimSpace(expectedOrigin) != "" && envelope.Origin != strings.TrimSpace(expectedOrigin) {
			return ExecutionResult{}, &OriginMismatchError{Expected: strings.TrimSpace(expectedOrigin), Observed: envelope.Origin}
		}
		return ExecutionResult{}, ErrEvalBlocked
	case "ok":
		if strings.TrimSpace(expectedOrigin) != "" && envelope.Origin != strings.TrimSpace(expectedOrigin) {
			return ExecutionResult{}, &OriginMismatchError{Expected: strings.TrimSpace(expectedOrigin), Observed: envelope.Origin}
		}
		return ExecutionResult{Value: envelope.Value, Origin: envelope.Origin, ReadyState: envelope.ReadyState}, nil
	default:
		return ExecutionResult{}, fmt.Errorf("%w: unknown guard outcome %q", ErrUnreadableResponse, envelope.Outcome)
	}
}

// RedactSensitiveURL returns a display-safe form of rawURL. The whole query
// string is replaced, not filtered by parameter name: authenticated sites carry
// document, session and sticky identifiers under site-specific names, and the
// identifier is just as often the parameter name as the value, so no name-based
// rule can be trusted to fail closed. Fragments, userinfo and payload-carrying
// opaque URLs are dropped for the same reason.
func RedactSensitiveURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "[redacted-invalid-url]"
	}
	if parsed.Opaque != "" && !isDisclosableOpaqueScheme(parsed.Scheme) {
		return "[redacted-opaque-url]"
	}
	parsed.User = nil
	if parsed.RawQuery != "" {
		parsed.RawQuery = redactedQueryPlaceholder
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		parsed.Fragment = redactedValuePlaceholder
		parsed.RawFragment = ""
	}
	return parsed.String()
}

func isDisclosableOpaqueScheme(scheme string) bool {
	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case "about", "blob":
		return true
	default:
		return false
	}
}

func SanitizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" || isSensitiveHeader(normalized) {
			continue
		}
		out[normalized] = value
	}
	return out
}

func OriginOf(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	return parsed.Scheme + "://" + parsed.Host
}

func isSensitiveHeader(name string) bool {
	switch name {
	case "set-cookie", "cookie", "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate", "authentication-info", "x-api-key", "x-auth-token", "x-csrf-token":
		return true
	default:
		return false
	}
}
