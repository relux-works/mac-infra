package browserfacade

import (
	"strings"
	"testing"
)

func TestCentralOutboundBoundaryNormalizesCleanRedactedRefusedAndUnknown(t *testing.T) {
	testCases := map[string]struct {
		input     string
		wantState OutboundState
		wantCode  string
	}{
		"clean": {
			input:     "Desk lamp at HTTPS://SHOP.EXAMPLE/items?category=lighting",
			wantState: OutboundClean,
		},
		"clean-canonical-browser-secret-redactions": {
			input:     "https://shop.example/item?cookie=%5Bredacted%5D&localStorage=%5Bredacted%5D&session_id=%5Bredacted%5D",
			wantState: OutboundClean,
		},
		"redacted-uppercase-url-duplicate-sensitive-keys": {
			input:     "HTTPS://SHOP.EXAMPLE/items?API_KEY=one&api_key=two&SIGNATURE=three#four",
			wantState: OutboundRedacted,
		},
		"refused-gitlab": {
			input:     "glpat-0123456789abcdefghijklmnop",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-nested-encoded-url": {
			input:     "https://shop.example/redirect?next=https%253A%252F%252Fvault.example%252Fitem%253Ftoken%253Dnested-secret",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-nested-url-in-query-name": {
			input:     "https://shop.example/redirect?https%3A%2F%2Fvault.example%2Fitem%3Ftoken%3Dnested-key-secret=safe",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-openai-project-token": {
			input:     "sk-proj-0123456789abcdefghijklmnopqrstuvwxyz",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-openai-opaque-token": {
			input:     "sk-0123456789abcdefghijklmnopqrstuvwxyz",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-openai-project-token-hostname": {
			input:     "https://sk-proj-0123456789abcdefghijklmnopqrstuvwxyz.example/item",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"unknown-opaque-credential-hostname": {
			input:     "https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.example/item",
			wantState: OutboundUnknown,
			wantCode:  "SENSITIVE_RESPONSE_UNKNOWN",
		},
		"refused-cookie-hostname": {
			input:     "https://CoOkIe-State.example/item",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-session-path-component": {
			input:     "https://shop.example/item/session%5Fstate/value",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-storage-path-component": {
			input:     "https://shop.example/item/local%2Dstorage/value",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"redacted-cookie-query": {
			input:     "https://shop.example/item?cookie=browser-cookie-value",
			wantState: OutboundRedacted,
		},
		"redacted-session-storage-query": {
			input:     "https://shop.example/item?session_id=opaque-session&local-storage=browser-state",
			wantState: OutboundRedacted,
		},
		"refused-cookie-assignment": {
			input:     "cookie=browser-cookie-value",
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-json-escaped-secret-url": {
			input:     `transport failed at https:\/\/shop.example\/error?callback_code=escaped-secret`,
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"refused-unicode-escaped-secret-url": {
			input:     `transport failed at https:\u002f\u002fshop.example\u002ferror?session_state=escaped-state`,
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"unknown-opaque-high-entropy-candidate": {
			input:     "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
			wantState: OutboundUnknown,
			wantCode:  "SENSITIVE_RESPONSE_UNKNOWN",
		},
		"refused-duplicate-json-secret": {
			input:     `{"title":"Bearer duplicate-shadow-secret","title":"safe"}`,
			wantState: OutboundRefused,
			wantCode:  "SENSITIVE_RESPONSE_REFUSED",
		},
		"unknown-duplicate-json": {
			input:     `{"title":"first","title":"second"}`,
			wantState: OutboundUnknown,
			wantCode:  "SENSITIVE_RESPONSE_UNKNOWN",
		},
		"unknown-malformed-secret-url": {
			input:     "HTTPS://SHOP.EXAMPLE/items?API_KEY=%zz",
			wantState: OutboundUnknown,
			wantCode:  "SENSITIVE_RESPONSE_UNKNOWN",
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			decision, err := EnforceOutbound(testCase.input)
			if decision.State != testCase.wantState || ErrorCode(err) != codeOrInternal(testCase.wantCode) {
				t.Fatalf("decision=%#v error=%v code=%s", decision, err, ErrorCode(err))
			}
			if err == nil {
				for _, forbidden := range []string{"one", "two", "three", "four", "browser-cookie-value", "opaque-session", "browser-state"} {
					if strings.Contains(decision.Value, forbidden) {
						t.Fatalf("redacted decision retained %q: %s", forbidden, decision.Value)
					}
				}
			} else if decision.Value != "" {
				t.Fatalf("failed decision retained input: %#v", decision)
			}
		})
	}
}

func TestCentralOutboundBoundaryCanonicalRedactionIsIdempotentlyClean(t *testing.T) {
	value := "https://shop.example/item?api_key=%5Bredacted%5D&api_key=%5Bredacted%5D#%5Bredacted%5D"
	decision, err := EnforceOutbound(value)
	if err != nil || decision.State != OutboundClean || decision.Value != value {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
}

func TestNormalizationHelpersBoundEscapesAndSensitiveNames(t *testing.T) {
	for name, testCase := range map[string]struct {
		input         string
		want          string
		wantChanged   bool
		wantAmbiguous bool
	}{
		"slash":           {`https:\/\/example.test`, `https://example.test`, true, false},
		"unicode":         {`https:\u002f\u002fexample.test`, `https://example.test`, true, false},
		"standard":        {`line\nnext`, "line\nnext", true, false},
		"invalid-unicode": {`https:\u00zz`, `https:\u00zz`, false, true},
		"surrogate":       {`https:\ud800`, `https:\ud800`, false, true},
		"trailing":        {`https:\`, `https:\`, false, true},
		"unknown-escape":  {`https:\q`, `https:\q`, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			got, changed, ambiguous := decodeBackslashVariant(testCase.input)
			if got != testCase.want || changed != testCase.wantChanged || ambiguous != testCase.wantAmbiguous {
				t.Fatalf("got=%q changed=%t ambiguous=%t", got, changed, ambiguous)
			}
		})
	}

	for name, wantState := range map[string]OutboundState{
		"session%255fid": OutboundRefused,
		"session%zz":     OutboundUnknown,
		"sessiön":        OutboundUnknown,
		"public-title":   OutboundClean,
	} {
		if state := outboundNameState(name); state != wantState {
			t.Fatalf("name=%q state=%s want=%s", name, state, wantState)
		}
	}
	if !hasTransformHint(`https:\u002f`) || !hasSecretHint("cookie material") || hasSecretHint("ordinary title") {
		t.Fatal("normalization hint classification drifted")
	}

	for name, testCase := range map[string]struct {
		input     string
		want      string
		wantState OutboundState
	}{
		"bounded-decoding":    {"session%255Fstate", "session_state", OutboundClean},
		"budget-exhaustion":   {"session%252525255Fstate", "", OutboundUnknown},
		"malformed-component": {"session%zzstate", "", OutboundUnknown},
	} {
		t.Run("url-component-"+name, func(t *testing.T) {
			got, state := decodeOutboundURLComponent(testCase.input)
			if got != testCase.want || state != testCase.wantState {
				t.Fatalf("got=%q state=%s want=%q/%s", got, state, testCase.want, testCase.wantState)
			}
		})
	}
}

func codeOrInternal(code string) string {
	if code == "" {
		return "INTERNAL_ERROR"
	}
	return code
}
