package browserfacade

import (
	"strings"
	"testing"
	"time"
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

func TestEnforceOutboundAdmitsOnlyCanonicalDocumentSanitizerPlaceholders(t *testing.T) {
	// This proves the composed boundary admits its own safe token without widening malformed bracket-shaped input.
	decision, err := EnforceOutbound("[EMAIL_1]")
	if err != nil || decision.State != OutboundClean || decision.Value != "[EMAIL_1]" {
		t.Fatalf("canonical placeholder decision=%#v err=%v", decision, err)
	}
	for _, value := range []string{"[EMAIL]", "[email_1]", "[EMAIL_1] trailing"} {
		if _, err := EnforceOutbound(value); err == nil {
			t.Fatalf("noncanonical placeholder admitted: %q", value)
		}
	}
}

func codeOrInternal(code string) string {
	if code == "" {
		return "INTERNAL_ERROR"
	}
	return code
}

// Bug (2026-10-21): in adapter metadata only, a nested string that starts with
// '[' and fully matches the CSS selector grammar is scanned as text, so an
// attribute selector no longer refuses the adapter. The general boundary keeps
// the strict rule for every nested bracket string. Secret-bearing selectors are
// refused; JSON-ish, single-quoted pairs (review F5) and brace values stay
// UNKNOWN in both modes.
func TestAdapterSelectorException(t *testing.T) {
	for raw, want := range map[string][2]OutboundState{ // {general, adapter}
		`{"s":"[data-widget=\"searchResults\"] > div"}`:     {OutboundUnknown, OutboundClean},
		`{"s":"[data-widget=searchResults] > div"}`:         {OutboundUnknown, OutboundClean},
		`{"s":"div.card > [data-testid='item'] a"}`:         {OutboundClean, OutboundClean},
		`{"s":"[data-token=\"abcdefgh12345\"] > div"}`:      {OutboundUnknown, OutboundRefused},
		`{"s":"[token=abcdefgh12345]"}`:                     {OutboundUnknown, OutboundRefused},
		`{"s":"[x=\"a1b2c3d4e5f6g7h8a1b2c3d4e5f6g7h8\"]"}`:  {OutboundUnknown, OutboundUnknown},
		`{"s":"['access_token','abcdefgh12345']"}`:          {OutboundUnknown, OutboundUnknown},
		`{"s":"['cookie','sid=abcdefgh12345']"}`:            {OutboundUnknown, OutboundUnknown},
		`{"s":"{'data':{'access_token':'abcdefgh12345'}}"}`: {OutboundUnknown, OutboundUnknown},
		`{"s":"[1, 2"}`:                       {OutboundUnknown, OutboundUnknown},
		`[data-widget="searchResults"] > div`: {OutboundUnknown, OutboundUnknown},
	} {
		general, _ := EnforceOutbound(raw)
		adapter, _ := EnforceAdapterOutbound(raw)
		if general.State != want[0] || adapter.State != want[1] {
			t.Errorf("%s: general=%s adapter=%s, want %s/%s", raw, general.State, adapter.State, want[0], want[1])
		}
	}
}

// Review F1/F2 (PR #29): opaque-credential detection has no length cap and no
// "redacted" substring exemption. Tokens of 32, 256, 257 and 300 characters
// and redacted_-prefixed or -suffixed credentials are UNKNOWN in text and in
// adapter selectors; "[redacted]" and short identifiers stay clean (controls).
func TestOpaqueCredentialLengthAndRedactedPrefix(t *testing.T) {
	token := func(n int) string {
		const unit = "a1b2c3d4e5f6g7h8"
		return strings.Repeat(unit, n/len(unit)+1)[:n]
	}
	t32 := token(32)
	for _, raw := range []string{"value " + token(32), "value " + token(256), "value " + token(257), "value " + token(300), "value redacted_" + t32, "value " + t32 + "_redacted"} {
		if d, _ := EnforceOutbound(raw); d.State != OutboundUnknown {
			t.Errorf("text %.40q -> %s, want unknown", raw, d.State)
		}
	}
	for _, sel := range []string{"[" + token(32) + "]", "[redacted_" + t32 + "]", "[x='" + t32 + "']"} {
		if d, _ := EnforceAdapterOutbound(`{"s":"` + sel + `"}`); d.State != OutboundUnknown {
			t.Errorf("adapter %.40q -> %s, want unknown", sel, d.State)
		}
	}
	for _, raw := range []string{"note [redacted] kept", "item a1b2 lamp"} {
		if d, err := EnforceOutbound(raw); err != nil || d.State != OutboundClean {
			t.Errorf("control %q -> %s", raw, d.State)
		}
	}
	if d, err := EnforceAdapterOutbound(`{"s":"[redacted]"}`); err != nil || d.State != OutboundClean {
		t.Errorf("adapter control [redacted] -> %s", d.State)
	}
}

// Review F3/F4 (PR #29): sensitive assignments are found with a quoted key
// ('access_token':'…') and when nested inside the value of a harmless one
// ('title': 'cookie=…'). WriteOutbound emits nothing for them; harmless
// quoted keys stay clean (controls).
func TestQuotedAndNestedSensitiveAssignments(t *testing.T) {
	for _, raw := range []string{
		`note 'access_token': 'abcdefgh12345'`,
		`note "cookie"= abcdefgh12345`,
		`note 'title': 'cookie=abcdefgh12345'`,
		`note 'title': 'session_state=abcdefgh12345'`,
		`note data: {access_token: abcdefgh12345}`,
	} {
		if d, err := EnforceOutbound(raw); err == nil || d.State == OutboundClean {
			t.Errorf("%q admitted: %s", raw, d.State)
		}
		var out strings.Builder
		if werr := WriteOutbound(&out, raw); werr == nil || out.Len() != 0 {
			t.Errorf("%q written: %q (err=%v)", raw, out.String(), werr)
		}
	}
	for _, raw := range []string{`note 'color': red`, `size = large lamp`, `note 'title': lamp`} {
		if d, err := EnforceOutbound(raw); err != nil || d.State != OutboundClean {
			t.Errorf("control %q -> %s (err=%v)", raw, d.State, err)
		}
	}
}

// Review F6 (PR #29): the assignment scan is linear. 1 MiB of dense
// "a=a=…" assignments classifies within a generous bound (a quadratic scan
// takes minutes); F4 nested pairs are still found in the same single pass.
func TestDenseAssignmentsAreLinear(t *testing.T) {
	raw := strings.Repeat("a=", 1<<19) + "z"
	done := make(chan OutboundState, 1)
	go func() { done <- inspectSensitiveAssignments(raw) }()
	select {
	case state := <-done:
		if state != OutboundClean {
			t.Fatalf("dense harmless assignments -> %s", state)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("dense assignment scan exceeded 5s (not linear)")
	}
	for _, prefix := range []int{1 << 16, 1<<16 + 1} { // even and odd prefixes
		if inspectSensitiveAssignments(strings.Repeat("a=", prefix)+"cookie=abcdefgh12345") != OutboundRefused {
			t.Fatalf("sensitive assignment after a %d-pair dense prefix missed", prefix)
		}
	}
}

// Review F7 (PR #29): every separator's complete name is checked, so an
// overlapping pair (title=cookie=…) is refused whatever precedes it (odd or
// even dense prefixes), with zero WriteOutbound output; a name separated from
// '=' by long whitespace is still found. Hyphenated harmless names
// (data-state, data-key, x-state) are not cut into a sensitive suffix.
func TestOverlappingAssignmentNames(t *testing.T) {
	refused := []string{
		"title=cookie=abcdefgh12345",
		"title=session_state=abcdefgh12345",
		"title=password=abcdefgh12345",
		"a=cookie=abcdefgh12345",
		"a=a=cookie=abcdefgh12345",
		"a=a=a=cookie=abcdefgh12345",
		"cookie" + strings.Repeat(" ", 100) + "= abcdefgh12345",
	}
	for _, raw := range refused {
		if d, err := EnforceOutbound(raw); err == nil || d.State == OutboundClean {
			t.Errorf("%.50q admitted: %s", raw, d.State)
		}
		var out strings.Builder
		if werr := WriteOutbound(&out, raw); werr == nil || out.Len() != 0 {
			t.Errorf("%.50q written: %q", raw, out.String())
		}
	}
	for _, raw := range []string{"selector=data-state=active", "attribute=data-key=Escape", "filter=x-state=active", "color: red; size: large"} {
		if d, err := EnforceOutbound(raw); err != nil || d.State != OutboundClean {
			t.Errorf("control %q -> %s (err=%v)", raw, d.State, err)
		}
	}
}

// Review F8 (PR #29): names whose runes case-fold to ASCII (Kelvin sign
// U+212A to k, long s U+017F to s) are folded before classification, as the
// former (?i) regex matched them. They are refused in both boundary modes with
// zero WriteOutbound output. Runs without a letter are not names, and
// non-folding letters only end a name (controls stay clean).
func TestCaseFoldedAssignmentNames(t *testing.T) {
	kelvin, longS := "\u212a", "\u017f"
	for _, raw := range []string{
		"coo" + kelvin + "ie=abcdefgh12345",
		"to" + kelvin + "en=abcdefgh12345",
		"private_" + kelvin + "ey=abcdefgh12345",
		longS + "ession_state=abcdefgh12345",
		"'coo" + kelvin + "ie': 'abcdefgh12345'",
		"\"to" + kelvin + "en\" = abcdefgh12345",
	} {
		if d, err := EnforceOutbound(raw); err == nil || d.State == OutboundClean {
			t.Errorf("%q admitted: %s", raw, d.State)
		}
		if d, err := EnforceAdapterOutbound(raw); err == nil || d.State == OutboundClean {
			t.Errorf("adapter mode %q admitted: %s", raw, d.State)
		}
		var out strings.Builder
		if werr := WriteOutbound(&out, raw); werr == nil || out.Len() != 0 {
			t.Errorf("%q written: %q", raw, out.String())
		}
	}
	for _, raw := range []string{"--:--", "___:blue", "gr\u00f6\u00dfe=klein", "Kelvin=5" + kelvin} {
		if d, err := EnforceOutbound(raw); err != nil || d.State != OutboundClean {
			t.Errorf("control %q -> %s (err=%v)", raw, d.State, err)
		}
	}
}

// Review F9 (PR #29): word boundaries are judged on raw characters before
// folding, as \b in the former regex did (K U+212A and ſ U+017F are non-word
// characters). Kstate, ſkey and 0Key therefore expose their sensitive names
// (state, key, Key) and are refused in both modes with zero output.
func TestFoldedNamesKeepRawWordBoundaries(t *testing.T) {
	kelvin, longS := "\u212a", "\u017f"
	for _, raw := range []string{
		kelvin + "state=abcdefgh12345",
		longS + "key=abcdefgh12345",
		"0" + kelvin + "ey=abcdefgh12345",
		"'" + kelvin + "state': 'abcdefgh12345'",
		"\"0" + kelvin + "ey\" = abcdefgh12345",
	} {
		if d, err := EnforceOutbound(raw); err == nil || d.State == OutboundClean {
			t.Errorf("%q admitted: %s", raw, d.State)
		}
		if d, err := EnforceAdapterOutbound(raw); err == nil || d.State == OutboundClean {
			t.Errorf("adapter mode %q admitted: %s", raw, d.State)
		}
		var out strings.Builder
		if werr := WriteOutbound(&out, raw); werr == nil || out.Len() != 0 {
			t.Errorf("%q written: %q", raw, out.String())
		}
	}
}
