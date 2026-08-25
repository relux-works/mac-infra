package chromectl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

func TestDecodeSlackReadRequestUsesCompiledReadAllowlistAndBoundedArguments(t *testing.T) {
	valid := []string{
		`{"version":1,"method":"auth.test","args":{}}`,
		`{"version":1,"method":"conversations.list","args":{"limit":1,"exclude_archived":true,"types":"public_channel,private_channel"}}`,
		`{"version":1,"method":"conversations.info","args":{"channel":"C12345678","include_locale":true,"include_num_members":false}}`,
		`{"version":1,"method":"conversations.history","args":{"channel":"C12345678","cursor":"next-page","limit":100,"oldest":"1700000000.000001","latest":"1700000001.000002","inclusive":true,"include_all_metadata":false}}`,
		`{"version":1,"method":"conversations.replies","args":{"channel":"G12345678","ts":"1700000000.000001","cursor":"next-page","limit":1,"oldest":"1700000000.000001","latest":"1700000001.000002","inclusive":false,"include_all_metadata":true}}`,
		`{"version":1,"method":"users.list","args":{"cursor":"next-page","limit":100,"include_locale":true,"team_id":"T073GL82HJB"}}`,
		`{"version":1,"method":"search.messages","args":{"query":"deployment failure","count":100,"page":1000,"cursor":"next-page","sort":"timestamp","sort_dir":"desc","highlight":false,"team_id":"T073GL82HJB"}}`,
	}
	for _, input := range valid {
		if _, err := DecodeSlackReadRequest(strings.NewReader(input)); err != nil {
			t.Fatalf("valid request refused: %v", err)
		}
	}
	invalid := map[string]string{
		"write":          `{"version":1,"method":"chat.postMessage","args":{}}`,
		"unknown-read":   `{"version":1,"method":"admin.users.list","args":{}}`,
		"unknown-field":  `{"version":1,"method":"auth.test","args":{},"script":"localStorage"}`,
		"method-args":    `{"version":1,"method":"auth.test","args":{"token":"forged"}}`,
		"large-limit":    `{"version":1,"method":"conversations.list","args":{"limit":101}}`,
		"unknown-arg":    `{"version":1,"method":"conversations.list","args":{"channel":"C123"}}`,
		"trailing-value": `{"version":1,"method":"auth.test","args":{}} {}`,
	}
	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSlackReadRequest(strings.NewReader(input)); err == nil {
				t.Fatal("unsafe or malformed request was accepted")
			}
		})
	}
	oversized := `{"version":1,"method":"auth.test","args":{},"padding":"` + strings.Repeat("x", MaxSlackRequestBytes) + `"}`
	if _, err := DecodeSlackReadRequest(strings.NewReader(oversized)); SlackReadErrorKind(err) != "request-too-large" {
		t.Fatalf("oversized request error = %v", err)
	}
}

func TestSlackReadTypedArgumentBoundsAndWorkspaceConstraint(t *testing.T) {
	tests := map[string]SlackReadRequest{
		"info-missing-channel":        {Version: 1, Method: "conversations.info", Args: json.RawMessage(`{}`)},
		"info-malformed-channel":      {Version: 1, Method: "conversations.info", Args: json.RawMessage(`{"channel":"general"}`)},
		"history-limit-zero":          {Version: 1, Method: "conversations.history", Args: json.RawMessage(`{"channel":"C12345678","limit":0}`)},
		"history-limit-large":         {Version: 1, Method: "conversations.history", Args: json.RawMessage(`{"channel":"C12345678","limit":101}`)},
		"history-malformed-oldest":    {Version: 1, Method: "conversations.history", Args: json.RawMessage(`{"channel":"C12345678","oldest":"yesterday"}`)},
		"history-oversized-cursor":    {Version: 1, Method: "conversations.history", Args: json.RawMessage(`{"channel":"C12345678","cursor":"` + strings.Repeat("x", maxSlackCursorBytes+1) + `"}`)},
		"replies-missing-ts":          {Version: 1, Method: "conversations.replies", Args: json.RawMessage(`{"channel":"C12345678"}`)},
		"replies-malformed-ts":        {Version: 1, Method: "conversations.replies", Args: json.RawMessage(`{"channel":"C12345678","ts":"1700000000"}`)},
		"users-limit-large":           {Version: 1, Method: "users.list", Args: json.RawMessage(`{"limit":101}`)},
		"users-malformed-team":        {Version: 1, Method: "users.list", Args: json.RawMessage(`{"team_id":"workspace"}`)},
		"users-cross-workspace-team":  {Version: 1, Method: "users.list", Args: json.RawMessage(`{"team_id":"T12345678"}`)},
		"search-empty-query":          {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"  "}`)},
		"search-oversized-query":      {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"` + strings.Repeat("x", maxSlackSearchQuery+1) + `"}`)},
		"search-count-zero":           {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"safe","count":0}`)},
		"search-page-zero":            {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"safe","page":0}`)},
		"search-page-large":           {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"safe","page":1001}`)},
		"search-sort":                 {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"safe","sort":"channel"}`)},
		"search-sort-dir":             {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"safe","sort_dir":"sideways"}`)},
		"search-cross-workspace-team": {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"safe","team_id":"T12345678"}`)},
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := request.arguments("T073GL82HJB"); SlackReadErrorKind(err) != "invalid-arguments" {
				t.Fatalf("unsafe arguments error = %v", err)
			}
		})
	}
}

func TestSlackReadEveryArgumentDecoderRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	methods := map[string]string{
		"auth.test":             `{}`,
		"conversations.list":    `{}`,
		"conversations.info":    `{"channel":"C12345678"}`,
		"conversations.history": `{"channel":"C12345678"}`,
		"conversations.replies": `{"channel":"C12345678","ts":"1700000000.000001"}`,
		"users.list":            `{}`,
		"search.messages":       `{"query":"safe"}`,
	}
	for method, validArgs := range methods {
		t.Run(method+"/unknown", func(t *testing.T) {
			request := SlackReadRequest{Version: 1, Method: method, Args: json.RawMessage(`{"unknown":"value"}`)}
			if _, err := request.arguments("T073GL82HJB"); SlackReadErrorKind(err) != "invalid-arguments" {
				t.Fatalf("unknown field error = %v", err)
			}
		})
		t.Run(method+"/trailing", func(t *testing.T) {
			request := SlackReadRequest{Version: 1, Method: method, Args: json.RawMessage(validArgs + ` {}`)}
			if _, err := request.arguments("T073GL82HJB"); SlackReadErrorKind(err) != "invalid-arguments" {
				t.Fatalf("trailing JSON error = %v", err)
			}
		})
	}
}

func TestSlackReadKnownStringArgumentsRejectSecretShapes(t *testing.T) {
	tests := map[string]SlackReadRequest{
		"list-cursor":    {Version: 1, Method: "conversations.list", Args: json.RawMessage(`{"cursor":"Bearer abcdefghijklmnop"}`)},
		"history-cursor": {Version: 1, Method: "conversations.history", Args: json.RawMessage(`{"channel":"C12345678","cursor":"xoxc-12345678-secret"}`)},
		"search-query":   {Version: 1, Method: "search.messages", Args: json.RawMessage(`{"query":"abcdefghijkl.mnopqrstuvwx.yzABCDEFGHIJ"}`)},
	}
	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := request.arguments("T073GL82HJB"); SlackReadErrorKind(err) != "invalid-arguments" {
				t.Fatalf("secret-shaped argument error = %v", err)
			}
		})
	}
}

func TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv(t *testing.T) {
	captureDir := t.TempDir()
	start := slackEnvelope(t, "started", "")
	poll := slackEnvelope(t, "ok", `{"ok":true,"url":"https://example.slack.com/"}`)
	osa := writeSlackFakeOsa(t, start, poll, captureDir)
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	result, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Method != "auth.test" {
		t.Fatalf("method = %q", result.Method)
	}
	source, err := os.ReadFile(filepath.Join(captureDir, "start-source"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, want := range []string{
		`windows.whose({id:Number("11")})`,
		`tabs.whose({id:Number("22")})`,
		`location.origin !== __origin`,
		`location.pathname.startsWith`,
		`localStorage.getItem`,
		`localConfig_v2`,
		`__teams[__workspace]`,
		`fetch(`,
		`auth.test`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("atomic Slack source missing %q:\n%s", want, text)
		}
	}
	originGuard := strings.Index(text, `location.origin !== __origin`)
	workspaceGuard := strings.Index(text, `location.pathname.startsWith`)
	secretRead := strings.Index(text, `localStorage.getItem`)
	requestStart := strings.Index(text, `fetch(`)
	if originGuard < 0 || workspaceGuard < 0 || secretRead < 0 || requestStart < 0 ||
		originGuard > secretRead || workspaceGuard > secretRead || originGuard > requestStart || workspaceGuard > requestStart {
		t.Fatalf("start evaluation does not atomically guard origin/workspace before secret lookup and fetch:\n%s", text)
	}
	for _, forbidden := range []string{"activate", "frontmost", "activeTabIndex", "System Events", "set visible"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("silent Slack source contains focus mutation %q", forbidden)
		}
	}
	argv, err := os.ReadFile(filepath.Join(captureDir, "argv"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(argv), "auth.test") || strings.Contains(string(argv), "T073GL82HJB") || strings.Contains(string(argv), "localConfig") {
		t.Fatalf("request or browser schema leaked to osascript argv: %s", argv)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(argv)), "\n") {
		if line != "-l JavaScript" {
			t.Fatalf("unexpected osascript argv %q", line)
		}
	}
}

func TestSlackReadOriginAndWorkspaceDriftFailBeforePolling(t *testing.T) {
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	for _, outcome := range []string{"origin-mismatch", "workspace-mismatch"} {
		t.Run(outcome, func(t *testing.T) {
			captureDir := t.TempDir()
			osa := writeSlackFakeOsa(t, slackEnvelope(t, outcome, ""), slackEnvelope(t, "ok", `{"ok":true}`), captureDir)
			_, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
			if kind := SlackReadErrorKind(err); kind != outcome {
				t.Fatalf("error kind = %q, want %q (%v)", kind, outcome, err)
			}
			source, err := os.ReadFile(filepath.Join(captureDir, "source"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(source), "--call--") != 1 {
				t.Fatalf("refused start unexpectedly polled or retried:\n%s", source)
			}
		})
	}
}

func TestSlackReadMissingStorageSchemaFailsCapabilityUnavailable(t *testing.T) {
	osa := writeSlackFakeOsa(t, slackEnvelope(t, "capability-unavailable", ""), "", t.TempDir())
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	_, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
	if kind := SlackReadErrorKind(err); kind != "capability-unavailable" {
		t.Fatalf("error kind = %q (%v)", kind, err)
	}
}

func TestSlackReadRefusesMalformedPendingTimeoutAndMissingTarget(t *testing.T) {
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	t.Run("malformed", func(t *testing.T) {
		osa := writeSlackFakeOsa(t, `{"outcome":"started"}`, "", t.TempDir())
		_, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
		if kind := SlackReadErrorKind(err); kind != "response-invalid" {
			t.Fatalf("error kind = %q (%v)", kind, err)
		}
	})
	t.Run("malformed-response-json", func(t *testing.T) {
		osa := writeSlackFakeOsa(t, slackEnvelope(t, "started", ""), slackEnvelope(t, "ok", `{"unterminated":`), t.TempDir())
		_, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
		if kind := SlackReadErrorKind(err); kind != "response-invalid" {
			t.Fatalf("error kind = %q (%v)", kind, err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		osa := writeSlackFakeOsa(t, slackEnvelope(t, "started", ""), slackEnvelope(t, "pending", ""), t.TempDir())
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		defer cancel()
		_, err := (Session{OsaScriptPath: osa}).SlackRead(ctx, "11", "22", SlackOrigin, "T073GL82HJB", request)
		if kind := SlackReadErrorKind(err); kind != "timeout" {
			t.Fatalf("error kind = %q (%v)", kind, err)
		}
	})
	t.Run("target-missing", func(t *testing.T) {
		osa := filepath.Join(t.TempDir(), "osascript")
		if err := os.WriteFile(osa, []byte("#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' 'Chrome target tab is no longer open' >&2\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		_, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
		if !errors.Is(err, browsersession.ErrTargetMissing) || SlackReadErrorKind(err) != "target-missing" {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestSlackReadProductionPathRecursivelyRedactsSecrets(t *testing.T) {
	response := `{"ok":true,"auth_token":{"prefix":"safe","nested":["still","sensitive"]},"nested":{"authorization":"Bearer abcdefghijklmnop","safe":"ordinary"},"items":[{"api_key":["composite","secret"],"url":"https://example.com/path?code=secret&keep=ok#private"}]}`
	data := slackReadProductionData(t, response)
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	for _, leaked := range []string{"Bearer abcdefghijklmnop", `"prefix":"safe"`, `"api_key":[`, "code=secret", "keep=ok", "#private"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("sanitized response leaked %q: %s", leaked, text)
		}
	}
	if strings.Count(text, "redacted") < 4 || strings.Contains(text, "keep=ok") {
		t.Fatalf("expected recursive redactions with a closed query: %s", text)
	}
}

func TestSlackReadProductionPathPreservesNonSecretBytesAroundEveryTokenSpan(t *testing.T) {
	const (
		slackToken = "xoxc-12345678-secret"
		appToken   = "xapp-1-abcdefgh-12345678"
		bearer     = "Bearer abcdefghijklmnop"
		jwt        = "abcdefghijkl.mnopqrstuvwx.yzABCDEFGHIJ"
	)
	input := map[string]any{
		"standalone":  slackToken,
		"surrounded":  "before " + slackToken + " after",
		"repeated":    slackToken + " middle " + slackToken,
		"adjacent":    slackToken + "|" + bearer + "|" + jwt,
		"punctuation": "(" + appToken + ");",
		"unicode":     "Привет " + slackToken + " мир",
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got := slackReadProductionData(t, string(raw))
	want := map[string]string{
		"standalone":  "[redacted]",
		"surrounded":  "before [redacted] after",
		"repeated":    "[redacted] middle [redacted]",
		"adjacent":    "[redacted]|[redacted]|[redacted]",
		"punctuation": "([redacted]);",
		"unicode":     "Привет [redacted] мир",
	}
	for key, expected := range want {
		if actual, ok := got[key].(string); !ok || actual != expected {
			t.Errorf("%s = %#v, want %q", key, got[key], expected)
		}
	}
}

func TestSlackReadProductionPathSanitizesNestedSecretShapedKeysAndPreservesSafeKeys(t *testing.T) {
	const (
		safeKey     = "safe.key-_ Space"
		slackToken  = "xoxb-12345678-keyvalue"
		secretNamed = "xoxb-12345678-secret"
		bearer      = "Bearer abcdefghijklmnop"
		jwt         = "abcdefghijkl.mnopqrstuvwx.yzABCDEFGHIJ"
	)
	input := map[string]any{
		safeKey: []any{map[string]any{
			"slack " + slackToken:  "slack-value",
			"bearer " + bearer:     "bearer-value",
			"jwt " + jwt:           "jwt-value",
			"glued a" + slackToken: "glued-slack-value",
			"glued zz" + bearer:    "glued-bearer-value",
			"glued x" + jwt:        "glued-jwt-value",
			secretNamed:            map[string]any{"must-not-survive": true},
			"refs " + slackToken + " " + bearer + " " + jwt: "all-value",
		}},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	got := slackReadProductionData(t, string(raw))
	nested, ok := got[safeKey].([]any)
	if !ok || len(nested) != 1 {
		t.Fatalf("safe key changed or nested array lost: %#v", got)
	}
	object, ok := nested[0].(map[string]any)
	if !ok {
		t.Fatalf("nested object type = %T", nested[0])
	}
	want := map[string]any{
		"slack [redacted]":                      "slack-value",
		"bearer [redacted]":                     "bearer-value",
		"jwt [redacted]":                        "jwt-value",
		"glued a[redacted]":                     "glued-slack-value",
		"glued zz[redacted]":                    "glued-bearer-value",
		"glued [redacted]":                      "glued-jwt-value",
		"[redacted]":                            "[redacted]",
		"refs [redacted] [redacted] [redacted]": "all-value",
	}
	if !reflect.DeepEqual(object, want) {
		t.Fatalf("sanitized nested object = %#v", object)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{slackToken, bearer, jwt} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("Session.SlackRead leaked secret-shaped key bytes %q: %s", forbidden, encoded)
		}
	}
}

func TestSlackReadProductionPathFailsClosedOnRedactedKeyCollisions(t *testing.T) {
	const (
		slackToken = "xoxb-12345678-keyvalue"
		bearer     = "Bearer abcdefghijklmnop"
	)
	cases := map[string]any{
		"safe-redacted-key": map[string]any{
			slackToken:   "secret-shaped",
			"[redacted]": "safe-original",
		},
		"two-secret-shaped-keys": map[string]any{
			"before " + slackToken + " after": "slack",
			"before " + bearer + " after":     "bearer",
		},
		"nested-object": map[string]any{
			"outer": []any{map[string]any{
				slackToken:   1,
				"[redacted]": 2,
			}},
		},
		"secret-branch-collision": map[string]any{
			slackToken + "_token": 1,
			"[redacted]_token":    2,
		},
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			osa := writeSlackFakeOsa(t, slackEnvelope(t, "started", ""), slackEnvelope(t, "ok", string(raw)), t.TempDir())
			request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
			result, err := (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
			if kind := SlackReadErrorKind(err); kind != "response-key-collision" {
				t.Fatalf("Session.SlackRead collision error = %q (%v), result = %#v", kind, err, result)
			}
			if result.Data != nil {
				t.Fatalf("collision returned partial data: %#v", result.Data)
			}
		})
	}
}

func TestSlackReadProductionPathFailsClosedOnIdenticalDuplicateSecretShapedKeys(t *testing.T) {
	const secretKey = "xoxb-12345678-keyvalue"
	response := `{"` + secretKey + `":"first-value","` + secretKey + `":"second-value"}`

	result, err := slackReadProductionResult(t, response)
	if kind := SlackReadErrorKind(err); kind != "response-key-collision" {
		t.Fatalf("Session.SlackRead duplicate-key error = %q (%v), result = %#v", kind, err, result)
	}
	if result.Data != nil {
		t.Fatalf("duplicate-key refusal returned partial data: %#v", result.Data)
	}
}

func TestSlackReadProductionPathFailsClosedOnEquivalentEscapedDuplicateKeys(t *testing.T) {
	const response = `{"xoxb-12345678-keyvalue":"literal","xoxb-12345678-\u006beyvalue":"escaped"}`

	result, err := slackReadProductionResult(t, response)
	if kind := SlackReadErrorKind(err); kind != "response-key-collision" {
		t.Fatalf("Session.SlackRead escaped duplicate-key error = %q (%v), result = %#v", kind, err, result)
	}
	if result.Data != nil {
		t.Fatalf("escaped duplicate-key refusal returned partial data: %#v", result.Data)
	}
}

func TestSlackReadProductionPathFailsClosedOnNestedDuplicateSecretShapedKeys(t *testing.T) {
	const response = `{"outer":[{"Bearer abcdefghijklmnop":"first","Bearer abcdefghijklmnop":"second"}]}`

	result, err := slackReadProductionResult(t, response)
	if kind := SlackReadErrorKind(err); kind != "response-key-collision" {
		t.Fatalf("Session.SlackRead nested duplicate-key error = %q (%v), result = %#v", kind, err, result)
	}
	if result.Data != nil {
		t.Fatalf("nested duplicate-key refusal returned partial data: %#v", result.Data)
	}
}

func TestSlackReadProductionPathCountsDuplicateMembersAgainstRawNodeBound(t *testing.T) {
	response := `{` + strings.TrimSuffix(strings.Repeat(`"a":0,`, maxSlackResponseNodes+1), ",") + `}`
	if len(response) > MaxSlackResponseBytes {
		t.Fatalf("duplicate-member response bytes = %d, exceeds %d-byte response ceiling", len(response), MaxSlackResponseBytes)
	}

	result, err := slackReadProductionResult(t, response)
	if kind := SlackReadErrorKind(err); kind != "response-too-complex" {
		t.Fatalf("Session.SlackRead raw-node error = %q (%v), result = %#v", kind, err, result)
	}
	if result.Data != nil {
		t.Fatalf("raw-node refusal returned partial data: %#v", result.Data)
	}
}

func TestSlackReadProductionPathBearerClassCannotBeNarrowed(t *testing.T) {
	got := slackReadProductionData(t, `{"text":"before Bearer abcdefghijklmnop after"}`)
	if got["text"] != "before [redacted] after" {
		t.Fatalf("text = %#v", got["text"])
	}
}

func TestSlackReadProductionPathEveryOccurrenceCannotBeNarrowed(t *testing.T) {
	got := slackReadProductionData(t, `{"text":"xoxc-12345678-first/xoxc-87654321-second"}`)
	if got["text"] != "[redacted]/[redacted]" {
		t.Fatalf("text = %#v", got["text"])
	}
}

func TestSlackReadProductionPathRedactsTokenSpansWithAlphanumericGlue(t *testing.T) {
	got := slackReadProductionData(t, `{"values":["axoxb-12345678-secretvalue","idxapp-1-abcdefgh-12345678","zzBearer abcdefghijklmnop","xabcdefghijkl.mnopqrstuvwx.yzABCDEFGHIJ"]}`)
	want := []any{"a[redacted]", "id[redacted]", "zz[redacted]", "[redacted]"}
	if !reflect.DeepEqual(got["values"], want) {
		t.Fatalf("glued token spans = %#v, want %#v", got["values"], want)
	}
}

func TestSlackReadProductionPathWholeStringRedactionCannotReturn(t *testing.T) {
	got := slackReadProductionData(t, `{"text":"REF-SYN-4242 before xapp-1-abcdefgh-12345678 after"}`)
	if got["text"] != "REF-SYN-4242 before [redacted] after" {
		t.Fatalf("text = %#v", got["text"])
	}
}

func TestSlackReadProductionPathRescansAfterRejectedTokenStart(t *testing.T) {
	got := slackReadProductionData(t, `{"xapp":"9xapp-xapp-12345678secret","xox":"tag9xoxb-xoxb-12345678secret end"}`)
	if got["xapp"] != "9[redacted]" {
		t.Fatalf("xapp = %#v", got["xapp"])
	}
	if got["xox"] != "tag9[redacted] end" {
		t.Fatalf("xox = %#v", got["xox"])
	}
}

func TestSlackReadProductionPathRedactsEveryCompactTokenSegment(t *testing.T) {
	got := slackReadProductionData(t, `{"text":"before aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc.dddddddddddd.eeeeeeeeeeee after"}`)
	if got["text"] != "before [redacted] after" {
		t.Fatalf("text = %#v", got["text"])
	}
}

func TestSlackReadProductionPathUnionsOverlappingSecretSpans(t *testing.T) {
	got := slackReadProductionData(t, `{"text":"pre Bearer xoxc-12345678-secret post"}`)
	if got["text"] != "pre [redacted] post" {
		t.Fatalf("text = %#v", got["text"])
	}
}

func TestSlackReadProductionPathUnionsPartiallyOverlappingSecretSpans(t *testing.T) {
	got := slackReadProductionData(t, `{"text":"REF-SYN-4242 aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc-Bearer abcdefghij tail"}`)
	if got["text"] != "REF-SYN-4242 [redacted] tail" {
		t.Fatalf("text = %#v", got["text"])
	}
}

func TestSlackReadProductionPathRedactsTokenInURLPath(t *testing.T) {
	got := slackReadProductionData(t, `{"url":"https://example.com/p/xoxb-12345678-secret"}`)
	if got["url"] != "https://example.com/p/[redacted]" {
		t.Fatalf("url = %#v", got["url"])
	}
}

func TestSlackReadProductionPathAtResponseCeilingMeetsCostBound(t *testing.T) {
	const (
		responsePrefix = `{"text":"`
		responseSuffix = `"}`
		token          = "xapp-1-abcdefgh-12345678"
		costBound      = 3 * time.Second
	)
	bodyBytes := MaxSlackResponseBytes - len(responsePrefix) - len(responseSuffix)
	hostilePrefixBytes := bodyBytes - len(token) - 1
	hostilePrefix := strings.Repeat("9xapp-", hostilePrefixBytes/len("9xapp-")) +
		strings.Repeat("9", hostilePrefixBytes%len("9xapp-")) + "|"
	response := responsePrefix + hostilePrefix + token + responseSuffix
	if len(response) != MaxSlackResponseBytes {
		t.Fatalf("response bytes = %d, want %d", len(response), MaxSlackResponseBytes)
	}

	osa := writeSlackFakeOsa(t, slackEnvelope(t, "started", ""), slackEnvelope(t, "ok", response), t.TempDir())
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	type outcome struct {
		result SlackReadResult
		err    error
	}
	result := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), costBound)
	defer cancel()
	go func() {
		got, err := (Session{OsaScriptPath: osa}).SlackRead(ctx, "11", "22", SlackOrigin, "T073GL82HJB", request)
		result <- outcome{result: got, err: err}
	}()

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		data, ok := got.result.Data.(map[string]any)
		if !ok {
			t.Fatalf("data type = %T", got.result.Data)
		}
		text, ok := data["text"].(string)
		if !ok || !strings.HasSuffix(text, slackRedactedMarker) || strings.Contains(strings.ToLower(text), "xapp-") || containsTokenShape(text) {
			t.Fatalf("sanitized text retained a token-shaped span at the response ceiling")
		}
	case <-ctx.Done():
		t.Fatalf("production SlackRead exceeded %s at the %d-byte response ceiling", costBound, MaxSlackResponseBytes)
	}
}

func TestSlackReadProductionPathSanitizesKeyAtResponseCeilingWithinCostBound(t *testing.T) {
	const (
		responsePrefix = `{"`
		responseSuffix = `":true}`
		token          = "xapp-1-abcdefgh-12345678"
		costBound      = 3 * time.Second
	)
	keyBytes := MaxSlackResponseBytes - len(responsePrefix) - len(responseSuffix)
	hostilePrefixBytes := keyBytes - len(token) - 1
	hostilePrefix := strings.Repeat("9xapp-", hostilePrefixBytes/len("9xapp-")) +
		strings.Repeat("9", hostilePrefixBytes%len("9xapp-")) + "|"
	response := responsePrefix + hostilePrefix + token + responseSuffix
	if len(response) != MaxSlackResponseBytes {
		t.Fatalf("response bytes = %d, want %d", len(response), MaxSlackResponseBytes)
	}

	osa := writeSlackFakeOsa(t, slackEnvelope(t, "started", ""), slackEnvelope(t, "ok", response), t.TempDir())
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	type outcome struct {
		result SlackReadResult
		err    error
	}
	result := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(context.Background(), costBound)
	defer cancel()
	go func() {
		got, err := (Session{OsaScriptPath: osa}).SlackRead(ctx, "11", "22", SlackOrigin, "T073GL82HJB", request)
		result <- outcome{result: got, err: err}
	}()

	select {
	case got := <-result:
		if got.err != nil {
			t.Fatal(got.err)
		}
		data, ok := got.result.Data.(map[string]any)
		if !ok {
			t.Fatalf("data type = %T", got.result.Data)
		}
		if len(data) != 1 {
			t.Fatalf("sanitized response keys = %d, want 1", len(data))
		}
		for key, value := range data {
			if value != true || !strings.HasSuffix(key, slackRedactedMarker) || strings.Contains(strings.ToLower(key), "xapp-") || containsTokenShape(key) {
				t.Fatalf("sanitized key retained a token-shaped span at the response ceiling")
			}
		}
	case <-ctx.Done():
		t.Fatalf("production SlackRead key sanitization exceeded %s at the %d-byte response ceiling", costBound, MaxSlackResponseBytes)
	}
}

func TestSlackReadProductionPathRejectsNestedTokenStartBeforeBrowserExecution(t *testing.T) {
	request := SlackReadRequest{
		Version: SlackReadVersion,
		Method:  "search.messages",
		Args:    json.RawMessage(`{"query":"9xapp-xapp-12345678secret"}`),
	}
	_, err := (Session{OsaScriptPath: filepath.Join(t.TempDir(), "must-not-execute")}).SlackRead(
		context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request,
	)
	if SlackReadErrorKind(err) != "invalid-arguments" {
		t.Fatalf("secret-shaped request reached browser execution: %v", err)
	}
}

func TestSlackTokenSpanSanitizerLeavesNoTokenInRandomizedDifferentialCorpus(t *testing.T) {
	legacySlack := regexp.MustCompile(`(?i)(^|[^a-z0-9])(xox[a-z]-[a-z0-9-]{8,}|xapp-[a-z0-9-]{8,})($|[^a-z0-9])`)
	legacyBearer := regexp.MustCompile(`(?i)(^|[^a-z0-9])bearer[[:space:]]+[a-z0-9._~+/=-]{8,}`)
	legacyJWT := regexp.MustCompile(`(^|[^A-Za-z0-9_-])[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}($|[^A-Za-z0-9_-])`)
	unboundedToken := regexp.MustCompile(`(?i)(?:xox[a-z]-[a-z0-9-]{8,}|xapp-[a-z0-9-]{8,}|bearer[[:space:]]+[a-z0-9._~+/=-]{8,}|[a-z0-9_-]{12,}\.[a-z0-9_-]{12,}\.[a-z0-9_-]{12,}(?:\.[a-z0-9_-]+)*)`)
	legacyContainsTokenShape := func(value string) bool {
		return legacySlack.MatchString(value) || legacyBearer.MatchString(value) || legacyJWT.MatchString(value)
	}

	parts := []string{
		"xox", "xoxb-12345678-secret", "xapp-", "xapp-1-abcdefgh-12345678",
		"Bearer ", "abcdefghijkl", ".", "-", "_", "9", "a", " ", "|", "Ж", "🔐",
	}
	random := rand.New(rand.NewSource(260825))
	corpusHits := 0
	for index := 0; index < 200_000; index++ {
		var value strings.Builder
		for count := 1 + random.Intn(12); count > 0; count-- {
			value.WriteString(parts[random.Intn(len(parts))])
		}
		input := value.String()
		if !legacyContainsTokenShape(input) && !unboundedToken.MatchString(input) {
			continue
		}
		corpusHits++
		sanitized := sanitizeSlackString(input)
		if legacyContainsTokenShape(sanitized) || unboundedToken.MatchString(sanitized) || containsTokenShape(sanitized) {
			t.Fatalf("sanitizer left a token-shaped span in corpus case %d", index)
		}
	}
	if corpusHits == 0 {
		t.Fatal("differential corpus did not exercise a token-shaped span")
	}
	t.Logf("sanitizer removed every token-shaped span from %d corpus cases across 200000 inputs", corpusHits)
}

func TestSanitizeSlackResponsePreservesURLPolicyAndStructuredSecretKeys(t *testing.T) {
	const sensitiveURL = "https://example.com/path?code=secret&keep=ok#private"
	got, err := sanitizeSlackResponse([]byte(`{"url":"` + sensitiveURL + `","access_token":{"safe":"must not survive"}}`))
	if err != nil {
		t.Fatal(err)
	}
	data := got.(map[string]any)
	if data["url"] != browsersession.RedactSensitiveURL(sensitiveURL) {
		t.Fatalf("url = %#v", data["url"])
	}
	if data["access_token"] != "[redacted]" {
		t.Fatalf("access_token = %#v", data["access_token"])
	}
	wrappedURL := "  " + sensitiveURL + "  "
	if got := sanitizeSlackString(wrappedURL); got != "  "+browsersession.RedactSensitiveURL(sensitiveURL)+"  " {
		t.Fatalf("whitespace-wrapped URL = %q", got)
	}
}

func TestSanitizeSlackResponseBoundsDepthAndSize(t *testing.T) {
	deep := strings.Repeat(`{"x":`, maxSlackResponseDepth+1) + `true` + strings.Repeat(`}`, maxSlackResponseDepth+1)
	if _, err := sanitizeSlackResponse([]byte(deep)); SlackReadErrorKind(err) != "response-too-deep" {
		t.Fatalf("deep response error = %v", err)
	}
	large := []byte(`"` + strings.Repeat("x", MaxSlackResponseBytes) + `"`)
	if _, err := sanitizeSlackResponse(large); SlackReadErrorKind(err) != "response-too-large" {
		t.Fatalf("large response error = %v", err)
	}
	nodes := `[` + strings.TrimSuffix(strings.Repeat(`0,`, maxSlackResponseNodes+1), ",") + `]`
	if _, err := sanitizeSlackResponse([]byte(nodes)); SlackReadErrorKind(err) != "response-too-complex" {
		t.Fatalf("complex response error = %v", err)
	}
	for _, malformed := range []string{`{"unterminated":`, `{"one":1} {"two":2}`} {
		if _, err := sanitizeSlackResponse([]byte(malformed)); SlackReadErrorKind(err) != "response-invalid" {
			t.Fatalf("malformed response error = %v", err)
		}
	}
}

func slackReadProductionData(t *testing.T, response string) map[string]any {
	t.Helper()
	result, err := slackReadProductionResult(t, response)
	if err != nil {
		t.Fatal(err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("data type = %T", result.Data)
	}
	return data
}

func slackReadProductionResult(t *testing.T, response string) (SlackReadResult, error) {
	t.Helper()
	osa := writeSlackFakeOsa(t, slackEnvelope(t, "started", ""), slackEnvelope(t, "ok", response), t.TempDir())
	request := SlackReadRequest{Version: SlackReadVersion, Method: "auth.test", Args: json.RawMessage(`{}`)}
	return (Session{OsaScriptPath: osa}).SlackRead(context.Background(), "11", "22", SlackOrigin, "T073GL82HJB", request)
}

func slackEnvelope(t *testing.T, outcome, response string) string {
	t.Helper()
	value := slackPageEnvelope{Sentinel: slackReadGuardSentinel, Outcome: outcome, Response: response}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeSlackFakeOsa(t *testing.T, start, poll, captureDir string) string {
	t.Helper()
	if err := os.MkdirAll(captureDir, 0o700); err != nil {
		t.Fatal(err)
	}
	startPath := filepath.Join(captureDir, "start.json")
	pollPath := filepath.Join(captureDir, "poll.json")
	if err := os.WriteFile(startPath, []byte(start+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pollPath, []byte(poll+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(captureDir, "osascript")
	script := `#!/bin/sh
set -eu
source=$(cat)
printf '%s\n--call--\n' "$source" >> "` + filepath.Join(captureDir, "source") + `"
printf '%s\n' "$*" >> "` + filepath.Join(captureDir, "argv") + `"
case "$source" in
  *localConfig_v2*)
    printf '%s\n' "$source" > "` + filepath.Join(captureDir, "start-source") + `"
    /bin/cat "` + startPath + `"
    ;;
  *)
    printf '%s\n' "$source" > "` + filepath.Join(captureDir, "poll-source") + `"
    /bin/cat "` + pollPath + `"
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
