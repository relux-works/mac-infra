package chromectl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

func validTrustedRequest() TrustedInputRequest {
	return TrustedInputRequest{
		Version:        TrustedInputVersion,
		InputSelector:  `input[placeholder="Search"]`,
		Text:           "bounded test text",
		OptionSelector: `[role="option"]`,
		OptionText:     "Named option",
		TimeoutMS:      1000,
	}
}

func TestDecodeTrustedInputRequestRejectsUnknownTrailingAndUnsafeShapes(t *testing.T) {
	tests := map[string]string{
		"unknown":          `{"version":1,"inputSelector":"input","text":"safe","unexpected":true}`,
		"trailing":         `{"version":1,"inputSelector":"input","text":"safe"}{}`,
		"missing-text":     `{"version":1,"inputSelector":"input","text":""}`,
		"control-text":     `{"version":1,"inputSelector":"input","text":"line\nfeed"}`,
		"partial-option":   `{"version":1,"inputSelector":"input","text":"safe","optionText":"named"}`,
		"bad-timeout":      `{"version":1,"inputSelector":"input","text":"safe","timeoutMs":499}`,
		"unknown-version":  `{"version":2,"inputSelector":"input","text":"safe"}`,
		"control-selector": `{"version":1,"inputSelector":"input\tbad","text":"safe"}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTrustedInputRequest(strings.NewReader(input)); err == nil {
				t.Fatal("unsafe request was accepted")
			}
		})
	}
	tooLarge := `{"version":1,"inputSelector":"input","text":"` + strings.Repeat("a", maxTrustedRequest) + `"}`
	if _, err := DecodeTrustedInputRequest(strings.NewReader(tooLarge)); err == nil {
		t.Fatal("oversized request was accepted")
	}
}

func TestDecodeTrustedInputRequestAppliesBoundedDefault(t *testing.T) {
	request, err := DecodeTrustedInputRequest(strings.NewReader(`{"version":1,"inputSelector":"input[type=search]","text":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	if request.TimeoutMS != defaultTimeoutMS {
		t.Fatalf("timeout=%d want=%d", request.TimeoutMS, defaultTimeoutMS)
	}
}

func TestTrustedInputProductionMethodKeepsValuesOutOfArgvAndUsesExactAXBridge(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "args")
	sourcePath := filepath.Join(dir, "source")
	pressMarker := filepath.Join(dir, "pressed")
	t.Setenv("ARGS_PATH", argsPath)
	t.Setenv("SOURCE_PATH", sourcePath)
	t.Setenv("PRESS_MARKER", pressMarker)
	osa := writeFakeOsaScript(t, `
printf '%s\n' "$@" >> "$ARGS_PATH"
case "$*" in
  *chrome-exact-target*)
    printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"ok","origin":"https://example.com","title":"Example page","active":true}'
    ;;
  *)
    source=$(cat)
    printf '%s\n' "$source" >> "$SOURCE_PATH"
    case "$source" in
      *oldInputAria*) value='ready' ;;
      *trustedOptionClick*)
        if [ -f "$PRESS_MARKER" ]; then value='{"outcome":"selected"}'; else value='{"outcome":"option-ready"}'; fi
        ;;
      *) value='cleaned' ;;
    esac
    emit_value "$value"
    ;;
esac`)
	request := validTrustedRequest()
	var calls []string
	var setDescription, setValue, pressDescription string
	session := Session{
		OsaScriptPath: osa,
		AXProcessID:   func() (int, error) { return 123, nil },
		AXTypeText: func(pid int, description, value string) error {
			if pid != 123 {
				t.Fatalf("AX set target pid=%d", pid)
			}
			calls = append(calls, "type-text")
			setDescription, setValue = description, value
			return nil
		},
		AXPress: func(pid int, description string) error {
			if pid != 123 {
				t.Fatalf("AX press target pid=%d", pid)
			}
			calls = append(calls, "press")
			pressDescription = description
			return os.WriteFile(pressMarker, nil, 0o600)
		},
	}
	result, err := session.TrustedInput(context.Background(), "11", "22", "https://example.com", request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || !result.Typed || !result.Selected {
		t.Fatalf("result=%+v", result)
	}
	if got := strings.Join(calls, ","); got != "type-text,press" {
		t.Fatalf("trusted-input native call order=%q want input before selection", got)
	}
	if setValue != request.Text || !strings.HasPrefix(setDescription, "works.relux.mac-infra-input-") || !strings.HasPrefix(pressDescription, "works.relux.mac-infra-option-") {
		t.Fatalf("AX bridge did not receive bounded exact nonces: set=%q press=%q", setDescription, pressDescription)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(args), request.Text) || strings.Contains(string(args), request.OptionText) {
		t.Fatalf("authorized values leaked into process argv: %s", args)
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`event.isTrusted`, `trustedInput`, `trustedOptionClick`, `setAttribute`, `aria-label`, request.Text, request.OptionText, `options.length`, `20`} {
		if !strings.Contains(string(source), want) {
			t.Fatalf("trusted-input private production source missing %q", want)
		}
	}
	for _, forbidden := range []string{"clipboard", "pbcopy", "System Events", "keystroke", "keyCode", "screenX", "screenY"} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("trusted-input source contains forbidden fallback %q", forbidden)
		}
	}
}

func TestTrustedInputProductionMethodPreparesBeforeFinalExactFocus(t *testing.T) {
	dir := t.TempDir()
	preparedPath := filepath.Join(dir, "prepared")
	t.Setenv("PREPARED_PATH", preparedPath)
	osa := writeFakeOsaScript(t, `
case "$*" in
  *chrome-exact-target*)
    if [ ! -f "$PREPARED_PATH" ]; then printf '%s\n' '{}'; exit 0; fi
    printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"ok","origin":"https://example.com","active":true}'
    ;;
  *)
    source=$(cat)
    case "$source" in
      *oldInputAria*) touch "$PREPARED_PATH"; value='ready' ;;
      *state.trustedInput*) value='{"outcome":"typed"}' ;;
      *) value='cleaned' ;;
    esac
    emit_value "$value"
    ;;
esac`)
	typed := false
	request := validTrustedRequest()
	request.OptionSelector = ""
	request.OptionText = ""
	session := Session{
		OsaScriptPath: osa,
		AXProcessID:   func() (int, error) { return 123, nil },
		AXTypeText: func(int, string, string) error {
			typed = true
			return nil
		},
	}
	result, err := session.TrustedInput(context.Background(), "11", "22", "https://example.com", request)
	if err != nil {
		t.Fatal(err)
	}
	if !typed || !result.OK || !result.Typed {
		t.Fatalf("trusted input did not prepare before exact focus and native type: typed=%v result=%+v", typed, result)
	}
}

func TestTrustedInputProductionMethodRefusesForegroundDriftBeforeNativePress(t *testing.T) {
	dir := t.TempDir()
	countPath := filepath.Join(dir, "exact-count")
	t.Setenv("COUNT_PATH", countPath)
	osa := writeFakeOsaScript(t, `
case "$*" in
  *chrome-exact-target*)
    count=0; if [ -f "$COUNT_PATH" ]; then count=$(cat "$COUNT_PATH"); fi; count=$((count+1)); printf '%s' "$count" > "$COUNT_PATH"
	    if [ "$count" -lt 3 ]; then active=true; else active=false; fi
    printf '%s\n' "{\"__macChromeExactTarget\":\"works.relux.mac-infra/chrome-exact-target/v1\",\"outcome\":\"ok\",\"origin\":\"https://example.com\",\"title\":\"Duplicate title\",\"active\":$active}"
    ;;
  *)
    source=$(cat)
    case "$source" in
      *oldInputAria*) value='ready' ;;
      *trustedOptionClick*) value='{"outcome":"option-ready"}' ;;
      *) value='cleaned' ;;
    esac
    emit_value "$value"
    ;;
esac`)
	pressCalled := false
	session := Session{
		OsaScriptPath: osa,
		AXProcessID:   func() (int, error) { return 123, nil },
		AXTypeText:    func(int, string, string) error { return nil },
		AXPress: func(int, string) error {
			pressCalled = true
			return nil
		},
	}
	_, err := session.TrustedInput(context.Background(), "11", "22", "https://example.com", validTrustedRequest())
	if !errors.Is(err, browsersession.ErrTargetMissing) {
		t.Fatalf("foreground drift error=%v want ErrTargetMissing", err)
	}
	if pressCalled {
		t.Fatal("production TrustedInput called AXPress after exact target lost foreground focus")
	}
}

func TestTrustedInputOriginAndMalformedTargetAttestationsFailBeforeAX(t *testing.T) {
	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "origin", body: `printf '%s\n' '{"__macChromeExactTarget":"works.relux.mac-infra/chrome-exact-target/v1","outcome":"origin-mismatch","origin":"https://drift.example"}'`, want: browsersession.ErrOriginMismatch},
		{name: "malformed", body: `printf '%s\n' '{}'`, want: browsersession.ErrUnreadableResponse},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			osa := writeFakeOsaScript(t, `
case "$*" in
  *chrome-exact-target*) `+tc.body+` ;;
  *)
    cat >/dev/null
    emit_value ready
    ;;
esac`)
			axCalled := false
			session := Session{
				OsaScriptPath: osa,
				AXProcessID: func() (int, error) {
					axCalled = true
					return 123, nil
				},
			}
			_, err := session.TrustedInput(context.Background(), "11", "22", "https://example.com", validTrustedRequest())
			if !errors.Is(err, tc.want) {
				t.Fatalf("error=%v want=%v", err, tc.want)
			}
			if axCalled {
				t.Fatal("failed exact-target attestation reached Accessibility")
			}
		})
	}
}

func TestTrustedInputRejectsNonExactTargetBeforeAutomation(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	osa := writeFakeOsaScript(t, `touch "$MARKER"; exit 99`)
	for _, target := range [][3]string{{"0", "22", "https://example.com"}, {"11", "bad", "https://example.com"}, {"11", "22", "https://example.com/path"}, {"11", "22", ""}} {
		if _, err := (Session{OsaScriptPath: osa}).TrustedInput(context.Background(), target[0], target[1], target[2], validTrustedRequest()); err == nil {
			t.Fatalf("invalid target admitted: %q", target)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("invalid exact target reached osascript: %v", err)
	}
}

func TestTrustedInputInspectionRecognizesTrustedSelectionBeforeTypedQueryDrift(t *testing.T) {
	source := trustedInspectJavaScript("input", "state-key")
	selected := strings.Index(source, `state.trustedOptionClick&&normalize(input.value)===normalize(state.request.optionText)`)
	typedQuery := strings.Index(source, `String(input.value)!==String(state.request.text)`)
	if selected < 0 || typedQuery < 0 || selected >= typedQuery {
		t.Fatalf("trusted selected-value attestation must precede the typed-query drift refusal: selected=%d typed=%d", selected, typedQuery)
	}
}
