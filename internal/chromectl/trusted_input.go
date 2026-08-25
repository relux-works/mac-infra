package chromectl

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

const (
	TrustedInputVersion  = 1
	trustedInputSentinel = "works.relux.mac-infra/chrome-trusted-input/v1"
	exactTargetSentinel  = "works.relux.mac-infra/chrome-exact-target/v1"
	maxTrustedRequest    = 8 * 1024
	maxInputSelector     = 512
	maxInputTextBytes    = 2048
	maxInputTextRunes    = 512
	maxOptionSelector    = 512
	maxOptionTextBytes   = 1024
	maxOptionTextRunes   = 256
	maxVisibleOptions    = 20
	defaultTimeoutMS     = 5000
)

var ErrTrustedInputRefused = errors.New("trusted Chrome input was refused")

// privateTransportSentinel seals the stdin-only page-context transport envelope
// so a failure classification can never be inferred from untrusted child text.
const privateTransportSentinel = "works.relux.mac-infra/chrome-private-transport/v1"

// Fixed private-transport diagnostic kinds. This closed set is the entire
// vocabulary a sealed page-context failure may report.
const (
	PrivateTransportChildExit        = "child-exit-status"
	PrivateTransportChildUnavailable = "child-unavailable"
	PrivateTransportExecuteFailed    = "page-context-execute-failed"
	PrivateTransportUnverifiable     = "unverifiable-response"
)

// ErrPrivateTransport marks any sealed page-context transport failure.
var ErrPrivateTransport = errors.New("sealed Chrome page-context transport failed")

// PrivateTransportError is the only diagnostic the sealed transport emits. Kind
// is always one of the constants above, chosen in Go: the stdin program embeds
// the protected resource reference, so no child stdout, stderr, or error detail
// may be carried here.
type PrivateTransportError struct{ Kind string }

func (e *PrivateTransportError) Error() string {
	kind := e.Kind
	switch kind {
	case PrivateTransportChildExit, PrivateTransportChildUnavailable, PrivateTransportExecuteFailed, PrivateTransportUnverifiable:
	default:
		kind = PrivateTransportUnverifiable
	}
	// Fixed sentence. The Apple Events clause is a static operator hint, not a
	// child diagnostic, and keeps FormatAutomationError's guidance reachable.
	return ErrPrivateTransport.Error() + ": " + kind + " (no child diagnostic is retained; JavaScript from Apple Events may be disabled)"
}

func (e *PrivateTransportError) Unwrap() error { return ErrPrivateTransport }

// errSealedOriginMismatch is the only origin-drift diagnostic the sealed
// page-context transport emits. It preserves the browsersession.ErrOriginMismatch
// classification callers switch on while carrying a fixed sentence: the observed
// origin reported by a sealed child is untrusted page/child text, not evidence.
var errSealedOriginMismatch = fmt.Errorf("%w: sealed Chrome page-context response did not come from the guarded origin (the reported origin is withheld because it is untrusted child input)", browsersession.ErrOriginMismatch)

type TrustedInputRequest struct {
	Version        int    `json:"version"`
	InputSelector  string `json:"inputSelector"`
	Text           string `json:"text"`
	OptionSelector string `json:"optionSelector,omitempty"`
	OptionText     string `json:"optionText,omitempty"`
	TimeoutMS      int    `json:"timeoutMs,omitempty"`
}

type TrustedInputResult struct {
	Version  int    `json:"version"`
	OK       bool   `json:"ok"`
	Origin   string `json:"origin"`
	Typed    bool   `json:"typed"`
	Selected bool   `json:"selected"`
}

type TrustedInputRefusalError struct{ Kind string }

func (e *TrustedInputRefusalError) Error() string {
	return fmt.Sprintf("%v: %s", ErrTrustedInputRefused, e.Kind)
}

func (e *TrustedInputRefusalError) Unwrap() error { return ErrTrustedInputRefused }

func DecodeTrustedInputRequest(r io.Reader) (TrustedInputRequest, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxTrustedRequest+1))
	if err != nil {
		return TrustedInputRequest{}, errors.New("read trusted-input request")
	}
	if len(data) > maxTrustedRequest {
		return TrustedInputRequest{}, errors.New("trusted-input request exceeds 8192 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request TrustedInputRequest
	if err := decoder.Decode(&request); err != nil {
		return TrustedInputRequest{}, fmt.Errorf("decode trusted-input request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return TrustedInputRequest{}, errors.New("decode trusted-input request: trailing JSON is not allowed")
	}
	if err := request.Validate(); err != nil {
		return TrustedInputRequest{}, err
	}
	return request, nil
}

func (r *TrustedInputRequest) Validate() error {
	if r.Version != TrustedInputVersion {
		return fmt.Errorf("trusted-input request version must be %d", TrustedInputVersion)
	}
	r.InputSelector = strings.TrimSpace(r.InputSelector)
	r.OptionSelector = strings.TrimSpace(r.OptionSelector)
	r.OptionText = strings.TrimSpace(r.OptionText)
	if r.InputSelector == "" || len(r.InputSelector) > maxInputSelector || hasControl(r.InputSelector) {
		return errors.New("inputSelector must contain 1..512 printable bytes")
	}
	if r.Text == "" || len(r.Text) > maxInputTextBytes || utf8.RuneCountInString(r.Text) > maxInputTextRunes || hasControl(r.Text) {
		return errors.New("text must contain 1..512 printable characters and at most 2048 bytes")
	}
	if (r.OptionSelector == "") != (r.OptionText == "") {
		return errors.New("optionSelector and optionText must be supplied together")
	}
	if len(r.OptionSelector) > maxOptionSelector || hasControl(r.OptionSelector) {
		return errors.New("optionSelector must contain at most 512 printable bytes")
	}
	if len(r.OptionText) > maxOptionTextBytes || utf8.RuneCountInString(r.OptionText) > maxOptionTextRunes || hasControl(r.OptionText) {
		return errors.New("optionText must contain at most 256 printable characters and 1024 bytes")
	}
	if r.TimeoutMS == 0 {
		r.TimeoutMS = defaultTimeoutMS
	}
	if r.TimeoutMS < 500 || r.TimeoutMS > 10000 {
		return errors.New("timeoutMs must be between 500 and 10000")
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validateExactTarget(windowID, tabID, expectedOrigin string) error {
	for name, value := range map[string]string{"window id": windowID, "tab id": tabID} {
		trimmed := strings.TrimSpace(value)
		number, err := strconv.ParseInt(trimmed, 10, 64)
		if err != nil || number <= 0 || strconv.FormatInt(number, 10) != trimmed {
			return fmt.Errorf("%s must be a positive exact Chrome id", name)
		}
	}
	origin := strings.TrimSpace(expectedOrigin)
	parsed, err := url.Parse(origin)
	if err != nil || origin != strings.ToLower(origin) || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || browsersession.OriginOf(origin) != origin {
		return errors.New("origin must be an exact lowercase http(s) origin with no path, query, fragment, or credentials")
	}
	return nil
}

type exactTargetState struct {
	Origin string
	Active bool
}

func (s Session) resolveExactTarget(ctx context.Context, windowID, tabID, expectedOrigin string, selectTab bool) (exactTargetState, error) {
	raw, err := s.runJXA(ctx, exactTargetJXA(), windowID, tabID, expectedOrigin, strconv.FormatBool(selectTab))
	if err != nil {
		return exactTargetState{}, err
	}
	var envelope struct {
		Sentinel string `json:"__macChromeExactTarget"`
		Outcome  string `json:"outcome"`
		Origin   string `json:"origin"`
		Active   bool   `json:"active"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil || envelope.Sentinel != exactTargetSentinel {
		return exactTargetState{}, fmt.Errorf("%w: malformed exact-target verification", browsersession.ErrUnreadableResponse)
	}
	if envelope.Outcome == "origin-mismatch" {
		return exactTargetState{}, &browsersession.OriginMismatchError{Expected: expectedOrigin, Observed: envelope.Origin}
	}
	if envelope.Outcome != "ok" || envelope.Origin != expectedOrigin {
		return exactTargetState{}, fmt.Errorf("%w: exact-target attestation failed", browsersession.ErrUnreadableResponse)
	}
	return exactTargetState{Origin: envelope.Origin, Active: envelope.Active}, nil
}

func (s Session) TrustedInput(ctx context.Context, windowID, tabID, expectedOrigin string, request TrustedInputRequest) (TrustedInputResult, error) {
	if err := validateExactTarget(windowID, tabID, expectedOrigin); err != nil {
		return TrustedInputResult{}, err
	}
	if err := request.Validate(); err != nil {
		return TrustedInputResult{}, err
	}
	inputNonce, err := trustedNonce("input")
	if err != nil {
		return TrustedInputResult{}, err
	}
	optionNonce, err := trustedNonce("option")
	if err != nil {
		return TrustedInputResult{}, err
	}
	stateKey, err := trustedNonce("state")
	if err != nil {
		return TrustedInputResult{}, err
	}
	prepared, err := s.runJavaScriptPrivate(ctx, windowID, tabID, expectedOrigin, trustedPrepareJavaScript(request, inputNonce, optionNonce, stateKey))
	if err != nil {
		return TrustedInputResult{}, err
	}
	if prepared.Value != "ready" {
		return TrustedInputResult{}, &TrustedInputRefusalError{Kind: prepared.Value}
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = s.runJavaScriptPrivate(cleanupCtx, windowID, tabID, expectedOrigin, trustedCleanupJavaScript(request.InputSelector, stateKey))
	}()
	if _, err := s.focusExactTarget(ctx, windowID, tabID, expectedOrigin); err != nil {
		return TrustedInputResult{}, err
	}
	pid, err := s.axProcessID()
	if err != nil {
		return TrustedInputResult{}, err
	}
	if err := s.axTypeText(pid, inputNonce, request.Text); err != nil {
		return TrustedInputResult{}, err
	}
	deadline := time.Now().Add(time.Duration(request.TimeoutMS) * time.Millisecond)
	for {
		state, err := s.readTrustedPageState(ctx, windowID, tabID, expectedOrigin, request.InputSelector, stateKey)
		if err != nil {
			return TrustedInputResult{}, err
		}
		switch state.Outcome {
		case "typed":
			return TrustedInputResult{Version: TrustedInputVersion, OK: true, Origin: expectedOrigin, Typed: true}, nil
		case "option-ready":
			if err := s.requireExactTargetActive(ctx, windowID, tabID, expectedOrigin); err != nil {
				return TrustedInputResult{}, err
			}
			if err := s.axPress(pid, optionNonce); err != nil {
				return TrustedInputResult{}, err
			}
			return s.waitForTrustedSelection(ctx, deadline, windowID, tabID, expectedOrigin, request.InputSelector, stateKey)
		case "waiting-text", "waiting-option":
			if time.Now().After(deadline) {
				return TrustedInputResult{}, &TrustedInputRefusalError{Kind: state.Outcome + "-timeout"}
			}
			time.Sleep(100 * time.Millisecond)
		default:
			return TrustedInputResult{}, &TrustedInputRefusalError{Kind: state.Outcome}
		}
	}
}

func (s Session) requireExactTargetActive(ctx context.Context, windowID, tabID, origin string) error {
	target, err := s.resolveExactTarget(ctx, windowID, tabID, origin, false)
	if err != nil {
		return err
	}
	if !target.Active {
		return fmt.Errorf("%w: exact Chrome target lost foreground focus", browsersession.ErrTargetMissing)
	}
	return nil
}

func (s Session) waitForTrustedSelection(ctx context.Context, deadline time.Time, windowID, tabID, origin, inputSelector, stateKey string) (TrustedInputResult, error) {
	for {
		state, err := s.readTrustedPageState(ctx, windowID, tabID, origin, inputSelector, stateKey)
		if err != nil {
			return TrustedInputResult{}, err
		}
		if state.Outcome == "selected" {
			return TrustedInputResult{Version: TrustedInputVersion, OK: true, Origin: origin, Typed: true, Selected: true}, nil
		}
		if state.Outcome != "waiting-selection" {
			return TrustedInputResult{}, &TrustedInputRefusalError{Kind: state.Outcome}
		}
		if time.Now().After(deadline) {
			return TrustedInputResult{}, &TrustedInputRefusalError{Kind: "selection-timeout"}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type trustedPageState struct {
	Outcome string `json:"outcome"`
}

func (s Session) readTrustedPageState(ctx context.Context, windowID, tabID, origin, inputSelector, stateKey string) (trustedPageState, error) {
	result, err := s.runJavaScriptPrivate(ctx, windowID, tabID, origin, trustedInspectJavaScript(inputSelector, stateKey))
	if err != nil {
		return trustedPageState{}, err
	}
	var state trustedPageState
	if err := json.Unmarshal([]byte(result.Value), &state); err != nil || strings.TrimSpace(state.Outcome) == "" {
		return trustedPageState{}, fmt.Errorf("%w: malformed trusted-input page state", browsersession.ErrUnreadableResponse)
	}
	return state, nil
}

func trustedNonce(kind string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errors.New("generate trusted-input nonce")
	}
	return "works.relux.mac-infra-" + kind + "-" + hex.EncodeToString(value[:]), nil
}

func trustedPrepareJavaScript(request TrustedInputRequest, inputNonce, optionNonce, stateKey string) string {
	requestJSON, _ := json.Marshal(request)
	inputNonceJSON, _ := json.Marshal(inputNonce)
	optionNonceJSON, _ := json.Marshal(optionNonce)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  const request=%s,inputNonce=%s,optionNonce=%s,stateKey=%s;
  let inputs;try{inputs=document.querySelectorAll(request.inputSelector);}catch(_){return "invalid-input-selector";}
  if(inputs.length===0)return "input-missing";if(inputs.length!==1)return "input-ambiguous";
  const input=inputs[0],type=String(input.type||"").toLowerCase();
  if(!(input instanceof HTMLInputElement)||!(type==="text"||type==="search")||input.disabled||input.readOnly)return "input-not-editable";
  if(!input.getClientRects().length||getComputedStyle(input).visibility==="hidden"||getComputedStyle(input).display==="none")return "input-hidden";
  if(input[stateKey])return "probe-collision";
  const state={request,oldInputAria:input.getAttribute("aria-label"),optionNonce,trustedInput:false,trustedOptionClick:false,option:null,oldOptionAria:null};
  state.onInput=event=>{if(event.isTrusted)state.trustedInput=true;};input.addEventListener("input",state.onInput);
  Object.defineProperty(input,stateKey,{value:state,configurable:true});input.setAttribute("aria-label",inputNonce);return "ready";
})()`, string(requestJSON), string(inputNonceJSON), string(optionNonceJSON), string(stateKeyJSON))
}

func trustedInspectJavaScript(inputSelector, stateKey string) string {
	selectorJSON, _ := json.Marshal(inputSelector)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  const inputSelector=%s,stateKey=%s,outcome=value=>JSON.stringify({outcome:value});
  let inputs;try{inputs=document.querySelectorAll(inputSelector);}catch(_){return outcome("invalid-input-selector");}
  if(inputs.length!==1)return outcome(inputs.length===0?"input-missing":"input-ambiguous");
  const input=inputs[0],state=input[stateKey];if(!state)return outcome("probe-missing");
  const normalize=value=>String(value||"").replace(/\s+/g," ").trim();
  if(state.request.optionSelector&&state.trustedOptionClick&&normalize(input.value)===normalize(state.request.optionText))return outcome("selected");
  if(!state.trustedInput||String(input.value)!==String(state.request.text))return outcome("waiting-text");
  if(!state.request.optionSelector)return outcome("typed");
  let options;try{options=Array.from(document.querySelectorAll(state.request.optionSelector)).filter(node=>node.getClientRects().length&&getComputedStyle(node).visibility!=="hidden"&&getComputedStyle(node).display!=="none");}catch(_){return outcome("invalid-option-selector");}
  if(options.length>%d)return outcome("option-list-too-large");
  const targets=options.filter(node=>normalize(node.textContent)===normalize(state.request.optionText));
  if(targets.length===0)return outcome("waiting-option");if(targets.length!==1)return outcome("option-ambiguous");
  const target=targets[0];if(state.option!==target){
    if(state.option){state.option.removeEventListener("click",state.onOptionClick);if(state.oldOptionAria===null)state.option.removeAttribute("aria-label");else state.option.setAttribute("aria-label",state.oldOptionAria);}
    state.option=target;state.oldOptionAria=target.getAttribute("aria-label");state.onOptionClick=event=>{if(event.isTrusted)state.trustedOptionClick=true;};
    target.addEventListener("click",state.onOptionClick);target.setAttribute("aria-label",state.optionNonce);
  }
  return outcome(state.trustedOptionClick?"waiting-selection":"option-ready");
})()`, string(selectorJSON), string(stateKeyJSON), maxVisibleOptions)
}

func trustedCleanupJavaScript(inputSelector, stateKey string) string {
	selectorJSON, _ := json.Marshal(inputSelector)
	stateKeyJSON, _ := json.Marshal(stateKey)
	return fmt.Sprintf(`(() => {
  const inputs=document.querySelectorAll(%s);if(inputs.length!==1)return "cleanup-target-missing";
  const input=inputs[0],state=input[%s];if(!state)return "already-clean";input.removeEventListener("input",state.onInput);
  if(state.oldInputAria===null)input.removeAttribute("aria-label");else input.setAttribute("aria-label",state.oldInputAria);
  if(state.option){state.option.removeEventListener("click",state.onOptionClick);if(state.oldOptionAria===null)state.option.removeAttribute("aria-label");else state.option.setAttribute("aria-label",state.oldOptionAria);}
  delete input[%s];return "cleaned";
})()`, string(selectorJSON), string(stateKeyJSON), string(stateKeyJSON))
}

// runJavaScriptPrivate evaluates source in the exact tab through a stdin-only
// JXA program. The program embeds the caller's page-context source, and for
// fetch-file that source embeds the protected resource reference, so nothing
// derived from the child's stdout, stderr, or exit detail may ever reach a
// returned error. Every failure below is a fixed, typed diagnostic decided in
// Go; target loss is classified from a sentinel-sealed envelope the program
// returns instead of from untrusted child text.
func (s Session) runJavaScriptPrivate(ctx context.Context, windowID, tabID, expectedOrigin, source string) (browsersession.ExecutionResult, error) {
	wrapped, err := browsersession.WrapJavaScript(source, expectedOrigin)
	if err != nil {
		return browsersession.ExecutionResult{}, err
	}
	windowJSON, _ := json.Marshal(windowID)
	tabJSON, _ := json.Marshal(tabID)
	sourceJSON, _ := json.Marshal(wrapped)
	sentinelJSON, _ := json.Marshal(privateTransportSentinel)
	program := fmt.Sprintf(`function run(){
  const sentinel=%s,windowID=%s,tabID=%s,source=%s;
  const seal=(outcome,value)=>JSON.stringify({__macChromePrivateTransport:sentinel,outcome:outcome,value:value===undefined?"":String(value)});
  try{
    const c=Application("Google Chrome");
    const windows=c.windows(),matches=windows.filter(w=>String(w.id())===windowID);
    if(matches.length!==1)return seal("window-missing");
    const tabs=matches[0].tabs(),indexes=[];for(let i=0;i<tabs.length;i++)if(String(tabs[i].id())===tabID)indexes.push(i);
    if(indexes.length!==1)return seal("tab-missing");
    return seal("ok",c.execute(tabs[indexes[0]],{javascript:source}));
  }catch(_){
    // The caught error can quote the evaluated program, so it is dropped whole.
    return seal("execute-failed");
  }
}`, string(sentinelJSON), string(windowJSON), string(tabJSON), string(sourceJSON))
	raw, err := s.runJXAStdin(ctx, program)
	if err != nil {
		return browsersession.ExecutionResult{}, err
	}
	var envelope struct {
		Sentinel string `json:"__macChromePrivateTransport"`
		Outcome  string `json:"outcome"`
		Value    string `json:"value"`
	}
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil || envelope.Sentinel != privateTransportSentinel {
		return browsersession.ExecutionResult{}, &PrivateTransportError{Kind: PrivateTransportUnverifiable}
	}
	switch envelope.Outcome {
	case "ok":
	case "window-missing":
		return browsersession.ExecutionResult{}, &browsersession.TargetMissingError{Browser: browsersession.BrowserChrome, Target: "exact-target", Detail: "exact Chrome window is no longer open"}
	case "tab-missing":
		return browsersession.ExecutionResult{}, &browsersession.TargetMissingError{Browser: browsersession.BrowserChrome, Target: "exact-target", Detail: "exact Chrome tab is no longer open"}
	case "execute-failed":
		return browsersession.ExecutionResult{}, &PrivateTransportError{Kind: PrivateTransportExecuteFailed}
	default:
		return browsersession.ExecutionResult{}, &PrivateTransportError{Kind: PrivateTransportUnverifiable}
	}
	result, err := browsersession.ParseJavaScriptResult(envelope.Value, expectedOrigin)
	if err != nil {
		if errors.Is(err, browsersession.ErrOriginMismatch) {
			// Keep the classification, drop the observed value. The nested guard
			// envelope's origin field is child-controlled, and the stdin program
			// the child receives embeds the protected resource reference, so a
			// hostile child can mint a well-formed origin-mismatch envelope whose
			// origin is a copy of that reference. Returning
			// browsersession.OriginMismatchError here would print it.
			return browsersession.ExecutionResult{}, errSealedOriginMismatch
		}
		// ParseJavaScriptResult formats decoder detail; a sealed call returns a
		// fixed message so no page-context byte can ride out on that path.
		return browsersession.ExecutionResult{}, fmt.Errorf("%w: sealed Chrome page-context response could not be verified", browsersession.ErrUnreadableResponse)
	}
	return result, nil
}

// runJXAStdin runs the sealed program with the source on stdin. Child stdout is
// returned only on success; on any failure both child streams are discarded
// unread by the caller, because the program they can quote carries the
// protected resource reference.
func (s Session) runJXAStdin(ctx context.Context, source string) (string, error) {
	path := strings.TrimSpace(s.OsaScriptPath)
	if path == "" {
		path = "/usr/bin/osascript"
	}
	cmd := exec.CommandContext(ctx, path, "-l", "JavaScript")
	cmd.Stdin = strings.NewReader(source)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return "", &PrivateTransportError{Kind: PrivateTransportChildExit}
		}
		return "", &PrivateTransportError{Kind: PrivateTransportChildUnavailable}
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func (s Session) axProcessID() (int, error) {
	if s.AXProcessID != nil {
		return s.AXProcessID()
	}
	return chromeAXProcessID()
}

func (s Session) axTypeText(pid int, description, value string) error {
	if s.AXTypeText != nil {
		return s.AXTypeText(pid, description, value)
	}
	return chromeAXTypeText(pid, description, value)
}

func (s Session) axPress(pid int, description string) error {
	if s.AXPress != nil {
		return s.AXPress(pid, description)
	}
	return chromeAXPress(pid, description)
}
