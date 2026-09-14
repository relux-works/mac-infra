#!/bin/zsh
# rev5 client-side envelope mutants. Each: name, perl substitution on client.go, test mask. KILLED = named test failed.
set -u
cd "$(dirname "$0")/../.."
export MAC_KEYVAULT_SKIP_KEYCHAIN=1
LOG=.temp/TASK-260915-2ny9kd/mutants-rev5.log
: > "$LOG"
C=internal/keyvault/signerclient/client.go
T=TestClientRefusesMalformedEnvelopeBeforeReadingOK
run_mutant() {
  local name="$1" perlexpr="$2" mask="$3"
  cp "$C" "$C.orig"
  perl -0pi -e "$perlexpr" "$C"
  if cmp -s "$C" "$C.orig"; then echo "$name: MUTANT DID NOT APPLY" | tee -a "$LOG"; mv "$C.orig" "$C"; return; fi
  go test -count=1 ./internal/keyvault/signerclient/ -run "$mask" > ".temp/TASK-260915-2ny9kd/mutant-rev5-$name.log" 2>&1
  local rc=$?
  mv "$C.orig" "$C"
  if [ $rc -eq 0 ]; then echo "$name: SURVIVED (exit 0, $mask)" | tee -a "$LOG"; else echo "$name: KILLED (exit $rc) by $(grep -E '^\s*--- FAIL' ".temp/TASK-260915-2ny9kd/mutant-rev5-$name.log" | head -4 | tr -s ' \n' ' ')" | tee -a "$LOG"; fi
}
# Reviewer-named narrowing: envelope/error validation retained but applied only when !resp.OK (the rev4 bypass), in Call.
run_mutant R5-M1-call-check-only-when-not-ok 's/\tif err := checkEnvelope\(resp, req.Op == OpVerify\); err != nil \{\n\t\tc.broken = fmt.Errorf\("%w: %v", ErrProtocol, err\)\n\t\tc.abort\(\)\n\t\treturn Response\{\}, c.broken\n\t\}\n\tif !resp.OK \{/\tif !resp.OK {\n\t\tif err := checkEnvelope(resp, req.Op == OpVerify); err != nil {\n\t\t\tc.broken = fmt.Errorf("%w: %v", ErrProtocol, err)\n\t\t\tc.abort()\n\t\t\treturn Response{}, c.broken\n\t\t}\n\t}\n\tif !resp.OK {/' "$T"
# Reviewer-named narrowing, startup side: hello envelope validated only when !resp.OK.
run_mutant R5-M2-hello-check-only-when-not-ok 's/\tif err := checkEnvelope\(resp, false\); err != nil \{\n\t\tc.abort\(\)\n\t\treturn nil, fmt.Errorf\("%w: hello: %v", ErrProtocol, err\)\n\t\}\n\tif !resp.OK \{/\tif !resp.OK {\n\t\tif err := checkEnvelope(resp, false); err != nil {\n\t\t\tc.abort()\n\t\t\treturn nil, fmt.Errorf("%w: hello: %v", ErrProtocol, err)\n\t\t}\n\t}\n\tif !resp.OK {/' "$T"
# Narrowing: ok:true next to a DECLARED error admitted (undeclared still refused).
run_mutant R5-M3-ok-with-declared-error-admitted 's/\t\tif resp.OK \{\n\t\t\treturn fmt.Errorf\("response is ok and carries error %q", resp.Error.Code\)\n\t\t\}/\t\tif resp.OK \&\& !IsStreamCode(resp.Error.Code) {\n\t\t\treturn fmt.Errorf("response is ok and carries error %q", resp.Error.Code)\n\t\t}/' "$T"
# Narrowing: a result next to a refusal admitted for every op, not only verify.
run_mutant R5-M4-result-on-refusal-any-op 's/checkEnvelope\(resp, req.Op == OpVerify\)/checkEnvelope(resp, req.Op != OpDescribe)/' "$T"
# Narrowing: the startup hello admits a result next to a refusal.
run_mutant R5-M5-hello-result-on-refusal 's/checkEnvelope\(resp, false\)/checkEnvelope(resp, true)/' "$T"
# Narrowing: ok:true without a result admitted.
run_mutant R5-M6-ok-without-result-admitted 's/\tif !hasResult \{\n\t\treturn errors.New\("response is ok and carries no result"\)\n\t\}\n/\tif false \&\& !hasResult {\n\t\treturn errors.New("response is ok and carries no result")\n\t}\n/' "$T"
# Narrowing: result literal null counts as present.
run_mutant R5-M7-null-result-present 's/ \&\& !bytes.Equal\(bytes.TrimSpace\(resp.Result\), \[\]byte\("null"\)\)//' "$T"
# Narrowing: ok:false without an error member admitted (returned as a nil *Error).
run_mutant R5-M8-fail-without-error-admitted 's/\tif !resp.OK \{\n\t\treturn errors.New\("response is not ok and carries no error"\)\n\t\}/\tif false \&\& !resp.OK {\n\t\treturn errors.New("response is not ok and carries no error")\n\t}/' "$T"
# Narrowing: the code-set check on the error member admits exactly self_minted (ok:true still refused).
run_mutant R5-M9-self-minted-admitted 's/\t\tif !IsStreamCode\(resp.Error.Code\) \{/\t\tif !IsStreamCode(resp.Error.Code) \&\& resp.Error.Code != "self_minted" {/' "$T|TestClientFailsClosedOnUndeclaredErrorCode"
# Narrowing: a malformed envelope mid-stream is ErrProtocol for this call but the session is not broken/reaped.
run_mutant R5-M10-envelope-not-fatal 's/\tif err := checkEnvelope\(resp, req.Op == OpVerify\); err != nil \{\n\t\tc.broken = fmt.Errorf\("%w: %v", ErrProtocol, err\)\n\t\tc.abort\(\)\n\t\treturn Response\{\}, c.broken\n\t\}/\tif err := checkEnvelope(resp, req.Op == OpVerify); err != nil {\n\t\treturn Response{}, fmt.Errorf("%w: %v", ErrProtocol, err)\n\t}/' "$T"
echo "--- baseline (no mutant) ---" | tee -a "$LOG"
go test -count=1 ./internal/keyvault/signerclient/ -run 'TestStart|TestClient|TestCall|TestTyped' >> "$LOG" 2>&1; echo "baseline exit=$?" | tee -a "$LOG"
git status --short "$C"
