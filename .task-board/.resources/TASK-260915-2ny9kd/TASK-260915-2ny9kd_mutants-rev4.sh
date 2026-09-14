#!/bin/zsh
# rev4 client-side mutants. Each: name, perl substitution on client.go, test mask. KILLED = named test failed.
set -u
cd "$(dirname "$0")/../.."
export MAC_KEYVAULT_SKIP_KEYCHAIN=1
LOG=.temp/TASK-260915-2ny9kd/mutants-rev4.log
: > "$LOG"
C=internal/keyvault/signerclient/client.go
run_mutant() {
  local name="$1" perlexpr="$2" mask="$3"
  cp "$C" "$C.orig"
  perl -0pi -e "$perlexpr" "$C"
  if cmp -s "$C" "$C.orig"; then echo "$name: MUTANT DID NOT APPLY" | tee -a "$LOG"; mv "$C.orig" "$C"; return; fi
  go test -count=1 ./internal/keyvault/signerclient/ -run "$mask" > ".temp/TASK-260915-2ny9kd/mutant-rev4-$name.log" 2>&1
  local rc=$?
  mv "$C.orig" "$C"
  if [ $rc -eq 0 ]; then echo "$name: SURVIVED (exit 0, $mask)" | tee -a "$LOG"; else echo "$name: KILLED (exit $rc) by $(grep -E '^\s*--- FAIL' ".temp/TASK-260915-2ny9kd/mutant-rev4-$name.log" | head -3 | tr -s ' \n' ' ')" | tee -a "$LOG"; fi
}
# F1 narrowing: the closed-set check stays, but admits exactly one undeclared code.
run_mutant R4-M1-self-minted-admitted 's/if !IsStreamCode\(e.Code\) \{/if !IsStreamCode(e.Code) \&\& e.Code != "self_minted" {/' 'TestClientFailsClosedOnUndeclaredErrorCode'
# F1 narrowing: the startup hello only checks presence, not the code set (mid-stream keeps the full check).
run_mutant R4-M2-startup-code-unchecked 's/\t\tif err := checkError\(resp.Error\); err != nil \{\n\t\t\treturn nil, fmt.Errorf\("%w: hello: %v", ErrProtocol, err\)\n\t\t\}/\t\tif resp.Error == nil {\n\t\t\treturn nil, fmt.Errorf("%w: hello: no error", ErrProtocol)\n\t\t}/' 'TestClientFailsClosedOnUndeclaredErrorCode'
# F1 narrowing: undeclared code is ErrProtocol for this call but the session is not broken/reaped.
run_mutant R4-M3-undeclared-code-not-fatal 's/\t\tif err := checkError\(resp.Error\); err != nil \{\n\t\t\tc.broken = fmt.Errorf\("%w: %v", ErrProtocol, err\)\n\t\t\tc.abort\(\)\n\t\t\treturn Response\{\}, c.broken\n\t\t\}/\t\tif err := checkError(resp.Error); err != nil {\n\t\t\treturn Response{}, fmt.Errorf("%w: %v", ErrProtocol, err)\n\t\t}/' 'TestClientFailsClosedOnUndeclaredErrorCode'
# F1 narrowing: empty code admitted (any non-empty undeclared code still refused).
run_mutant R4-M4-empty-code-admitted 's/if !IsStreamCode\(e.Code\) \{/if e.Code != "" \&\& !IsStreamCode(e.Code) {/' 'TestClientFailsClosedOnUndeclaredErrorCode'
# F2 reviewer-named mutant: checkHello retains only the version comparison.
run_mutant R4-M5-hello-version-only 's/func checkHello\(h Hello, opts Options\) error \{\n/func checkHello(h Hello, opts Options) error {\n\tif h.Version < 1 {\n\t\treturn fmt.Errorf("does not pin a generation (version %d)", h.Version)\n\t}\n\tif opts.Version != 0 \&\& h.Version != opts.Version {\n\t\treturn fmt.Errorf("requested version %d, hello bound version %d", opts.Version, h.Version)\n\t}\n\treturn nil\n}\n\nfunc checkHelloUnused(h Hello, opts Options) error {\n/' 'TestStartRefusesHelloBoundToAnotherIdentity'
# F2 narrowing: tool check admits exactly "impostor".
run_mutant R4-M6-tool-impostor-admitted 's/if h.Tool != Tool \{/if h.Tool != Tool \&\& h.Tool != "impostor" {/' 'TestStartRefusesHelloBoundToAnotherIdentity'
# F2 narrowing: a missing address is admitted (a different one is still refused).
run_mutant R4-M7-address-missing-admitted 's/if h.Address != opts.Address \{/if h.Address != "" \&\& h.Address != opts.Address {/' 'TestStartRefusesHelloBoundToAnotherIdentity'
# F2 narrowing: kind is checked only when one was requested (omitted kind accepts any hello kind).
run_mutant R4-M8-kind-default-unchecked 's/\tif h.Kind != kind \{/\tif opts.Kind != "" \&\& h.Kind != kind {/' 'TestStartRefusesHelloBoundToAnotherIdentity'
# F2 narrowing: ops compared by count only (a renamed op passes).
run_mutant R4-M9-ops-count-only 's/\t\tif h.Ops\[i\] != op \{/\t\tif len(h.Ops[i]) != len(op) {/' 'TestStartRefusesHelloBoundToAnotherIdentity'
# F2 narrowing: fingerprint presence not required.
run_mutant R4-M10-fingerprint-optional 's/\tif h.Fingerprint == "" \{\n\t\treturn errors.New\("fingerprint is missing"\)\n\t\}/\tif h.Fingerprint == "" \&\& h.Label == "" {\n\t\treturn errors.New("fingerprint is missing")\n\t}/' 'TestStartRefusesHelloBoundToAnotherIdentity'
echo "--- baseline (no mutant) ---" | tee -a "$LOG"
go test -count=1 ./internal/keyvault/signerclient/ -run 'TestStart|TestClient|TestCall|TestTyped' >> "$LOG" 2>&1; echo "baseline exit=$?" | tee -a "$LOG"
