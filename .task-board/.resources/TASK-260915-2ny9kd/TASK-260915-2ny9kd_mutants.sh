#!/bin/zsh
# Each mutant: file, perl substitution, package, test mask. Prints KILLED (test failed) or SURVIVED.
set -u
cd "$(dirname "$0")/../.."
export MAC_KEYVAULT_SKIP_KEYCHAIN=1
LOG=.temp/TASK-260915-2ny9kd/mutants-01.log
: > "$LOG"
run_mutant() {
  local name="$1" file="$2" perlexpr="$3" pkg="$4" mask="$5"
  cp "$file" "$file.orig"
  perl -0pi -e "$perlexpr" "$file"
  if cmp -s "$file" "$file.orig"; then echo "$name: MUTANT DID NOT APPLY" | tee -a "$LOG"; mv "$file.orig" "$file"; return; fi
  go test -count=1 "$pkg" -run "$mask" > ".temp/TASK-260915-2ny9kd/mutant-$name.log" 2>&1
  local rc=$?
  mv "$file.orig" "$file"
  if [ $rc -eq 0 ]; then echo "$name: SURVIVED (exit 0, $mask)" | tee -a "$LOG"; else echo "$name: KILLED (exit $rc) by $(grep -E '^\s*--- FAIL' ".temp/TASK-260915-2ny9kd/mutant-$name.log" | head -3 | tr -s ' \n' ' ')" | tee -a "$LOG"; fi
}
S=internal/keyvault/signer.go
C=internal/keyvault/signerclient/client.go
M=cmd/mac-keyvault/main.go
run_mutant M1-null-id-admitted "$S" 's/if len\(id\) == 0 \|\| bytes.Equal\(id, nullID\) \{\n\t\treturn false\n\t\}/if len(id) == 0 {\n\t\treturn false\n\t}\n\tif bytes.Equal(id, nullID) {\n\t\treturn true\n\t}/' ./internal/keyvault/ 'TestSignerServeGoldenWire'
run_mutant M2-op-case-insensitive "$S" 's/\tswitch req.Op \{\n\tcase signerclient.OpDescribe:/\tswitch strings.ToLower(req.Op) {\n\tcase signerclient.OpDescribe:/; s/import \(\n/import (\n\t"strings"\n/' ./internal/keyvault/ 'TestSignerServeGoldenWire'
run_mutant M3-sign-digest-length-server-only "$S" 's/\tif err := ValidateDigest\(digest\); err != nil \{\n\t\twireErr := wireError\(err\)/\tif err := ValidateDigest(digest); err != nil \&\& req.Op != signerclient.OpSign {\n\t\twireErr := wireError(err)/' ./internal/keyvault/ 'TestSignerServeGoldenWire'
run_mutant M3b-verify-digest-length-removed "$S" 's/\tif err := ValidateDigest\(digest\); err != nil \{\n\t\twireErr := wireError\(err\)/\tif err := ValidateDigest(digest); err != nil \&\& req.Op != signerclient.OpVerify {\n\t\twireErr := wireError(err)/' ./internal/keyvault/ 'TestSignerServeGoldenWire'
run_mutant M4-bad-request-ends-stream "$S" 's/\t\tif trimmed := bytes.TrimSpace\(line\); len\(trimmed\) != 0 \{\n\t\t\tif err := writeLine\(out, s.handle\(trimmed\)\); err != nil \{\n\t\t\t\treturn err\n\t\t\t\}/\t\tif trimmed := bytes.TrimSpace(line); len(trimmed) != 0 {\n\t\t\tresp := s.handle(trimmed)\n\t\t\tif err := writeLine(out, resp); err != nil {\n\t\t\t\treturn err\n\t\t\t}\n\t\t\tif resp.Error != nil \&\& resp.Error.Code == signerclient.CodeBadRequest {\n\t\t\t\treturn nil\n\t\t\t}/' ./internal/keyvault/ 'TestSignerServeGoldenWire'
run_mutant M5-high-s-after-store "$S" 's/\tif !sig.IsLowS\(\) && !req.AllowHighS \{\n\t\treturn verdict, wireError\(&Refusal\{Code: CodeHighSRefused/\tif _, err := s.Manager.PublicKeyFor(s.Address); err != nil {\n\t\treturn nil, wireError(err)\n\t}\n\tif !sig.IsLowS() \&\& !req.AllowHighS {\n\t\treturn verdict, wireError(\&Refusal{Code: CodeHighSRefused/' ./internal/keyvault/ 'TestSignerServeGatesBeforeStore'
run_mutant M9-unknown-member-admitted "$S" 's/\tif err := DecodeSingleJSON\(line, req\); err != nil \{\n\t\treturn fmt.Errorf\("request has a member/\tif err := json.Unmarshal(line, req); err != nil {\n\t\treturn fmt.Errorf("request has a member/' ./internal/keyvault/ 'TestSignerServeGoldenWire'
run_mutant M6-contract-ge-1-accepted "$C" 's/if resp.Contract != Contract \{/if resp.Contract < Contract {/' ./internal/keyvault/signerclient/ 'TestStartRefusesForeignContractAndSurfacesStartupErrors'
run_mutant M7-id-unchecked-when-ok "$C" 's/if !bytes.Equal\(bytes.TrimSpace\(resp.ID\), req.ID\) \{/if !resp.OK \&\& !bytes.Equal(bytes.TrimSpace(resp.ID), req.ID) {/' ./internal/keyvault/signerclient/ 'TestCallProtocolViolationsAndRemoteErrors'
run_mutant M10-any-hash-accepted "$C" 's/if opts == nil \|\| opts.HashFunc\(\) != crypto.SHA256 \{/if opts == nil {/' ./internal/keyvault/signerclient/ 'TestTypedCallsAgainstFake'
run_mutant M8-raw-label-inside-prefix-admitted "$M" 's/\taddr, err := keyvault.ParseAddress\(\*address, \*kind, \*version\)\n\tif err != nil \{\n\t\treturn fail\(err\)\n\t\}\n\tmanager, err := newManager\(\)/\taddr, err := keyvault.ParseAddress(*address, *kind, *version)\n\tif parsed, ok := keyvault.ParseLabel(*address); ok {\n\t\taddr, err = parsed, nil\n\t}\n\tif err != nil {\n\t\treturn fail(err)\n\t}\n\tmanager, err := newManager()/' ./cmd/mac-keyvault/ 'TestRunSignerServeRefusesBeforeStore'
run_mutant M11-serve-usage-text-mode "$M" 's/\t\t_ = keyvault.WriteStartupFailure\(out.stdout, keyvault.ContractError\{Code: respErr.Code, Message: respErr.Message, Hint: respErr.Hint, Status: respErr.Status\}\)\n\t\treturn code/\t\tif respErr.Code == "usage" {\n\t\t\tfmt.Fprintf(out.stderr, "error: usage: %s\\n", respErr.Message)\n\t\t\treturn code\n\t\t}\n\t\t_ = keyvault.WriteStartupFailure(out.stdout, keyvault.ContractError{Code: respErr.Code, Message: respErr.Message, Hint: respErr.Hint, Status: respErr.Status})\n\t\treturn code/' ./cmd/mac-keyvault/ 'TestRunSignerServeRefusesBeforeStore'
echo "--- baseline (no mutant) ---" | tee -a "$LOG"
go test -count=1 ./internal/keyvault/ ./internal/keyvault/signerclient/ ./cmd/mac-keyvault/ -run 'TestSignerServe|TestStart|TestCall|TestTyped|TestRunSigner' 2>&1 | tee -a "$LOG"
