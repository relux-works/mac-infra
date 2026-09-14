#!/bin/zsh
# Narrowing-mutant harness for TASK-260915-2ny9kd rev3 (F1 registry, F2 presence gate).
# Each mutant is a perl substitution (or a file removal) applied to the worktree,
# the named test mask is run, the real exit code is recorded, the mutant is reverted.
set -u
WT=/Users/alexis/src/mac-infra/.temp/STORY-260915-3r0ys5/worktree
cd "$WT" || exit 9
SIGNER=internal/keyvault/signer.go
CODES=internal/keyvault/signerclient/codes.go
MAIN=cmd/mac-keyvault/main.go
FIX=internal/keyvault/testdata/signer-v1/startup-07-invalid-service.json

run_mask() { # pkg mask
  go test "$1" -run "$2" -count=1 >/tmp/mut.out 2>&1; local rc=$?
  echo "    $1 -run '$2' => exit $rc"; grep -E '^\s*--- FAIL' /tmp/mut.out | sed 's/^/      /' | head -12
  return $rc
}

mutant() { # name file perl-expr pkg mask
  local name=$1 file=$2 expr=$3 pkg=$4 mask=$5
  cp "$file" /tmp/mut.bak
  perl -0pi -e "$expr" "$file"
  if cmp -s "$file" /tmp/mut.bak; then echo "== $name: MUTATION DID NOT APPLY"; return; fi
  echo "== $name"
  run_mask "$pkg" "$mask"; local rc=$?
  cp /tmp/mut.bak "$file"
  if [ $rc -ne 0 ]; then echo "  KILLED"; else echo "  SURVIVED"; fi
}

echo "baseline"
run_mask ./internal/keyvault/ 'TestSigner' ; run_mask ./cmd/mac-keyvault/ 'TestRunSignerServeStartupGolden|TestSignerStreamCodesEmittedByProduction'; run_mask ./internal/keyvault/signerclient/ 'TestErrorContractRegistryComplete'

# F2: presence gate narrowed to admit zero-valued members
mutant M1-zero-values-treated-absent "$SIGNER" \
  's/if name == "id" \|\| name == "op" \|\| allowed\[name\] \{/if name == "id" || name == "op" || allowed[name] || string(members[name]) == "false" || string(members[name]) == `""` {/' \
  ./internal/keyvault/ 'TestSignerServeRefusesInapplicableZeroValueMembers|TestSignerServeGoldenWire'
mutant M2-sign-admits-allow-high-s "$SIGNER" \
  's/signerclient\.OpSign:\s+\{"format": true, "digest": true\},/signerclient.OpSign: {"format": true, "digest": true, "allow_high_s": true},/' \
  ./internal/keyvault/ 'TestSignerServeRefusesInapplicableZeroValueMembers|TestSignerServeGoldenWire'
mutant M3-only-allow-high-s-false-admitted "$SIGNER" \
  's/if name == "id" \|\| name == "op" \|\| allowed\[name\] \{/if name == "id" || name == "op" || allowed[name] || (name == "allow_high_s" \&\& string(members[name]) == "false") {/' \
  ./internal/keyvault/ 'TestSignerServeRefusesInapplicableZeroValueMembers|TestSignerServeGoldenWire'

# F1: registry token-preserving narrowings (constant stays, row flips)
mutant M4-invalid-kind-not-stream "$CODES" \
  's/\{CodeInvalidKind, ExitRefused, true,/{CodeInvalidKind, ExitRefused, false,/' \
  ./internal/keyvault/ 'TestSignerGoldenCoversStreamErrorCodes'
mutant M4b-invalid-kind-not-stream-cli "$CODES" \
  's/\{CodeInvalidKind, ExitRefused, true,/{CodeInvalidKind, ExitRefused, false,/' \
  ./cmd/mac-keyvault/ 'TestSignerStreamCodesEmittedByProduction'
mutant M5-failure-not-stream "$CODES" \
  's/\{CodeFailure, ExitFailure, true,/{CodeFailure, ExitFailure, false,/' \
  ./internal/keyvault/ 'TestSignerGoldenCoversStreamErrorCodes|TestSignerServedErrorCodesAreDeclared'
mutant M6-cli-emits-undeclared-usage-code "$MAIN" \
  's/Code: keyvault\.CodeUsage,/Code: "usage_error",/' \
  ./cmd/mac-keyvault/ 'TestRunSignerServeStartupGolden|TestSignerStreamCodesEmittedByProduction'
mutant M7-row-removed-constant-kept "$CODES" \
  's/\t\{CodeInvalidPublicKey, ExitRefused, true, "[^"]*"\},\n//' \
  ./internal/keyvault/signerclient/ 'TestErrorContractRegistryComplete'
mutant M8-signature-invalid-exit-class "$CODES" \
  's/\{CodeSignatureInvalid, ExitFailure, true,/{CodeSignatureInvalid, ExitRefused, true,/' \
  ./cmd/mac-keyvault/ 'TestRunVerify'
mutant M9-duplicate-stream-row-not-found-declared-twice "$CODES" \
  's/(\{CodeNotFound, ExitFailure, true, "[^"]*"\},)/$1\n\t{CodeNotFound, ExitFailure, true, "dup"},/' \
  ./internal/keyvault/signerclient/ 'TestErrorContractRegistryComplete'

# F1: fixture removed for a declared startup code
echo "== M10-startup-fixture-removed (invalid_service)"
cp "$FIX" /tmp/fix.bak; rm "$FIX"
run_mask ./internal/keyvault/ 'TestSignerGoldenCoversStreamErrorCodes'; rc1=$?
run_mask ./cmd/mac-keyvault/ 'TestSignerStreamCodesEmittedByProduction'; rc2=$?
cp /tmp/fix.bak "$FIX"
if [ $rc1 -ne 0 ] && [ $rc2 -ne 0 ]; then echo "  KILLED (both suites)"; else echo "  SURVIVED in one suite (rc $rc1 / $rc2)"; fi

echo "post-harness worktree status (must equal pre-harness):"; git status --short
