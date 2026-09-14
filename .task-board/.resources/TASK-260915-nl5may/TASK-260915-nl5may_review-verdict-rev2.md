# TASK-260915-nl5may review verdict — CR revision 2

Verdict: **accepted**  
Change Request: `CR-TASK-260915-nl5may-2`, revision 2  
Reviewed base: `1a150bd50e7ea064bd9b3dc12674372566925a98`  
Reviewed candidate tree: `32f01a16185c1526ced98f3898b87aa75655182c`

## Acceptance basis

- The independently materialized candidate tree is exactly `32f01a16185c1526ced98f3898b87aa75655182c`, matching the frozen revision.
- AC coverage is **15 of 15 rows driven** through production entry points (`run(sign)`, `run(verify)`, `Manager.Sign`, `Manager.PublicKeyFor`, and `SecurityStore.Sign`). The unavailable external kvctl verifier is explicitly stated as a bound; the task's executable interop requirement is independently exercised in both directions with Go `crypto/ecdsa` and with openssl against the real Keychain implementation.
- Rev1 F1 (**bypass path around the check**) is closed: `(*GuardedStore).Sign` calls the label guard before delegating. `TestGuardedStoreRefusesNonTestLabels` uses a signing-capable foreign-label control, observes zero leaked calls, and admits a test-label positive control. Narrowing mutant M14 preserves the guard while admitting one foreign label class and is killed; M15 deletion control is also killed.
- Rev1 F2 (**check ordered after the protected backend boundary**) is closed: `runVerify` rejects high-S immediately after parsing, before an SPKI read, address resolution, manager construction, or `Backend.List`. `TestRunVerifyHighSRefusedBeforeStore` drives DER/raw, label/SPKI, file input, absent-address, and absent-SPKI variants with zero backend calls plus a low-S positive control. Narrowing/order mutants M16–M18 are all killed.
- Strict DER, low-S normalization, raw `r||s`, JSON exit/verdict behavior, invalid digest lengths, malformed signatures, tampering, foreign addresses, usage and expiry gates, registry-only operation exposure, and `describe via=sign|verify` are covered by named production-entry tests. The source-text mutant rule is inapplicable: no gate in this scope inspects source text.
- The candidate remains uncommitted at checkpoint `1a150bd50e7ea064bd9b3dc12674372566925a98`; the repository delta is present and limited to the 17 declared paths.

## Reviewer verification

All commands ran on Darwin arm64 with Go 1.25.5 against the frozen candidate:

| Check | Result |
| --- | --- |
| Targeted CLI tests including strict DER, raw, high-S ordering, bad-input refusal, policy gates, and real Keychain/openssl interop | pass |
| Targeted keyvault tests including parser bounds, manager authorization, guarded labels, `SecurityStore.Sign`, and registry operations | pass |
| `go test -count=1 -v -run '^TestRunSignVerifyAgainstLoginKeychain$' ./cmd/mac-keyvault` | pass, not skipped |
| `go vet ./...` | rc 0 |
| `go build ./...` | rc 0 |
| `git diff --check <base> <candidate>` | rc 0 |
| `go test -count=1 ./...` | rc 0; complete log ends with `[exit 0]` |

Reviewer scratch logs are under `.temp/review-TASK-260915-nl5may/`; no candidate source was modified by the reviewer.
