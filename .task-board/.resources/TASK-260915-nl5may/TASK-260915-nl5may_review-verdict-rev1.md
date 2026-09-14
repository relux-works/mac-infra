# TASK-260915-nl5may review verdict — CR revision 1

Verdict: **changes requested**  
Route: `to-dev`  
Repeat-of: `none`

Reviewed candidate: `CR-TASK-260915-nl5may-1` revision 1, base `1a150bd50e7ea064bd9b3dc12674372566925a98`, candidate tree `de1b5a172bae2dd0e14b25a5da494e894b3773a4`.

## Findings

### F1 — Keychain test guard has a Sign bypass (blocking)

Shape: **bypass path around the check**; the attached results also make an incorrect attestation that both guard implementations protect `Sign`.

`internal/keyvault/security_darwin_test.go:19` defines `GuardedStore` by embedding `Backend`. It overrides `Create`, `Delete`, and `UpdateTag`, but does not override `Sign`. Go therefore promotes `Backend.Sign` directly, bypassing `GuardedStore.guard`. `TestSecurityStoreSign` calls that promoted method at `internal/keyvault/security_darwin_test.go:349` and `:353`. `TestGuardedStoreRefusesNonTestLabels` tests only Create/Delete/UpdateTag at `:87-100`; it never tries Sign. A future or refactored integration test can consequently call the real Keychain signer with a non-test label even though the required guard test remains green.

This contradicts the DoD requirement “Throwaway labels only; existing Keychain items untouched (guard test)” and the producer artifact’s claim that `guardedBackend`/`GuardedStore` now guard `Sign`.

Required rework:

- Override `(*GuardedStore).Sign` and call `guard(label)` before delegating.
- Extend `TestGuardedStoreRefusesNonTestLabels` with a foreign-label Sign attempt and a positive test-label control; assert the wrapped backend saw no forbidden Sign call.
- Add a narrowing mutant that leaves the Sign guard present but admits one foreign-label class, and name the production test that kills it.

### F2 — high-S refusal occurs after the label backend read (blocking)

Shape: **bypass path around the check** / **check ordered after the protected backend boundary**.

`cmd/mac-keyvault/main.go:873` parses the signature, but label verification then constructs the manager and calls `Manager.PublicKeyFor` at `:899-904`, which resolves via `Backend.List`. The `high_s_refused` gate is not evaluated until `:917-919`. Thus a valid high-S signature without `--allow-high-s` touches Security.framework before the input/policy refusal, contrary to this task’s inherited “no backend call before validation” guard.

The high-S cases in `TestRunVerifyVerdicts` assert only exit/result fields; unlike malformed-input cases, they do not assert `store.touched()==false`. Mutant M4 checks whether the raw high-S refusal exists, not whether it precedes the backend boundary.

Required rework:

- Evaluate the high-S refusal immediately after `ParseSignature`, before loading SPKI or resolving a vault address.
- Add DER and raw label-path regression cases using independently prepared signatures and a fresh recording backend; assert exit 3 `high_s_refused`, JSON `verified:false`, and zero backend calls.
- Add a narrowing/order mutant that moves or limits this early refusal so one label-path high-S case reaches `Backend.List`; the new test must fail.

## Evidence reviewed and run

- Producer AC table: 15 of 15 rows driven through `run()`/Manager, plus one stated bound for the unavailable external kvctl verifier. The bound is not the reason for rejection.
- Producer full candidate validation: `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` all exit 0; logs are complete.
- Reviewer rerun: `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault` exits 0 (`.temp/TASK-260915-nl5may-review-targeted-tests-01.log`). This confirms the current suite is green while F1/F2 remain uncovered.
- `git diff --check` exits 0.
- The candidate remains uncommitted at the recorded checkpoint.

The logbook skill was inspected, but no `LOGBOOK.md` entry was added because a reviewer is forbidden to mutate the candidate tree. This verdict artifact is the persistent task record; the producer should add the concise logbook entry during rework.
