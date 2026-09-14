# TASK-260915-2ny9kd review verdict — CR revision 1

Verdict: **changes_requested** → `to-dev`

repeat-of: none

Reviewed candidate: base `39131c7b28152fda50ed6224ef7afe566d8829f2`, tree `9a0432f53e1f428a4a209f0916b1fb737e048c03`, 46 paths. Every candidate path was byte-compared with the live worktree and matched. The attached full validation is complete and ends with exit 0 for `go test -count=1 ./...`, `go vet ./...`, and `go build ./...`; this review reran the new-package behavioral tests with `-count=1`, plus `go vet ./...` and `go build ./...`, all exit 0.

## F1 — unversioned sessions bypass the hello fingerprint attestation

Shape: **bypass path around the check**.

`SignerServer.Serve` resolves the key for hello, but retains `Address.Version == 0`; every later operation calls `Manager.Describe`, `Manager.Sign`, or `Manager.PublicKeyFor` with that unpinned address and therefore resolves newest again. The README/SKILL contract says a consumer compares `Hello().Fingerprint` before the first signature, but that attestation does not bind later operations to the same key.

Adversarial production probe: built the real `cmd/mac-keyvault` binary, created only `works.relux.mac-keyvault.key.test.reviewer-rotate-74812.v1`, started `signer serve --address test/reviewer-rotate-74812`, read the hello, rotated to v2, then sent `pub` on the existing stream. The hello returned v1 fingerprint `72_R-oEohLEmaYuojyfrgbfN3yKTqsyNuhrmLr-XuR4`; the response returned v2 fingerprint `vHgju4a3myl5cv9e_GS9BrpbHiMAjNrTTAdtJ_xFORU`; `identity_changed=true`; EOF still exited 0. Both throwaway generations were deleted successfully.

Required rework: pin the resolved generation for the lifetime of the process (or enforce an equally strong protocol-level identity binding) so a successful hello cannot authorize operations by another key. Add a production-entry regression that rotates between hello and the first `pub`/`sign`, with a positive pinned-version control. Add a narrowing mutant that restores per-request newest resolution and prove the regression kills it.

## F2 — golden negative coverage is 10 of 13 documented stream codes

Shape: **unchecked AC row / gate coverage ratio below the normative set**.

The task requires one byte-exact negative fixture per error code. Enumerating fixture response bytes yields 10 distinct codes: `bad_request`, `expired`, `high_s_refused`, `invalid_digest`, `invalid_signature`, `missing_id`, `not_found`, `signature_invalid`, `unknown_op`, `usage_refused`. README's signer stream contract documents 13 reachable codes; no golden fixture drives `metadata_unknown`, `unsupported_primitive`, or `security`, all of which are reachable through the production handlers (`sign`/`verify` → Manager authorization/backend; `pub` also emits `security` for an unreadable public half). Existing unit tests of Manager gates are not byte-exact signer-wire evidence.

Required rework: add deterministic byte-exact signer-v1 fixtures and production-path golden sessions for the three missing documented codes, report the source-derived ratio as 13 of 13, and add a narrowing mutant proving the fixture/session enumeration fails when one documented code is omitted. Also make the README's “one negative per error code” claim match the measured corpus.

## Evidence summary

- AC driving evidence claimed by producer: 12 of 15 rows; the golden-error row is incomplete as measured above.
- Reviewer targeted suite: `go test -count=1 ./internal/keyvault ./internal/keyvault/signerclient ./cmd/mac-keyvault -run 'TestSignerServe|TestStart|TestCall|TestTyped|TestRunSigner'` — exit 0.
- Reviewer static/build checks: `go vet ./...` and `go build ./...` — exit 0.
- No product files were modified by the reviewer. Findings require producer rework; this is not a Stop-The-Line boundary.
