# TASK-260915-2mf19o review verdict — CR revision 1

Verdict: **changes requested** → `to-dev`

repeat-of: none

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `8674240cbcc8dcd76b971f9baa3b42946f4d6a00`, repository delta `present`.

## Findings

### F1 — High — production delete does not refuse a foreign label before the store call

`runDelete` sends every syntactically valid input through `ResolveLabel`. `ResolveLabel("com.apple.security.key")` becomes `works.relux.mac-keyvault.com.apple.security.key`; `Manager.Delete` therefore admits it and calls `Backend.Delete`. The committed production-entry test `TestRunDeleteGatesBeforeStore/foreign_confirmed` pins the wrong behavior: it expects `not_found` and a backend call instead of `foreign_label` with zero backend calls.

This contradicts the explicit AC and is the **check present but uncalled from production** shape: `RequireOwnLabel` rejects a foreign label when called directly, but the CLI rewrites the value before the guard sees it. Fix the production parsing/dispatch contract and add a named `run(...)` regression that supplies a foreign full label and asserts exit 3, `foreign_label`, and no List/Create/Delete call. Add a narrowing mutant that restores the rewrite/bypass and is killed by that test.

### F2 — High — duplicate-label refusal is racy and can admit two creates

`Manager.Init` performs `List`/lookup and `Create` as separate operations, while `SecurityStore` explicitly permits duplicate labels. A barrier-backed adversarial probe ran two `Manager.Init` calls for the same label and observed `create_calls=2 err1=<nil> err2=<nil>`. Two CLI processes have the same TOCTOU window, so the required duplicate refusal is not guaranteed.

Make uniqueness atomic across processes or otherwise make the Security.framework create shape reject an existing managed identity. Add a concurrent production-contract regression with a positive control and a narrowing mutant that restores the check-then-create race.

### F3 — Medium — JSON mode is bypassed by usage errors in named commands

The built production binary invoked as `mac-keyvault --json init` printed plain text `init requires exactly one label` and exited 2; stdout contained no JSON envelope. Flag-parser errors and several other usage paths behave the same way. `TestRunJSONEnvelopeAndExitCodes` does not cover usage failures, while `TestRunUsageErrorsDoNotReachStore/json_unknown` checks only the exit code and store effects.

Route every named-command outcome after `--json` selection through the JSON emitter. Add production-entry rows for missing/extra args, incompatible/unknown flags, and bad format, asserting a parseable error envelope, empty stderr, exit 2, and no backend call. Include a narrowing mutant that leaves JSON behavior only on operational/refusal paths.

### F4 — High — rotate silently converts unknown origin to keychain

`Manager.Rotate` maps `StoreUnknown` to `StoreKeychain` and creates the next version. A probe with an existing `StoreUnknown` key observed `err=<nil>`, `.v2` created in `keychain`, and one create call. Because store identity comes only from a parseable application tag, an unreadable/missing tag can hide an Enclave origin. This is **absence vs failure to read** plus **prove, or report nothing**, and violates the no-silent-fallback rule.

Refuse rotation when store/ACL metadata is unknown; do not guess keychain. Add a production-path negative and a narrowing mutant that restores the unknown→keychain fallback. If rotation is intended to preserve optional user-presence policy, persist and reuse that policy too rather than silently weakening it.

### F5 — High — required non-extractability and caller-only ACL have positive-path-only evidence

The real Security.framework tests prove create/list/public/delete, P-256/SPKI, and -34018 behavior. They never attempt private-key extraction and never verify the resulting `SecAccess` trusted-application set. A candidate that makes the private key extractable or broadens the ACL can keep every current test green. These are core security requirements, not an implementation detail.

Add executable tests against the composed keychain item that prove private material cannot be exported and the installed ACL is scoped to the calling binary/current user. Include a narrowing ACL mutant (gate remains but trust is broadened) and a named behavioral test that kills it. Keep all probes under `works.relux.mac-keyvault.test.` with guarded cleanup.

## AC and evidence assessment

Reviewer-measured AC coverage is **10 of 13 rows satisfied**. The duplicate-refusal, foreign-delete-refusal-at-production-entry, and JSON-for-every-command rows fail as described above. The producer's `13 of 13` claim counts direct helpers or partial assertions where the production behavior contradicts the row.

The producer's exact-candidate `go test -count=1 ./...` log is complete through all 27 packages and board notes record exit 0; it was reused because candidate, suite, configuration, and environment identities are unchanged. Reviewer reran `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault` (pass), `go vet ./...` (pass), `go build ./...` (pass), `gofmt -l cmd/mac-keyvault internal/keyvault` (clean), and `git diff --check` (pass). A separate reviewer full-suite invocation reached the initial tool yield and its final exit stream was not recoverable, so it is not claimed as passing evidence.

No external or human-only blocker exists; this is ordinary implementation/test rework.
