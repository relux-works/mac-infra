# TASK-260915-2ny9kd review verdict — CR revision 8

Verdict: **changes requested** → `to-dev`.

Candidate: `CR-TASK-260915-2ny9kd-8` revision 8, base `39131c7b28152fda50ed6224ef7afe566d8829f2`, candidate tree `917589aa3ece1fc97c947567b002dba9ae4ede7b`, repository delta present.

Producer evidence reviewed: AC coverage is reported as 12 of 15 rows driven, with the remaining three identified as process rows. The frozen-candidate validation log is complete and records `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` at exit 0. Rev8 reports 135 of 135 result rows driven and 12 of 14 narrowing mutants killed; the two surviving mutants are documented as refusal clauses subsumed by the shared invariant layer. The reviewer reran `TestClientRefusesResultNotBoundToRequestOrHello` at the production client boundary and it passed. That corpus does not cover the finding below.

## F1 — nested duplicate members bypass the contract reader

`repeat-of: revision 6 F1`

Negative shapes: **bypass path around the check**, **JSON maps are too late for duplicate-key gates**, and **many variants, one unowned decision**.

Production call site: `signerclient.Start` → `(*Client).Describe` → `(*Client).Call` → `checkResult` → `checkDescribe` → `DecodeSingleJSON` (`internal/keyvault/signerclient/result.go`, `record.go`). The envelope and top-level result pass through `DecodeObject`, but nested record objects are decoded directly by `encoding/json`. `DisallowUnknownFields` rejects unknown names; it does not reject duplicate decoded names. The later member silently replaces the earlier member before `ValidateStored` sees the record.

The reviewer fake signer returned a valid hello followed by one successful `describe` response containing both identical and escape-equivalent duplicates inside newly typed rev8 objects:

- `format.public`: `wrong` then `spki-der`;
- `origin.u\u0073er`: `attacker` then `origin.user: tester`;
- `validity.not_before`: a timestamp then `null`;
- `meta.owner`: `attacker` then `probe`;
- `operations[0].na\u006de`: `forged` then `name: ecdsa-sha256-sign`.

`Client.Describe` returned nil error and the later values. The fake remained accepted instead of producing `ErrProtocol`, even though the package contract states that a repeated decoded member at any level is a contract break. The nearby existing honest-result corpus passed unchanged, so the probe does not merely make the client reject everything.

Evidence: `TASK-260915-2ny9kd_review-nested-duplicate-rev8.log`.

Required rework: give duplicate decoded-name validation one recursive owner before any nested contract object is materialized. Cover every object reachable inside a `describe` result, including closed structs, `meta`, and operation entries; do not add another hand-picked list of the five examples. Add production-entry fake-signer regressions for both identical and escape-equivalent nested duplicates, with a valid nearby control and assertions for `ErrProtocol`, process reap, and unusable session. Add a narrowing mutant that keeps the recursive/token-level gate present but admits exactly one nested duplicate class. Record the repeated structural repair in `LOGBOOK.md`.

## Bounds

- No live kvctl interop is possible because kvctl does not exist yet; the vendored Go client remains the contract boundary.
- The reviewer probe used a standalone fake executable and did not access or mutate Keychain items.
- The rev7 required-member typing repair works for non-duplicate values; this verdict is limited to duplicate decoded names below the result object's top level.
- The candidate worktree was not modified outside ignored `.temp/` reviewer artifacts.
