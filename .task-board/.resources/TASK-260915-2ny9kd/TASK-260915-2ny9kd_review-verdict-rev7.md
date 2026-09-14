# TASK-260915-2ny9kd review verdict — CR revision 7

Verdict: **changes requested** → `to-dev`.

Candidate: CR-TASK-260915-2ny9kd-7 revision 7, base `39131c7b28152fda50ed6224ef7afe566d8829f2`, candidate tree `b5cc239d0eccc23a416e48f2be316a9e2b5fba4e`, repository delta present.

Producer evidence reviewed: AC coverage reported as 12 of 15 rows driven; rev7 result corpus 77 of 77 rows; duplicate-member corpus 27 of 27 applicable entries; 18 of 18 narrowing mutants killed; frozen-candidate validation completed `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` with exit 0. Reviewer reran `go test -count=1 ./internal/keyvault/signerclient ./internal/keyvault ./cmd/mac-keyvault`; all three packages passed. These green checks do not cover the finding below.

## F1 — `describe` required members remain untyped and bypass the owned result gate

`repeat-of: revision 6 F2`

Negative shape: **bypass path around the check** and **many variants, one unowned decision**.

Production call site: `signerclient.Start` → `(*Client).Describe` → `(*Client).Call` → `checkResult` → `checkDescribe` (`internal/keyvault/signerclient/result.go`). `resultObject` requires the names `kind`, `version`, `service`, `purpose`, and `schema`, but `checkDescribe`'s typed projection omits all five. It decodes only `label`, `fingerprint`, `exposure`, `operations`, and `findings`, so the five required values are never type-checked.

The reviewer fake signer returned one valid hello followed by a successful `describe` result carrying `kind:{}`, `version:{}`, `service:[]`, `purpose:false`, and `schema:"two"`. `Client.Describe` returned nil error and exposed those malformed values to the caller. A nearby valid record also returned nil. This contradicts the Story's key-record-model-v2 contract: `schema` is numeric, `version` is an integer ≥1, and `kind`, `service`, and `purpose` are strings with closed value/grammar rules. It also contradicts rev7's claim that required result members are typed before a helper returns.

Evidence: `TASK-260915-2ny9kd_review-describe-type-bypass-rev7.log`.

Required rework: make `checkDescribe` validate the schema-2 record members it requires against the normative record model before `Describe` returns. At minimum reject wrong JSON types and invalid values for `schema`, `kind`, `version`, `service`, and `purpose`; preserve the explicitly stated open-vocabulary bound for additional record fields. Extend the existing production-entry `TestClientRefusesResultNotBoundToRequestOrHello` with valid controls and one negative per affected member. Because this repeats revision 6 F2, add a narrowing mutant that keeps `checkResult`/`checkDescribe` present but admits exactly one malformed required member. Record the regression/fix in `LOGBOOK.md` during producer rework; this reviewer did not modify the candidate tree.

## Bounds

- No live kvctl interop is possible because kvctl does not exist yet; the vendored Go client remains the contract boundary.
- Reviewer tests used a standalone fake signer and did not access or mutate Keychain items.
- The rev7 duplicate-member repair was inspected and its targeted tests passed; no independent duplicate-collapse bypass was reproduced.
