# TASK-260915-2ny9kd — rev8 results (after rev7 changes_requested: F1 describe typing, repeat-of rev6 F2)

Scope: client side only (`internal/keyvault/signerclient`) plus the record-model move it needs; the server (`internal/keyvault/signer.go`), the CLI and every golden fixture are byte-identical to rev7 (`git diff` on `internal/keyvault/testdata/signer-v1` is empty; `signer_golden_test` and `TestRunSignerServeStartupGolden` pass unchanged).

## F1 — `describe` required members untyped (repeat-of rev6 F2)

Root cause was structural: `signerclient` must stay stdlib-only and `keyvault` already imports it (the error-code registry, rev3), so the record model could not be reached from the client and was re-described by hand — a projection that forgot five members.

Fix (orchestrator note: "reuse keyvault.Record decoding + the per-kind invariant table"):

- The schema-2 record model moved to the contract package: `signerclient/record.go` (`SchemaVersion`, `Record`, `Format`, `Origin`, `Issuer`, `Validity`, `Time`, `StoreKind`, vocabulary constants, `Refusal`, `HintFixInput`, `LabelPrefix`, `Address`/`ParseLabel`/`RequireOwnLabel`, `ValidateName`/`ValidateKind`/`ValidateMeta`, `EncodeRecord`, `DecodeSingleJSON`) and `signerclient/invariants.go` (the full per-kind table, `ValidateRecord`, `ValidateStored`, `InvariantFields`, `ValidateIssuer`). Still stdlib-only. `internal/keyvault/record.go`, `invariants.go`, `keyvault.go` alias every name (type aliases, const aliases, thin wrappers); what stays vault-side is `DecodeRecord` (legacy tag), `ParseAddress`, `ValidateNew`, the registry, `Key`, `Findings`, `Exposure`. `Address.Matches` became `addressMatches` (a method cannot be declared on an alias).
- `signerclient.Description` (wire.go): `Record` embedded + `label`, `fingerprint`, `exposure`, `operations []Operation`, `findings []string`; `Operation{name,input,output,via,human_authorized}`; `Exposures = {never, process, unknown}`. `Client.Describe` now returns `Description` (typed), not `map[string]any`.
- `checkDescribe` (result.go), run inside `Call` by `checkResult` before `Describe` can return: presence gate (`resultObject`) → `DecodeSingleJSON` into `Description` (wrong JSON type, `null`, undefined member at ANY level = `ErrProtocol`; the same UseNumber + DisallowUnknownFields + single-document rule the vault applies to its own persisted tag) → `schema == 2` → identity bound to the hello (`label`, `fingerprint`, `kind`, `version`, `service/purpose == hello.address`) and `label == Record.Label()` → `ValidateStored(label, record)` (the vault's rows + label agreement) with `findings` required to carry exactly `record_invalid:<code>` when a row fails and no such finding when none does → `exposure ∈ Exposures`, `unknown` iff `unsupported_primitive` reported (then `operations` empty) → findings from the read vocabulary only (`validity_expired`, `unsupported_primitive`, `record_invalid:<code>`), no repeats, `validity_expired` only with `not_after` → every operation entry has non-empty `name` and `via`.

Production call site: `signerclient.Start`/`Client.Describe` → `Client.Call` → `checkResult` → `checkDescribe` (`internal/keyvault/signerclient/result.go`); `Describe` additionally decodes through `checkDescribe` so the typed value can never be returned unjudged.

## Regression (production entry, fake signer subprocess)

`TestClientRefusesResultNotBoundToRequestOrHello` (`contract_test.go`): 135 of 135 rows driven (was 77). The 58 describe rows:

| class | rows |
|---|---|
| controls (admitted) | `describe-control`, `describe-control-invalid-record` (usages [] WITH `record_invalid:invalid_usages`), `describe-control-expired` (not_after + `validity_expired`), `describe-control-no-primitive` (enclave + `exposure: unknown` + `unsupported_primitive` + no ops), `describe-control-user-presence` (declared schema field) |
| wrong JSON type, one member each | the reviewer probe `kind:{}`, `version:{}`, `service:[]`, `purpose:false`, `schema:"two"`; plus `version:"1"`, `version:1.5`, `exposure:1`, `findings:{}`, `findings:[1]`, `label:7`, `title:[]`, `usages:"sign"`, `format:"spki-der"`, `created:1700000000`, `origin:"generated"`, `validity:[]`, `meta:[]`, `store:{}`, operation entry `"sign"`, operation `name:1` |
| wrong value / not the hello binding | `schema` 3 / 0, `kind` certificate / unknown, `version` 2 / 0, `service` prod / TEST, `purpose` other / "", label of another generation, undefined member `colour`, `exposure` public / "" |
| invariant ↔ finding mirror | row fails & unreported (`usages: []`), row fails & another code reported, finding on a clean record, `algorithm: ed25519`, `store: cloud`, `extraction: always`, issuer on a key, `not_before` on a key, `created: null`, empty origin, reserved meta name, 81-char title — each refused because the finding the vault would write is absent |
| derived-member consistency | unknown finding, duplicate finding, `validity_expired` without `not_after`, `exposure: unknown` with a registry row, `unsupported_primitive` with `exposure: never`, `unsupported_primitive` with operations, operation without `via`, operation with undefined member `cost` |
| declared refusal (session usable) | `describe-refusal` (`metadata_unknown`) |

The fake's honest `describe` (`fake_test.go: fakeKey.describe`) is a complete valid schema-2 key record (every invariant row passes, label derived from the record) so the controls prove the gate admits what the vault writes.

## Mutants (rev8, `TASK-260915-2ny9kd_mutants-rev8.py`, log `_mutants-rev8.log`)

Each keeps `checkResult`/`checkDescribe` present and narrows it to admit one class; the suite run is `go test -run TestClientRefusesResultNotBoundToRequestOrHello ./internal/keyvault/signerclient/`.

| mutant | narrows the gate to | named failing test rows |
|---|---|---|
| M1 unmarshal-not-closed | typed decode kept, `json.Unmarshal` instead of `DecodeSingleJSON` (unknown members admitted) | describe-undefined-member, describe-operation-undefined-member |
| M2 schema-untyped | `schema` stripped before the typed decode and trusted as 2 (the reviewer's `schema:"two"`) | describe-schema-string, -schema-3, -schema-0 |
| M3 version-untyped | `version` stripped, trusted as hello.version (`version:{}`) | describe-version-object, -string, -float, -2, -0 |
| M4 kind-untyped | `kind` stripped, trusted as hello.kind (`kind:{}`) | describe-kind-object, -certificate, -unknown |
| M5 service-untyped | `service` stripped, trusted from hello.address (`service:[]`) | describe-service-array, -other, -uppercase |
| M6 purpose-untyped | `purpose` stripped, trusted from hello.address (`purpose:false`) | describe-purpose-bool, -other, -empty |
| M7 invariants-skipped | `ValidateStored` result ignored | 11 rows incl. describe-invalid-record-unreported, describe-control-invalid-record (control now refused) |
| M8 finding-vocab-open | unknown finding names admitted | describe-finding-unknown |
| M9 exposure-vocab-open | any exposure string admitted | describe-exposure-other, -empty |
| M10 exposure-unknown-unbound | `unknown` no longer tied to `unsupported_primitive` | describe-exposure-unknown-with-row, describe-no-primitive-with-exposure |
| M11 operations-unchecked | empty name/via admitted | describe-operation-without-via |
| M12 expired-unbound | `validity_expired` without `not_after` admitted | describe-expired-without-not-after |
| M13 schema-value-unbound | explicit `schema != 2` check removed | **SURVIVED** — bound: the invariant row `schema` refuses the same inputs through the findings mirror (`describe-schema-3`/`-0` still fail via "findings report \"\", the record model says record_invalid:invalid_schema"); the explicit check only improves the message |
| M14 label-derivation-unbound | `label == Record.Label()` check removed | **SURVIVED** — bound: `ValidateStored` label agreement (`metadata_unknown`) refuses the same inputs through the findings mirror; the explicit check only improves the message |

12 of 14 killed; the two survivors are documented redundancy (a second, shared-code layer refuses the same class), not admitted inputs.

## Gates (standalone, real exit codes)

| command | exit | log |
|---|---:|---|
| `gofmt -l .` (tracked) | 0 files | — |
| `go vet ./...` | 0 | `.temp/TASK-260915-2ny9kd/rev8/go-vet-01.log` |
| `go build ./...` | 0 | — |
| `git diff --check` | 0 | — |
| `go test -count=1 ./internal/keyvault/... ./cmd/mac-keyvault/` (live login keychain) | 0 | `TASK-260915-2ny9kd_go-test-all-rev8.log` |
| `go test -count=1 <the other 29 packages>` | 0 | same log (split into two bounded calls; together = `./...`, 34 packages) |
| `go test -count=1 -race ./internal/keyvault/...` | 0 | `TASK-260915-2ny9kd_go-test-race-rev8.log` |
| `mac-keyvault --json list --service test` afterwards | `result: []` | — |

AC coverage unchanged from rev7: 12 of 15 AC rows driven by named tests (docs, vet/build/test, Change Request are process rows); this rework adds no AC row and closes rev7 F1.

## Docs
README (Key Vault section: describe judgement, invariant-table pointer), SKILL.md (kvctl backend: typed `Description`, findings rule), `signerclient/wire.go` package doc, LOGBOOK 2245 entry.

## Bounds
- The primitive registry stays vault-side: an operation entry is checked for shape and non-empty `name`/`via`, not against the registry row.
- Whether `not_after` has passed is the server clock's call; the client checks presence, not time.
- The client serves schema-2 records only: a schema-0/1 item answers `describe` with a record the client refuses (`ErrProtocol`), by design — the contract client is for usable keys, the CLI keeps the operator view.
- No live kvctl interop (kvctl is not code yet).
