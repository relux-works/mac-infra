# TASK-260915-2mf19o — results rev6 (CR rev5 F13 rework, class closed per orchestrator directive)

Candidate: uncommitted working tree of `.temp/STORY-260915-3r0ys5/worktree` on base `f9ec756b123ea66a02545369ed007d9ddd8c5540`.

## What changed

- **F13 root cause and class fix.** `ValidateNew` checked validity only for ordering when both bounds were present; a key with `{not_before: T, not_after: null}` passed and `Manager.Rotate` reproduced it. Instead of one more `if`, `internal/keyvault/invariants.go` is one table-driven per-kind validator with exactly one row per JSON field of `Record` (schema, kind, service, purpose, version, title, description, algorithm, store, extraction, usages, format, created, origin, issuer, validity, meta). `TestRecordInvariantsCoverEveryField` compares the table to the struct's JSON tags, so a field cannot be added without a row. `user_presence` is the one stated bound (request flag; no value rule).
- **Kind-specific rules now enforced** (model v2 §2/§4): `validity.not_before` null unless certificate, certificate needs both bounds; `issuer` null unless certificate; algorithm per kind (`ec-p256` refused on secret, `aes/opaque` refused on key/public-key/certificate); extraction `human|agent` only on key/secret, enclave never extractable; format vocabulary per kind (certificate `x509-der|x509-pem|pkcs7-chain`, secret `json|der`); `created` non-null; `origin.user/host/tool` present and `source` = `generated` | `imported:<64 hex>`; `version ≥ 1`; `schema == 2`.
- **Call sites.** `ValidateNew` (init) runs the table; `ValidateStored(label, rec)` adds label agreement and is called by `Manager.Rotate` (`internal/keyvault/keyvault.go`) and `updateMeta` (meta set/unset) as `metadata_unknown`, zero `Create`/`UpdateTag`, old tag byte-identical; `Key.Findings` runs it on every read and appends `record_invalid:<code>` (reads never refuse). `created` is stamped before validation in Init and Rotate (moved out of `create`). `rotate`'s ad-hoc unknown-store and label-mismatch cases are folded into the table. `localOrigin` records `unknown` for a failed user/host lookup instead of an empty string.
- **Shared forgery table** `internal/keyvault/recordtest` (28 single-field forgeries + label mismatch + 2 positive controls) drives `TestForgedStoredRecordRefusedEverywhere` (external test package, `Manager.Rotate/MetaSet/MetaUnset/Describe`) and `TestRunForgedStoredRecordRefusedEverywhere` (`run(...)`: rotate, meta set, meta unset, describe). Named F13 regressions also added to `TestManagerRotateRefusesUnknownMetadata/forged_not_before`, `TestRunRotateRefusesUnknownMetadata/forged_not_before`, `TestValidateNew/validity_not_before_on_key`; `TestValidateRecordPerKind` covers certificate/secret/public-key rows that `ValidateNew` cannot reach (unsupported_kind first).
- **F2 determinism.** M2 (lock released before Create) had survived by scheduler luck in this run; `fakeStore.createGate` now holds `Create` until both racers have listed, so the kill is deterministic (3/3 runs).
- README + SKILL sentences, LOGBOOK 1815 entry.

## Validation (real exit codes, `validation-rev6.log`, `go-test-rev6.log`)

| Command | rc |
| --- | ---: |
| `gofmt -l cmd internal` | 0 (no output) |
| `go vet ./...` | 0 |
| `go build ./...` | 0 |
| `git diff --check` | 0 |
| `go test -count=1 ./...` | 0 (27 packages ok incl. `internal/keyvault`, `cmd/mac-keyvault`; real login-keychain tests included) |
| `mac-keyvault --json list` after the suite | `[]` — no test items left |
| Mutant harness `mutants-rev6.py` (50 mutants, two bounded runs) | 0 survivors |

Not run: `./scripts/setup.sh` end-to-end install (unchanged in this delta).

## AC coverage — 12 of 12 test-driven rows driven (row 13, CR revision, is produced by the handoff)

| # | AC row | Production call site | Named test(s) |
| --- | --- | --- | --- |
| 1 | F1 foreign full label, exit 3, zero backend calls | `keyvault.ParseAddress` via `singleAddress` in `run()` | `TestRunForeignLabelRefusedAtEntry`, `TestParseAddressAndLabel` (M1/M10/M16) |
| 2 | F2 duplicate atomic across processes | `Manager.create` under `FileLock` | `TestManagerInitDuplicateRefusalIsAtomic` (M2, now deterministic), `TestRunJSONEnvelopeAndExitCodes` (duplicate row); bound: in-process racers with separate flock descriptors |
| 3 | F3 JSON usage envelope, exit 2, empty stderr, no backend | `output.fail` in `run()` | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore`, `TestRunJSONSpellingsRouteUsageErrors` (M3/M3b/M26*) |
| 4 | F4 rotate refuses unknown store/policy | `Manager.Rotate` → `ValidateStored` | `TestManagerRotateRefusesUnknownMetadata/*`, `TestRunRotateRefusesUnknownMetadata/*` (M4/M4b/M21) |
| 5 | F5 private key non-exportable; ACL = calling binary | `security_darwin.c` create | `TestSecurityStorePrivateKeyIsNotExtractable`, `TestSecurityStoreACLTrustsOnlyCallingBinary` (M5/M6/M6b) — unchanged from rev5 |
| 6 | Model v2 round trip init/list/describe/rotate | `run(init|list|describe|rotate)` | `TestRunRecordRoundTrip`, `TestRunAgainstLoginKeychain`, positive controls in `TestRunForgedStoredRecordRefusedEverywhere/control_*` |
| 7 | reserved names inside meta refused | `ValidateMetaEntry` via `ValidateNew`/`MetaSet` | `TestValidateNew/meta_reserved_*`, `TestRunInitValidatesRecordBeforeStore`, `TestManagerMeta` (M7) |
| 8 | invalid service/purpose/algorithm/usage/format/extraction refused before any Security call | `ValidateNew` in `Manager.Init` before `create` | `TestManagerInitValidatesThenGatesDuplicates`, `TestRunInitValidatesRecordBeforeStore` (M8/M9/M15/M19) |
| 9 | describe operations for ec-p256; `[]` + `unsupported_primitive` for unknown row | `keyView` → `Key.Findings` → `Operations` | `TestRunDescribeOperationsAndLegacy` (M14, M30d) |
| 10 | **F13** key `not_before` refused at rotate/run, zero creates, tag identical; positive controls | `Manager.Rotate`/`updateMeta` → `ValidateStored`; `Key.Findings` | `TestManagerRotateRefusesUnknownMetadata/forged_not_before`, `TestRunRotateRefusesUnknownMetadata/forged_not_before`, `TestForgedStoredRecordRefusedEverywhere/*`, `TestRunForgedStoredRecordRefusedEverywhere/*` (M30–M30h) |
| 11 | v1 tags read as schema 1, never upgraded | `DecodeRecord` | `TestRecordEncodingAndLegacyTags`, `TestRunDescribeOperationsAndLegacy` (M13/M4b) |
| 12 | tests use `works.relux.mac-keyvault.<kind>.test.` labels only; existing items untouched | `GuardedStore` in both suites | `TestGuardedStoreRefusesNonTestLabels`, keychain list `[]` after the suite |

## Mutants — 50 replayed, 0 survivors (full table in `mutants-rev6.log`)

Rev6 additions (all narrowing; the gate stays present):

| Mutant | Narrows the gate to | Named failing test | Result |
| --- | --- | --- | --- |
| M30 validity row admits `{not_before: T, not_after: null}` on a key; inverted/both-set still refused | exactly the reviewer probe shape | `TestManagerRotateRefusesUnknownMetadata/forged_not_before`, `TestRunRotateRefusesUnknownMetadata/forged_not_before`, `Test(Run)ForgedStoredRecordRefusedEverywhere/validity_not_before_on_key`, `TestValidateNew/validity_not_before_on_key` | killed |
| M30b `created` row made a no-op | one row weakened | `…/created_null` ×3 | killed |
| M30c `origin` row removed from the table | one row dropped (orchestrator's mutant) | `TestRecordInvariantsCoverEveryField`, `…/origin_source_bogus`, `…/origin_user_empty` | killed |
| M30d reads skip `ValidateStored` | describe hides a forged record | `…/issuer_on_key`, `…/validity_not_before_on_key`, `TestRunDescribeOperationsAndLegacy` | killed |
| M30e meta writes skip `ValidateStored` | meta set/unset re-persist a forged record | `…/validity_not_before_on_key`, `…/issuer_on_key` | killed |
| M30f certificate row admits missing `not_before` | one certificate shape | `TestValidateRecordPerKind/certificate_no_not_before` | killed |
| M30g extraction `agent` admitted on public-key | one (kind, extraction) pair | `TestValidateRecordPerKind/public-key_extraction_agent` | killed |
| M30h `imported:` digest of any length | one origin shape | `…/origin_source_short_digest` ×2 | killed |
| M25b rotate skips `ValidateStored` (ValidateNew on next kept) | fields the next generation overwrites (version, created, label) | `…/version_zero`, `…/created_null`, `…/label_mismatch` | killed |
| M21 label agreement ignores version | version drift | `…/label_mismatch` ×2 | killed |

Re-targeted to the table (same class, same kill): M4, M8, M9, M19, M24, M24b, M25. M2 now kills deterministically.

## Stated bounds

- `user_presence` has no value rule (request flag answered by the backend; never true on an unprovisioned binary).
- Cross-process duplicate atomicity is proven in-process with separate flock descriptors; the reviewer's two-binary race remains the external witness.
- The ACL test attests the installed ACL, not its producer; SecItemUpdate mutant not replayed (orphans real items) — unchanged from rev2–rev5.
- `TestSecurityStoreKeychainRoundTrip` failed once in four package runs ("created key missing from list") while both packages hit the login keychain in parallel; green 3/3 afterwards and in the attached full run. Pre-existing flake, outside this delta; logged.
- `./scripts/setup.sh` not run.

Artifacts: `TASK-260915-2mf19o_results-rev6.md`, `_mutants-rev6.py`, `_mutants-rev6.log`, `_go-test-rev6.log`, `_validation-rev6.log`.
