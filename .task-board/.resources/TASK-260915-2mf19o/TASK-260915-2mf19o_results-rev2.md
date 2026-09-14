# TASK-260915-2mf19o — rev2 (rework of CR rev1 F1-F5 + consolidated record model v2 + error contract)

Candidate: uncommitted working tree of `task-board/story/STORY-260915-3r0ys5` on base `f9ec756`.
Scope: `cmd/mac-keyvault/{main.go,main_test.go}`, `internal/keyvault/{keyvault.go,record.go,registry.go,lock.go,security_darwin.{go,c,h},security_unsupported.go,keyvault_test.go,security_darwin_test.go}`, `README.md`, `agents/skills/mac-infra/SKILL.md`, `LOGBOOK.md` (setup/deinit unchanged from rev1).
Three orchestrator directives (agent extraction for keys; consolidated model: kind-first label, always `.v<N>`, uniqueness `(kind, service, purpose, version)`, `origin` replaces `issuer`, per-kind format keys; §8 error contract) were applied before this handoff.

## Headline findings (LOGBOOK 2026-09-15 1425)

1. **rev1 private keys were extractable.** `kSecAttrIsExtractable=false` inside `kSecPrivateKeyAttrs` is ignored by the legacy `SecKeyCreateRandomKey` path: a probe on the rev1 shape returned the private key from both `SecKeyCopyExternalRepresentation` (status 0) and `SecItemExport` (224 bytes). At the top level it clears `CSSM_KEYATTR_EXTRACTABLE`; both paths fail with `-25316 errSecDataNotAvailable`, zero bytes leak, the public half stays readable. Attested by `TestSecurityStorePrivateKeyIsNotExtractable`; mutant M5 (rev1 shape) killed.
2. **rev1's SecAccess was never installed.** `kSecAttrAccess` inside `kSecPrivateKeyAttrs` is ignored too; the creator-only ACL rev1 saw was the keychain default. A two-application list inside the private dict yields a one-entry ACL; at the top level the list is installed verbatim. `TestSecurityStoreACLTrustsOnlyCallingBinary` reads the installed ACL back and requires every entry authorising sign/decrypt/derive/export/MAC to trust exactly `os.Executable()` (M6 second app, M6b `SecACLSetContents(NULL)` killed).
3. **`SecItemUpdate` orphans legacy keys.** It wrote `kSecAttrApplicationTag` into the label attribute; three probe keys were orphaned and deleted by exact (label, tag) pair. `UpdateTag` uses `SecKeychainItemModifyAttributesAndData(kSecKeyApplicationTag)`; `TestSecurityStoreKeychainRoundTrip` finds the item by label after the update and deletes it.

## Review findings F1-F5

| Finding | Fix | Production call site | Named test(s) | Narrowing mutant |
| --- | --- | --- | --- | --- |
| F1 foreign label reaches the store | Only `<service>/<purpose>` + `--kind`/`--version` is an address; every input without a slash (foreign label, lookalike/sibling namespace, bare name, bare prefix, **and a full label inside the prefix**) is `foreign_label`, exit 3, zero backend calls (`List` included). | `run` → `singleAddress` → `keyvault.ParseAddress` → `RequireOwnLabel`; `Manager.Delete` re-checks the resolved label | `TestRunForeignLabelRefusedAtEntry` (9 commands × 8 inputs + positive controls + bad-part rows), `TestParseAddressAndLabel`, `TestRequireOwnLabel` | M1, M10, M16 — killed |
| F2 duplicate race | `Manager.create` holds an exclusive `flock` across one listing and the create; both duplicate shapes (exact tuple, any rotated generation of the family) are decided from that listing. | `Manager.Init`/`Rotate` → `create` under `FileLock{~/Library/Application Support/mac-infra/keyvault/init.lock}` | `TestManagerInitDuplicateRefusalIsAtomic` (barrier in `List`; locked → 1 create + 1 `duplicate`; `NoLock` positive control → 2 creates), `TestFileLock` | M2, M12 — killed |
| F3 usage errors bypass JSON | `run` scans for `--json` anywhere; every failure goes through `output.fail` → `{ok:false, error:{code:"usage", message, hint:<usage line>}}`, exit 2, empty stderr; flag parser output is captured. | `run` → `output.fail` → `classify(*usageError)` | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore` (29 shapes × json-first/json-last/text, store untouched); built binary: `--json init` → envelope rc=2, 0 stderr bytes | M3, M3b, M17 — killed |
| F4 rotate guesses keychain | `Manager.Rotate` refuses `metadata_unknown` for an unreadable tag, a non-schema-2 record (v1 tag, absent tag), a schema-2 record with unknown store, and a record contradicting its label; `user_presence` is persisted and copied. | `Manager.Rotate` | `TestManagerRotateRefusesUnknownMetadata` (6 shapes + positive control), `TestRunRotateRefusesUnknownMetadata` | M4, M4b, M21 — killed |
| F5 positive-only evidence | Top-level `kSecAttrIsExtractable=false` and `kSecAttrAccess`; bridge probes `MacKeyVaultProbeExport` / `MacKeyVaultCopyACL` read the real item back. | `SecurityStore.Create` → `MacKeyVaultCreate` | `TestSecurityStorePrivateKeyIsNotExtractable` (-25316 both paths, 0 bytes, public readable), `TestSecurityStoreACLTrustsOnlyCallingBinary` | M5, M6, M6b — killed |

## Consolidated record model v2 (+ directives)

- Label `works.relux.mac-keyvault.<kind>.<service>.<purpose>.v<N>` (`.v<N>` always); uniqueness `(kind, service, purpose, version)`; `init` refuses when any version of `(kind, service, purpose)` exists (hint: use rotate). Address `<service>/<purpose>` + `--kind` (default key) + `--version` (default newest) on describe/pub/rotate/delete/meta; `list [--service] [--kind]`. Resolution is by label parsing, so an item with an unreadable record is still found (and refused by rotate/meta with `metadata_unknown`).
- Record fields: schema, kind, service, purpose, version, title, description, algorithm, store, extraction, usages, format{public,signature,envelope}, created, origin{user,host,tool,source:"generated"}, issuer (null for keys), validity, meta, plus `user_presence` (omitempty; addition so rotate reproduces the policy). Derived, never stored: label, fingerprint, exposure (from the registry row; `unknown` without a row), operations.
- Validation before any Security call: service/purpose `[a-z0-9-]{1,40}`; kind ∈ 4 but only `key` created (`unsupported_kind`); algorithm ec-p256 (aes-256-gcm/opaque → `invalid_algorithm` for a key; ec-p384/rsa-3072 `unsupported_algorithm`; ed25519 refused explicitly); usages subset, non-empty, unique; per-kind format keys (envelope refused on a key); extraction none|human|agent — **human and agent are valid for a key via the literal flag and persisted as policy** (T7 wires the ACL; every key stays non-extractable at the keychain level now, and `describe` derives `export-private` from the recorded policy with `via: reserved`); any extraction ≠ none on the Enclave refused; `--generate` refused for a key (`invalid_generate`); title ≤ 80; validity ordering; 23 reserved meta names and value types.
- Registry: exactly one row `(key, ec-p256, keychain)` → exposure never; operations ecdsa-sha256-sign (sign, expires), ecdsa-sha256-verify, ecdh-p256 (wrap), ecies-p256-encrypt, ecies-p256-decrypt (decrypt, expires), export-public (via pub), export-private (extraction ≠ none; `human_authorized: true` for human; via reserved). No row → `[]` + `unsupported_primitive`.
- Error contract: `{code, message, hint, os_status}`; codes used: usage (2), foreign_label, duplicate, confirmation_required, metadata_unknown, invalid_* (3), not_found (1, hint names existing generations/kinds), missing_entitlement (1, -34018), security (1, other OSStatus with its name), failure (1, I/O). Text mode: `error: <code>: <message>`, `os_status: N (name)` when present, `hint: <hint>`.
- v1 tags → schema 1, service/purpose/kind/algorithm unknown; absent tag → schema 0; malformed → schema 0 + `record_unreadable` finding; never upgraded.

## AC coverage — 11 of 11 test-driven rows driven through `run(...)` / `Manager` / `SecurityStore`; row 12 (CR revision) is produced by the handoff

| # | AC row | Production call site | Named test |
| --- | --- | --- | --- |
| 1 | F1 foreign label exit 3, zero backend calls, mutant | `run`→`ParseAddress` | `TestRunForeignLabelRefusedAtEntry`; M1/M10/M16 |
| 2 | F2 atomic duplicate, concurrent regression + positive control, mutant | `Manager.create`+`FileLock` | `TestManagerInitDuplicateRefusalIsAtomic`; M2/M12 |
| 3 | F3 every usage error → JSON envelope, empty stderr, exit 2, no backend call | `run`→`output.fail` | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore`; M3/M3b/M17 |
| 4 | F4 rotate refuses unknown store/policy | `Manager.Rotate` | `TestRunRotateRefusesUnknownMetadata`, `TestManagerRotateRefusesUnknownMetadata`; M4/M4b/M21 |
| 5 | F5 export fails with documented error; ACL = exactly calling binary; ACL mutant | `SecurityStore.Create` | `TestSecurityStorePrivateKeyIsNotExtractable`, `TestSecurityStoreACLTrustsOnlyCallingBinary`; M5/M6/M6b |
| 6 | record round-trips init/list/describe/rotate | `run` init/list/describe/rotate/meta | `TestRunRecordRoundTrip`, `TestRunAgainstLoginKeychain` (real keychain) |
| 7 | reserved names inside meta refused | `ValidateMetaEntry` via `Manager.Init`/`MetaSet` | `TestRunInitValidatesRecordBeforeStore/meta_reserved_*`, `TestRunJSONEnvelopeAndExitCodes/meta_set_reserved`, `TestValidateNew`; M7 |
| 8 | invalid service/purpose/algorithm/usage/format/extraction refused before any Security call | `Manager.Init`→`ValidateNew` | `TestRunInitValidatesRecordBeforeStore` (22 rows, `store.touched()==false`), `TestManagerInitValidatesThenGatesDuplicates`; M8/M9/M15/M19 |
| 9 | describe: operations for ec-p256, `[]` + `unsupported_primitive` for unknown row | `run describe`→`Operations` | `TestRunDescribeOperationsAndLegacy`, `TestOperationsRegistry`; M14 |
| 10 | v1 tags read as schema 1, never upgraded | `DecodeRecord` | `TestRunDescribeOperationsAndLegacy`, `TestRecordEncodingAndLegacyTags`; M13 |
| 11 | tests use the test namespace only | `GuardedStore`/`guardedBackend` (`IsTestLabel`: service `test`) | `TestGuardedStoreRefusesNonTestLabels`; keychain dump after the suite: 0 items |
| 12 | go vet/build/test -count=1 ./... green | — | commands below |

Directive rows: uniqueness with kind (`TestRunJSONEnvelopeAndExitCodes/describe_other_kind`, `TestManagerListAndDescribe`; M20), error contract on every envelope (`runJSON` asserts code+message+hint on every error; text shape asserted in `TestRunJSONEnvelopeAndExitCodes`; M17/M18), extraction agent/human persisted for keys (`TestRunRecordRoundTrip`, `TestValidateNew`, `TestManagerRotate` copies it), per-kind format (`TestValidateNew/format_envelope_for_key`; M19).

## Mutant table (harness `TASK-260915-2mf19o_mutants-rev2.py`, log `TASK-260915-2mf19o_mutants-rev2.log`)

| Mutant | Finding | What it narrows the gate to | Named failing test(s) | Result |
| --- | --- | --- | --- | --- |
| M1: ParseAddress accepts a full label inside the prefix as an address | F1 | admits one raw-label shape (own full label) past the address-only contract | `TestRunForeignLabelRefusedAtEntry` (rc=1)<br>`TestParseAddressAndLabel/full_own_label` (rc=1) | killed |
| M2: lock released after the duplicate check, before Create | F2 | admits the concurrent second create of one label | `TestManagerInitDuplicateRefusalIsAtomic` (rc=1) | killed |
| M3: usage errors bypass the JSON emitter | F3 | admits plain-text usage output in --json mode | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore` (rc=1) | killed |
| M3b: unknown command prints text and exits 2 directly | F3 | admits one usage path (unknown command) around the envelope | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore/unknown_command` (rc=1) | killed |
| M4: rotate maps store unknown to keychain | F4 | admits the unknown-store schema-2 record (schema-1/unreadable still refused) | `TestManagerRotateRefusesUnknownMetadata/unknown_store` (rc=1)<br>`TestRunRotateRefusesUnknownMetadata/unknown_store` (rc=1) | killed |
| M4b: rotate upgrades a schema-1 record to schema 2 with guessed service/purpose | F4 | admits the rev1-tag key | `TestManagerRotateRefusesUnknownMetadata/schema_1_keychain` (rc=1)<br>`TestRunRotateRefusesUnknownMetadata/rev1_keychain` (rc=1) | killed |
| M5: kSecAttrIsExtractable moved back inside kSecPrivateKeyAttrs (rev1 shape) | F5 | admits an extractable private key while every other attribute stays | `TestSecurityStorePrivateKeyIsNotExtractable` (rc=1) | killed |
| M6: ACL trusted-application list gains a second binary (/usr/bin/security) | F5 | admits one more application into the private-key ACL | `TestSecurityStoreACLTrustsOnlyCallingBinary` (rc=1) | killed |
| M6b: private-key ACL entries rewritten to trust any application (SecACLSetContents NULL) | F5 | the SecAccess is still installed but its private entries admit every application | `TestSecurityStoreACLTrustsOnlyCallingBinary` (rc=1) | killed |
| M7: "fingerprint" dropped from ReservedMetaNames | model | admits one reserved name inside meta | `TestValidateNew/meta_reserved_fingerprint` (rc=1)<br>`TestRunInitValidatesRecordBeforeStore/meta_reserved_json` (rc=1) | killed |
| M8: ed25519 accepted as an algorithm | model | admits one known-unsupported algorithm | `TestValidateNew/algorithm_ed25519` (rc=1)<br>`TestRunInitValidatesRecordBeforeStore/algorithm_ed25519` (rc=1) | killed |
| M9: extraction agent admitted on a Secure Enclave key | model | admits one extraction value the Enclave can never honour | `TestValidateNew/extraction_agent_enclave` (rc=1) | killed |
| M10: RequireOwnLabel accepts the prefix without its trailing dot | F1 | admits the works.relux.mac-keyvaultX lookalike namespace | `TestRequireOwnLabel` (rc=1) | killed |
| M11: delete of an explicit version needs no confirmation | delete | admits one unconfirmed delete shape | `TestManagerDeleteGates/own_version_unconfirmed` (rc=1)<br>`TestRunJSONEnvelopeAndExitCodes/delete_unconfirmed_versioned` (rc=1) | killed |
| M12: duplicate check ignores rotated generations | duplicate | admits init of an address that exists only as .vN | `TestManagerInitValidatesThenGatesDuplicates` (rc=1) | killed |
| M13: v1 tag decoded as schema 2 | model | admits a silent upgrade of the legacy record | `TestRecordEncodingAndLegacyTags` (rc=1)<br>`TestRunDescribeOperationsAndLegacy` (rc=1) | killed |
| M14: unknown registry row falls back to the ec-p256 keychain row | model | admits guessed operations for an unknown primitive | `TestOperationsRegistry` (rc=1)<br>`TestRunDescribeOperationsAndLegacy` (rc=1) | killed |
| M15: record validation runs after the store listing | model | admits a Security call before an invalid record is refused | `TestManagerInitValidatesThenGatesDuplicates` (rc=1)<br>`TestRunInitValidatesRecordBeforeStore` (rc=1) | killed |
| M16: singleAddress accepts a parseable full label before ParseAddress | F1 | admits one raw-label shape at the CLI layer around the address gate | `TestRunForeignLabelRefusedAtEntry` (rc=1) | killed |
| M17: usage errors emitted without a hint | contract | admits one envelope class that violates {code, message, hint} | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore` (rc=1) | killed |
| M18: missing_entitlement reported as a policy refusal (exit 3) | contract | admits one operational failure into the refusal exit class | `TestRunInitMissingEntitlementIsExplicit` (rc=1)<br>`TestRunSecurityErrorIsExitOne` (rc=1) | killed |
| M19: format.envelope admitted on a key | model | admits one format key outside the per-kind allowed set | `TestValidateNew/format_envelope_for_key` (rc=1)<br>`TestRunInitValidatesRecordBeforeStore/format_envelope_key` (rc=1) | killed |
| M20: address match ignores kind | model | admits a record of another kind for the same service/purpose (uniqueness tuple loses kind) | `TestRunJSONEnvelopeAndExitCodes/describe_other_kind` (rc=1)<br>`TestManagerListAndDescribe` (rc=1) | killed |
| M21: rotate accepts a record that contradicts its label | F4 | admits one metadata mismatch shape | `TestManagerRotateRefusesUnknownMetadata/label_mismatch` (rc=1) | killed |

Survivors: 0 of 24. Files restored byte-exact after every mutant (`git status` unchanged; no `.mutant-backup`; keychain dump 0 test items).

## Stated bounds and deviations

- **Test namespace**: the AC text says `works.relux.mac-keyvault.test.` labels; with the directive's kind-first label that namespace is service `test` (`works.relux.mac-keyvault.<kind>.test.<purpose>.v<N>`), enforced by `IsTestLabel` in both guards (rev1-era `…test.` labels stay deletable by the cleanup).
- **Cross-process atomicity** is proven with two `flock` holders on separate descriptors inside one test process plus a barrier that forces both Inits into the window; no two-OS-process regression exists (the production binary exposes no hook to hold it inside the window).
- **ACL attestation proves the installed ACL**, not that the tool's own `SecAccess` produced it: `SecAccessCreate(NULL)` and the keychain default are also creator-only, so "correct single-app list inside `kSecPrivateKeyAttrs`" is indistinguishable by readback.
- **`SecItemUpdate` mutant not executed** in the harness: it orphans a real keychain item on every run (proven once by probe, cleaned by exact pair). `TestSecurityStoreKeychainRoundTrip` fails on that shape by construction but that failure was not replayed.
- **Extraction human/agent** is recorded policy only in this revision; the keychain item is non-extractable regardless (`TestSecurityStorePrivateKeyIsNotExtractable` covers extraction none; no test creates a human/agent key against the real keychain and asserts extractability either way — T7 owns that).
- **Schema-1 items are listed but not addressable** unless their label happens to parse as `<kind>.<service>.<purpose>.v<N>`; rev1 was never merged, so no such items exist outside test cleanup.
- `user_presence` is an addition to the schema-2 field list (never true on this binary; -34018). `./scripts/setup.sh` end-to-end install not run. No registry row for the Enclave in this revision (`unsupported_primitive`).

## Commands (all run standalone, exit codes real)

| Command | Exit |
| --- | ---: |
| `gofmt -l cmd internal` (empty) | 0 |
| `go vet ./...` | 0 |
| `go build ./...` | 0 |
| `git diff --check` | 0 |
| `go test -count=1 ./...` (27 packages ok, log `TASK-260915-2mf19o_go-test-rev2.log`, exact candidate) | 0 |
| `python3 mutants.py` (24 mutants, 0 survivors) | 0 |
| `security dump-keychain \| grep -c mac-keyvault` after the suite | 0 items |
| built binary: `--json init` (usage envelope with usage-line hint) | 2 |
| built binary: `init --service Bad --purpose x` (text `error: invalid_service: …` + `hint:`) | 3 |
| built binary: `--json delete <full own label> --confirm` (foreign_label, 0 stderr bytes) | 3 |
| built binary: `init --service test --purpose smoke --enclave` (missing_entitlement, os_status -34018) | 1 |
