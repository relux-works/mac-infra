# TASK-260915-2mf19o — rev4 (rework of CR rev3 F9-F11, repeat-of F6/F3)

Candidate: uncommitted working tree of `task-board/story/STORY-260915-3r0ys5` on base `f9ec756`.
Delta vs the rev3 candidate (`d8f7df5…`): `cmd/mac-keyvault/{main.go,main_test.go}`, `internal/keyvault/{record.go,keyvault_test.go}`, `README.md`, `LOGBOOK.md`. The cgo bridge, lock, registry, `keyvault.go`, SKILL, setup/deinit are byte-identical to rev3.

## Review findings F9-F11

| Finding | Fix | Production call site | Named test(s) | Narrowing mutants |
| --- | --- | --- | --- | --- |
| F9 (repeat-of F6/F3) JSON mode detected by string matching; `--json=TRUE`, `--json=1`, `-json=t` bypassed the envelope | Closed structurally per the orchestrator note: `wantsJSON` offers every token alone to a `flag.FlagSet` (`ContinueOnError`, output discarded) that defines only the `json` bool (`jsonToken`). The accepted spelling set is therefore, by construction, the set `flag.Bool`/`strconv.ParseBool` accepts (`--json`, `-json`, `=1/t/T/TRUE/true/True` with one or two dashes); a later `--json=false` wins like a repeated flag; `--` ends detection — and, so both agree, `parseFlags` now stops re-parsing after a consumed `--`. No string comparison remains. | `run` → `wantsJSON` → `jsonToken` (flag pre-parser) → `output.fail` | `TestRunJSONSpellingsRouteUsageErrors`: 14 spellings × {first, after command, last} = 42 usage shapes (exit 2, `code:"usage"`, hint = version usage line, empty stderr, `store.touched()==false`), 14 × 2 positive controls (`{ok:true}`), `json before terminator`, 12 text-mode negative controls (`=false/0/f/F/FALSE/False`, later-false-wins, `--jsonx`, `--json=maybe`, `--json=`, `-- --json`, `-- --json version`). Existing `assertUsageRefusal` (json-first/json-last/text on 42 shapes) still passes. | M26 (string matching of four spellings restored, pre-parser bypassed), M26b (pre-parser kept, exactly `--json=1` excluded), M26c (detector stops at the first non-json token, json-after-command bypass) — killed |
| F10 `list --kind bogus` reached `Backend.List` | `keyvault.ValidateKind` is the one closed-vocabulary gate; `ParseAddress` now calls it and `runList` applies it (and `ValidateName` for `--service`) before `newManager()`. | `run` → `runList` → `keyvault.ValidateKind` → `output.fail`; `ParseAddress` → `ValidateKind` | `TestRunListRejectsInvalidKindBeforeBackend` (`bogus`, `keypair`, `Key`, `key.`, `*` × json/text: exit 3 `invalid_kind`, `store.lists==0`; positive controls: `key`→2, `public-key`/`certificate`/`secret`→0, no filter→2, each with exactly one `Backend.List`; `--service Bad` refused with `lists==0`), `TestValidateKind` (4 kinds pass, 8 shapes refused, same code through `ParseAddress`) | M27 (list admits exactly `bogus`), M27b (validation present but after `Backend.List`) — killed |
| F11 numeric meta rounded through `float64` | Numbers are `json.Number` end to end: `DecodeRecord` decodes with `UseNumber`; `meta set --json-value` no longer converts; `keyView` re-decodes the record with `UseNumber` so init/describe/list/meta envelopes print the digits; `Rotate` copies the values unchanged; `ValidateMetaEntry` already admitted `json.Number`. | `runInit`→`collectMeta`→`decodeSingleJSON`; `runMeta set`→`decodeSingleJSON`→`Manager.MetaSet`; `DecodeRecord`; `keyView`; `Manager.Rotate` | `TestRunMetaNumberRoundTrips` (2^53+1 and 2^64+1 verbatim in the raw stored tag after init and meta set, in the raw init/describe/list/meta get/rotate envelopes, in the rotated v2 tag, old v1 tag untouched by rotate, text `meta get` prints the digits; `7` and `0.1` as nearby controls), `TestDecodeRecordPreservesNumericMeta` (decode → re-encode digit-exact, `ValidateMeta` admits, legacy tag empty meta) | M28 (only numeric meta converted after decode), M28b (meta set path converts — rev3 shape), M28c (tag exact, printed envelope rounded) — killed |

Repeat-of handling (standing order 8): the F3 class now has the structural fix the orchestrator asked for plus three named regressions at the detector (spelling set, single-spelling exclusion, placement) and the full-spelling regression the reviewer asked for.

## AC coverage — 12 of 12 test-driven rows driven through `run(...)` / `Manager` / `SecurityStore`; the CR revision row is produced by the handoff

Rows 1-2, 4-11 are unchanged from rev3 (`TASK-260915-2mf19o_results-rev3.md`): the backing sources are byte-identical except `main.go` (JSON detection, list kind gate, meta number, `--` in `parseFlags`) and `record.go` (`ValidateKind`, `UseNumber` decode), and the whole rev3 mutant set M1-M25b was replayed on this candidate — 0 survivors. The two rows the reviewer measured unsatisfied:

| # | AC row | Production call site | Named test |
| --- | --- | --- | --- |
| 3 | F3 every usage error in --json → envelope, empty stderr, exit 2, no backend call (now including every accepted `--json` spelling and placement) | `run`→`wantsJSON`/`jsonToken`→`parseFlags`/`requireNoArguments`/`decodeSingleJSON`→`output.fail` | `TestRunJSONSpellingsRouteUsageErrors`, `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore`, `TestRunVersionRejectsExtraInput`, `TestRunMetaJSONRejectsTrailingDocument`; M3/M3b/M17/M22/M22b/M23/M23b/M26/M26b/M26c |
| 6 | Model v2: record round-trips through init/list/describe/rotate (now including numeric meta) | `runInit`/`runDescribe`/`runList`/`runRotate`/`runMeta`→`Manager`→`EncodeRecord`/`DecodeRecord` | `TestRunRecordRoundTrip`, `TestRunMetaNumberRoundTrips`, `TestDecodeRecordPreservesNumericMeta`, `TestRecordEncodingAndLegacyTags`; M13/M28/M28b/M28c |
| 8 | invalid service/purpose/algorithm/usage/format/extraction (and kind, on every path that takes it) refused before any Security call | `runList`→`ValidateKind`/`ValidateName`; `ParseAddress`; `Manager.Init`→`ValidateNew` | `TestRunListRejectsInvalidKindBeforeBackend`, `TestValidateKind`, `TestRunInitValidatesRecordBeforeStore`, `TestRunForeignLabelRefusedAtEntry`; M27/M27b/M7/M8/M15/M19 |
| 12 | go vet/build/test -count=1 ./... green | — | commands below |

## Mutant table (harness `TASK-260915-2mf19o_mutants-rev4.py`, log `TASK-260915-2mf19o_mutants-rev4.log`; M1-M25b are the rev3 set replayed on this candidate, M26-M28c are new)

| Mutant | Finding | What it narrows the gate to | Named failing test(s) | Result |
| --- | --- | --- | --- | --- |
| M26: JSON detection narrowed back to string matching of four enumerated spellings (flag pre-parser bypassed) | F9 | admits every other flag.Bool true spelling (--json=TRUE, --json=1, -json=t, ...) into text mode on a usage error | `TestRunJSONSpellingsRouteUsageErrors` (rc=1) | killed |
| M26b: flag pre-parser kept, exactly one spelling (--json=1) excluded from detection | F9 | admits the single spelling --json=1 into text mode; every other spelling still selects the envelope | `TestRunJSONSpellingsRouteUsageErrors/--json=1_first` (rc=1) | killed |
| M26c: detector stops scanning at the first non-json token (json-after-command shapes bypass) | F9 | admits every "--json after the command" placement into text mode; --json first still detected with every spelling | `TestRunJSONSpellingsRouteUsageErrors/--json_after` (rc=1)<br>`TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore/list_with_arg` (rc=1) | killed |
| M27: list kind validation admits exactly one unknown kind ("bogus") | F10 | admits the single kind value bogus on the list path; the address paths still refuse it | `TestRunListRejectsInvalidKindBeforeBackend/json_bogus` (rc=1) | killed |
| M27b: list kind validated only after Backend.List was called | F10 | the refusal still happens (exit 3, invalid_kind) but one Security call precedes it | `TestRunListRejectsInvalidKindBeforeBackend` (rc=1) | killed |
| M28: DecodeRecord converts only numeric meta to float64 after the UseNumber decode | F11 | strings and bools still round-trip; numbers alone are rounded (2^53+1 -> 2^53) | `TestDecodeRecordPreservesNumericMeta` (rc=1)<br>`TestRunMetaNumberRoundTrips` (rc=1) | killed |
| M28b: meta set --json-value converts the parsed json.Number to float64 (rev4 shape) | F11 | init --meta-json numbers still exact; only the meta set path rounds | `TestRunMetaNumberRoundTrips` (rc=1) | killed |
| M28c: keyView re-decodes the record without UseNumber (stored tag exact, printed envelope rounded) | F11 | the record is persisted digit-exact; only what init/describe/list print is rounded | `TestRunMetaNumberRoundTrips` (rc=1) | killed |
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
| M22: version accepts and ignores extra positionals/flags (JSON emitter kept) | F6 | admits one command (version) around the usage gate while every other command keeps it | `TestRunVersionRejectsExtraInput` (rc=1) | killed |
| M22b: version parses flags but drops leftover positionals | F6 | admits the positional shape (version extra) while an unknown flag is still refused | `TestRunVersionRejectsExtraInput/version_positional` (rc=1) | killed |
| M23: JSON decoding kept, trailing document admitted (EOF check dropped) | F6 | admits a second/trailing JSON document after a well-formed first object | `TestRunMetaJSONRejectsTrailingDocument` (rc=1) | killed |
| M23b: trailing garbage refused but a well-formed second document admitted | F6 | admits exactly the second-object shape ({"a":1} {"b":2}); garbage after the first object still fails | `TestRunMetaJSONRejectsTrailingDocument/second_object` (rc=1) | killed |
| M24: title bound restored to bytes (len instead of RuneCountInString) | F7 | refuses the valid 80-character non-ASCII title (positive boundary control fails) | `TestRunTitleCharacterBound` (rc=1)<br>`TestValidateNew` (rc=1) | killed |
| M24b: title bound off by one (81 characters admitted) | F7 | admits exactly the 81-character title | `TestRunTitleCharacterBound` (rc=1)<br>`TestValidateNew/title_81_armenian` (rc=1) | killed |
| M25: issuer with a complete {dn, fingerprint} admitted on a key (only partial issuers refused) | F8 | admits one non-null issuer shape (complete) on a non-certificate kind | `TestManagerRotateRefusesUnknownMetadata/forged_issuer` (rc=1)<br>`TestRunRotateRefusesUnknownMetadata/forged_issuer` (rc=1)<br>`TestValidateNew/issuer_on_key` (rc=1) | killed |
| M25b: rotate skips ValidateNew on the reproduced record (init still validates) | F8 | admits reproduction of a stored record that init would refuse | `TestManagerRotateRefusesUnknownMetadata/forged_issuer` (rc=1)<br>`TestRunRotateRefusesUnknownMetadata/forged_issuer` (rc=1) | killed |

Survivors: 0 of 40. Every mutant has at least one named failing test (rc=1); files restored byte-exact after each (`git status` unchanged, no `.mutant-backup` left; keychain dump after the harness: 0 `mac-keyvault` items). Run in three bounded batches (M1-M15, M16-M25b, M26-M28c), all rc=0.

## Stated bounds

- Token-wise detection cannot know that a `--json`-shaped token is the *value* of a string flag (`pub S/P --out --json`, `init --title --`): the command parser owns that token, the detector counts it. This is the one place the two can disagree and is documented in README; every spelling and placement of a real `--json` flag is covered.
- `--` after a string-flag value that is itself `--` has the same shape and the same bound.
- The rev3 bounds still hold (cross-process atomicity via in-process flock holders — independently confirmed by the rev3 reviewer with two built processes; ACL readback attests the installed ACL, not its producer; `SecItemUpdate` mutant not replayed; extraction human/agent is recorded policy only; `./scripts/setup.sh` not run).
- The reviewer's `TestReviewerProbeListRejectsInvalidKindBeforeBackend` / `TestReviewerProbeMetaJSONNumberRoundTrips` were not available as files; the equivalent assertions are the two named regressions above, driven through `run(...)` against the recording `memStore`.

## Commands (all run standalone in the worktree, real exit codes)

| Command | Exit |
| --- | ---: |
| `gofmt -l cmd internal` (empty output) | 0 |
| `go vet ./...` | 0 |
| `go build ./...` | 0 |
| `git diff --check` | 0 |
| `go test -count=1 ./...` (27 packages ok, log `TASK-260915-2mf19o_go-test-rev4.log`, exact candidate Go sources; only LOGBOOK.md changed afterwards) | 0 |
| `python3 mutants-rev4.py M1…M15` / `M16…M25b` / `M26…M28c` (40 mutants, 0 survivors) | 0 / 0 / 0 |
| built binary `version --json=TRUE extra`, `--json=1`, `-json=t`, `-json=True`, `--json=T` (usage envelope 186 bytes on stdout, 0 stderr bytes; log `TASK-260915-2mf19o_binary-smoke-rev4.log`) | 2 |
| built binary `--json list --kind bogus` (`invalid_kind` envelope, 0 stderr bytes) / text mode (`error: invalid_kind: …` on stderr, 0 stdout bytes) | 3 / 3 |
| `security dump-keychain \| grep -c mac-keyvault` after everything | 0 items |

Not run: `./scripts/setup.sh` end-to-end install (unchanged since rev1). Candidate left uncommitted in the Story worktree.
