# TASK-260915-2mf19o — rev3 (rework of CR rev2 F6-F8, repeat-of F3)

Candidate: uncommitted working tree of `task-board/story/STORY-260915-3r0ys5` on base `f9ec756`.
Delta vs rev2 candidate `68764d6…`: `cmd/mac-keyvault/{main.go,main_test.go}`, `internal/keyvault/{record.go,keyvault_test.go}`, `README.md`, `LOGBOOK.md`. Everything else in the rev2 scope (cgo bridge, lock, registry, SKILL, setup/deinit) is unchanged.

## Review findings F6-F8

| Finding | Fix | Production call site | Named test(s) | Narrowing mutants |
| --- | --- | --- | --- | --- |
| F6 (repeat-of F3) `version` ignores extra args/flags | `run` dispatches `version` to `runVersion`, which goes through the same `parseFlags` as every command and `requireNoArguments`; `help` also refuses leftovers. Unknown flag, stray positional and a flag with value all yield `{ok:false, error:{code:"usage", message, hint:"mac-keyvault [--json] version"}}`, exit 2, empty stderr, zero store calls (List included). | `run` → `runVersion` → `parseFlags`/`requireNoArguments` → `output.fail` | `TestRunVersionRejectsExtraInput` (5 shapes × json-first/json-last/text + positive controls `version`/`help` exit 0) | M22 (version bypasses the parser, emitter kept), M22b (parser kept, positional dropped) — killed |
| F6 (repeat-of F3) `--meta-json` accepts a trailing document, then creates | `decodeSingleJSON` decodes one value with `UseNumber` and then requires `decoder.Token() == io.EOF`; a second object, trailing token, trailing `}`/`]`, garbage, array top-level and an empty file are `usage`, exit 2, zero store calls — the first object is never persisted. Same helper behind `meta set --json-value` (`1 2`, `true x` refused). | `runInit` → `collectMeta` → `decodeSingleJSON`; `runMeta set` → `decodeSingleJSON` | `TestRunMetaJSONRejectsTrailingDocument` (8 shapes × 3 placements; positive controls: single object with whitespace/newline persisted with string+number, single `3.5` json-value persisted) | M23 (EOF check dropped), M23b (garbage still refused, well-formed second document admitted) — killed |
| F7 title bound is 80 bytes | `utf8.RuneCountInString(rec.Title) > MaxTitleLength`; message reports the code-point count. | `Manager.Init` → `ValidateNew` | `TestRunTitleCharacterBound` (80 × U+0561 = 160 bytes admitted and persisted verbatim through `run init`; 81 Armenian and 81 ASCII refused `invalid_title` "81 characters", store untouched), `TestValidateNew` (80 Armenian / 80 ASCII pass; `title_too_long`, `title_81_armenian` refused) | M24 (byte count restored — the 80-char positive control fails), M24b (off-by-one admits 81) — killed |
| F8 rotate reproduces a non-null issuer on a key | `validateIssuer(kind, issuer)` inside `ValidateNew`: certificate must carry complete `{dn, fingerprint}`, every other kind must carry null (`invalid_issuer`). Rotate runs `ValidateNew(next)` on the reproduced record, so a stored schema-2 key with a forged issuer is `metadata_unknown` with zero creates. | `Manager.Init`/`Manager.Rotate` → `ValidateNew` → `validateIssuer` | `TestManagerRotateRefusesUnknownMetadata/forged_issuer` (+ positive control asserts the rotated record carries issuer null), `TestRunRotateRefusesUnknownMetadata/forged_issuer` (message names `invalid_issuer`, `creates==0`, + positive control v2 issuer null), `TestValidateNew/issuer_on_key`, `/issuer_dn_only_on_key`, `/issuer_empty_on_key`, `TestValidateIssuerPerKind` (10 rows, both directions) | M25 (complete issuer admitted on a key, partial still refused), M25b (rotate skips validation only when the issuer is set) — killed |

Repeat-of class handling (standing order 8): the F3 class now has named regressions at the two bypass points the reviewer found, plus narrowing mutants that preserve the common JSON emitter (M22/M22b) and preserve JSON decoding (M23/M23b).

## Test-harness fix (not a product change)

`TestManagerInitDuplicateRefusalIsAtomic`'s no-lock positive control failed once during the full `go test -count=1 ./...` run (creates=1: the first goroutine listed, returned and created before the second goroutine had listed — a scheduler-dependent window under package-parallel load). The fake store's `List` now holds every snapshot on a second barrier (`listDone`) until the peer has taken its own, so both callers really see the empty listing. Evidence: `go test -count=20 -cpu 1,2,8 -run TestManagerInitDuplicateRefusalIsAtomic` rc=0 (60 runs), M2 replayed 3× and killed each time (`locked race created 2 keys, want 1`).

## AC coverage — 12 of 12 test-driven rows driven through `run(...)` / `Manager` / `SecurityStore`; the CR revision row is produced by the handoff

Rows 1-11 are unchanged from rev2 (`TASK-260915-2mf19o_results-rev2.md`) and their evidence is reused: the source files backing F1, F2, F4, F5, the model rows and the registry are byte-identical to the rev2 candidate except `record.go` (title/issuer) and `main.go` (version/JSON input), and the whole rev2 mutant set (M1-M21) was replayed against this candidate — 0 survivors. Row 3 (F3 every usage error) is the one the reviewer measured unsatisfied and is now driven by `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore` (29 shapes) + `TestRunVersionRejectsExtraInput` (5) + `TestRunMetaJSONRejectsTrailingDocument` (8), all through `run(...)` with `store.touched()==false`.

| # | AC row | Production call site | Named test |
| --- | --- | --- | --- |
| 3 | F3 every usage error in --json → envelope, empty stderr, exit 2, no backend call | `run`→`parseFlags`/`requireNoArguments`/`decodeSingleJSON`→`output.fail` | `TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore`, `TestRunVersionRejectsExtraInput`, `TestRunMetaJSONRejectsTrailingDocument`; M3/M3b/M17/M22/M22b/M23/M23b |
| F7 | title ≤ 80 chars (code points) | `Manager.Init`→`ValidateNew` | `TestRunTitleCharacterBound`, `TestValidateNew`; M24/M24b |
| F8 | issuer null for a key on init and rotate | `Manager.Init`/`Rotate`→`ValidateNew`→`validateIssuer` | `TestRunRotateRefusesUnknownMetadata/forged_issuer`, `TestManagerRotateRefusesUnknownMetadata/forged_issuer`, `TestValidateIssuerPerKind`; M25/M25b |
| 12 | go vet/build/test -count=1 ./... green | — | commands below |

## Mutant table (harness `TASK-260915-2mf19o_mutants-rev3.py`, log `TASK-260915-2mf19o_mutants-rev3.log`; M1-M21 are the rev2 set replayed on this candidate)

## Markdown table

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
| M22: version accepts and ignores extra positionals/flags (JSON emitter kept) | F6 | admits one command (version) around the usage gate while every other command keeps it | `TestRunVersionRejectsExtraInput` (rc=1) | killed |
| M22b: version parses flags but drops leftover positionals | F6 | admits the positional shape (version extra) while an unknown flag is still refused | `TestRunVersionRejectsExtraInput/version_positional` (rc=1) | killed |
| M23: JSON decoding kept, trailing document admitted (EOF check dropped) | F6 | admits a second/trailing JSON document after a well-formed first object | `TestRunMetaJSONRejectsTrailingDocument` (rc=1) | killed |
| M23b: trailing garbage refused but a well-formed second document admitted | F6 | admits exactly the second-object shape ({"a":1} {"b":2}); garbage after the first object still fails | `TestRunMetaJSONRejectsTrailingDocument/second_object` (rc=1) | killed |
| M24: title bound restored to bytes (len instead of RuneCountInString) | F7 | refuses the valid 80-character non-ASCII title (positive boundary control fails) | `TestRunTitleCharacterBound` (rc=1)<br>`TestValidateNew` (rc=1) | killed |
| M24b: title bound off by one (81 characters admitted) | F7 | admits exactly the 81-character title | `TestRunTitleCharacterBound` (rc=1)<br>`TestValidateNew/title_81_armenian` (rc=1) | killed |
| M25: issuer with a complete {dn, fingerprint} admitted on a key (only partial issuers refused) | F8 | admits one non-null issuer shape (complete) on a non-certificate kind | `TestManagerRotateRefusesUnknownMetadata/forged_issuer` (rc=1)<br>`TestRunRotateRefusesUnknownMetadata/forged_issuer` (rc=1)<br>`TestValidateNew/issuer_on_key` (rc=1) | killed |
| M25b: rotate skips ValidateNew on the reproduced record (init still validates) | F8 | admits reproduction of a stored record that init would refuse | `TestManagerRotateRefusesUnknownMetadata/forged_issuer` (rc=1)<br>`TestRunRotateRefusesUnknownMetadata/forged_issuer` (rc=1) | killed |

survivors=0

Survivors: 0 of 32. Files restored byte-exact after every mutant (`git status` unchanged, no `.mutant-backup` left; keychain dump after the harness: 0 `mac-keyvault` items). M24 was first written as a plain `len()` swap, which failed to compile (unused `unicode/utf8` import) — a build failure is not a behavioral kill, so it was rewritten to keep the import used (`len(rec.Title) > 80 || !utf8.ValidString(...)`) and rerun: killed by the 80-character positive control in both packages.

## Stated bounds

- The certificate branch of `validateIssuer` is reachable only through `TestValidateIssuerPerKind` today: `ValidateNew` refuses every non-key kind as `unsupported_kind` before the issuer check (T4-T7 own certificate creation).
- Every rev2 bound still holds (cross-process atomicity via in-process flock holders; ACL readback attests the installed ACL, not its producer; `SecItemUpdate` mutant not replayed; extraction human/agent is recorded policy only; `./scripts/setup.sh` not run).
- `help` with extra input is refused as `usage` like `version`; the model does not name `help`, so this is a consistency choice, not an AC row.

## Commands (all run standalone in the worktree, exit codes real)

| Command | Exit |
| --- | ---: |
| `gofmt -l cmd internal` (empty) | 0 |
| `go vet ./...` | 0 |
| `go build ./...` | 0 |
| `git diff --check` | 0 |
| `go test -count=1 ./...` — first run: rc=1 (`TestManagerInitDuplicateRefusalIsAtomic` positive control, see harness fix) | 1 |
| `go test -count=1 ./...` — after the harness fix (27 packages ok, log `TASK-260915-2mf19o_go-test-rev3.log`, exact candidate) | 0 |
| `go test -count=20 -cpu 1,2,8 -run TestManagerInitDuplicateRefusalIsAtomic ./internal/keyvault` | 0 |
| `python3 mutants-rev3.py` (32 mutants, 0 survivors) | 0 |
| built binary `--json version extra` / `--json version --bogus` / `--json help x` (usage envelope, 0 stderr bytes) | 2 |
| built binary `--json init --service test --purpose smoke --meta-json two.json` (`{"owner":"a"} {"ignored":true}`; usage envelope, 0 stderr bytes, keychain dump 0 items) | 2 |
| built binary `--json init … --title <81 × U+0561>` (`invalid_title: title is 81 characters`) | 3 |
| `security dump-keychain \| grep -c mac-keyvault` after everything | 0 items |
