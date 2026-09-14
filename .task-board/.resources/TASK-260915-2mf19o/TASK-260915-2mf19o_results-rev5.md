# TASK-260915-2mf19o — rev5 results (CR rev4 F12 rework, repeat-of F6)

Candidate: uncommitted working tree of `.temp/STORY-260915-3r0ys5/worktree` on base `f9ec756`.

## What changed

F12: `DecodeRecord` read the persisted `kSecAttrApplicationTag` with a bare `json.Decoder.Decode`, so a schema-2 record followed by a second JSON document was reported readable and `Manager.Rotate` reproduced it. Per the orchestrator note, the EOF-required decoder behind `--meta-json` moved from `cmd/mac-keyvault/main.go` (`decodeSingleJSON`) to `internal/keyvault/record.go` as `keyvault.DecodeSingleJSON`; it is now the single document-boundary implementation for all three JSON boundaries:

| Boundary | Production call site |
| --- | --- |
| `--meta-json` file | `cmd/mac-keyvault/main.go` `loadMetaJSON` → `keyvault.DecodeSingleJSON` |
| `meta set --json-value` | `cmd/mac-keyvault/main.go` `runMeta` → `keyvault.DecodeSingleJSON` |
| persisted record tag | `internal/keyvault/record.go` `DecodeRecord` → `DecodeSingleJSON` |

Effect: `{record} {record}`, `{record} 1`, `{record}}`, `{record}]`, `{record} null` now yield a non-empty `RecordProblem` (schema 0, store unknown). `Manager.Rotate` refuses with `metadata_unknown`, zero `Backend.Create` calls, old tag byte-identical. Whitespace-padded single record remains readable (positive control). Nothing else changed in product code. README sentence added; LOGBOOK entry `1720`.

## Regressions (named, committed in the candidate)

| Test | Entry point | Claim |
| --- | --- | --- |
| `internal/keyvault` `TestRecordEncodingAndLegacyTags` | `DecodeRecord` | 5 trailing shapes → non-empty problem, schema 0; whitespace-padded record → readable schema 2 |
| `internal/keyvault` `TestManagerRotateRefusesUnknownMetadata/trailing_document`, `/trailing_token`, `/trailing_garbage` | `Manager.Rotate`, `Manager.Describe` | `metadata_unknown`, `creates=0`, one item, tag unchanged, describe reports problem with schema 0; positive control (valid schema-2) rotates once |
| `cmd/mac-keyvault` `TestRunRotateRefusesUnknownMetadata/trailing_document`, `/trailing_token`, `/trailing_garbage` | `run(...)` → `runRotate` → `Manager.Rotate` | exit 3, `error.code=metadata_unknown`, message names "unreadable record", `creates=0`, tag unchanged; positive control rotates |

## Narrowing mutants — 42 replayed, 0 survivors (`TASK-260915-2mf19o_mutants-rev5.log`)

rev4 M1–M28c replayed (M23/M23b/M28b relocated to the shared decoder / new call site) plus:

| Mutant | Narrows the gate to | Named failing test(s) | Result |
| --- | --- | --- | --- |
| M23 (F6, now shared decoder) EOF check dropped | admits any trailing data at both boundaries | `TestRunMetaJSONRejectsTrailingDocument`, `TestRunRotateRefusesUnknownMetadata/trailing_token` | killed |
| M23b (F6, shared decoder) garbage refused, well-formed second document admitted | one shape, both boundaries | `TestRunMetaJSONRejectsTrailingDocument/second_object`, `TestRunRotateRefusesUnknownMetadata/trailing_document`, `TestManagerRotateRefusesUnknownMetadata/trailing_document` | killed |
| **M29 (F12)** `DecodeRecord` alone admits exactly `{record} {record}`; token/garbage still refused; input decoder untouched | the reviewer-specified shape, record boundary only | `TestManagerRotateRefusesUnknownMetadata/trailing_document`, `TestRunRotateRefusesUnknownMetadata/trailing_document`, `TestRecordEncodingAndLegacyTags` | killed |
| **M29b (F12)** `DecodeRecord` bypasses the shared decoder (rev4 bare decoder) | record boundary loses EOF rule, inputs keep it | `TestManagerRotateRefusesUnknownMetadata/trailing_garbage`, `TestRunRotateRefusesUnknownMetadata/trailing_token`, `TestRecordEncodingAndLegacyTags` | killed |

M29 narrowness proof (`m29-narrowness.log`, mutant applied by hand): `TestRunMetaJSONRejectsTrailingDocument` rc=0, `…/trailing_garbage` rc=0 (both packages), `…/trailing_token` rc=0 — only `…/trailing_document` rc=1. The mutant admits exactly one member of the class.

Full table: see the mutant log.

## Gates (each run standalone, real exit codes)

| Command | rc |
| --- | ---: |
| `gofmt -l cmd internal` (no output) | 0 |
| `go vet ./...` | 0 |
| `go build ./...` | 0 |
| `git diff --check` | 0 |
| `go test -count=1 ./...` (27 packages ok, `TASK-260915-2mf19o_go-test-rev5.log`) | 0 |
| `python3 mutants-rev5.py` (42 mutants, survivors=0) | 0 |
| built binary `mac-keyvault list --json` after the suite → `[]` (keychain clean) | 0 |

## AC coverage

12 of 12 test-driven AC rows driven (rev4 table unchanged for F1–F3, F5, model rows; F4/read-integrity row now includes the trailing-document shapes above). Row "new Change Request revision published" is produced by the handoff.

## Stated bounds (carried from rev4, unchanged)

- Test namespace = service `test` (kind-first label).
- Cross-process duplicate atomicity proven via separate flock descriptors in-process (reviewer independently passed the cross-process race in rev3).
- ACL test attests the installed ACL, not its producer; `SecItemUpdate` orphaning mutant not replayed against real items.
- `--extraction human|agent` is recorded policy only; T7 wires the ACL.
- `scripts/setup.sh` end-to-end install not run.
- `--json` consumed as a string-flag value belongs to the command parser.

## Not run

- `scripts/setup.sh` end-to-end install (unchanged in this revision).
