# TASK-260915-2ny9kd — rev9 results (rework of review rev8 F1, repeat-of rev6 F1)

Candidate: story worktree `.temp/STORY-260915-3r0ys5/worktree`, branch `task-board/story/STORY-260915-3r0ys5`, tip unchanged at checkpoint `39131c7` (work left uncommitted for the handoff snapshot).

## Finding and fix

rev8 F1: nested identical and escape-equivalent duplicate member names inside `describe` record objects (`format.public`, `origin.user`, `validity.not_before`, `meta.owner`, `operations[0].name`) bypassed `DecodeSingleJSON`/`DecodeObject` because `encoding/json` collapsed them (last value wins) before any invariant ran. Root cause: the duplicate gate was per object (whoever remembered to route an object through `DecodeObject`), so every nested object was a bypass.

Fix (orchestrator note followed exactly): **one** recursive strict-JSON pass, `signerclient.CheckDocument` (`internal/keyvault/signerclient/object.go`) — `json.Decoder.Token` walk over the whole document, every depth, objects in objects and in arrays, refusing a repeated decoded member name in any one object (`ErrDuplicateMember`, message names member + path: `duplicate member "public" at format`, `... at operations[0]`) and anything but exactly one document (`ErrMultipleDocuments`). It runs before any typed decode from both document entry points:

| Entry point | Production call site | Inbound documents |
|---|---|---|
| `DecodeObject` | `signerclient.decodeEnvelope` (client hello + every response, via `Start`/`Call`/`readResponse`); `keyvault.SignerServer.handle` (server request line) | client hello/response lines, server request lines |
| `DecodeSingleJSON` | `keyvault.DecodeRecord` (persisted record tag); `cmd/mac-keyvault` `--meta-json` and `meta set --json-value`; `signerclient.checkDescribe` (typed record) | record tag, CLI JSON inputs, describe result |

`DecodeObject` lost its own per-object `seen` map: one owner. Typed decoders unchanged. Every pre-existing golden fixture is byte-identical to the rev8 candidate tree `917589aa` (verified by blob hash; a truncated line still reads `member "op": unexpected EOF`, a top-level repeat still `duplicate member "id"`).

## Regression tests (production entry, named)

| Test | Package | Drives | Rows |
|---|---|---|---|
| `TestClientRefusesDuplicateMembers` | signerclient | `Start` → `Describe`/`PublicKey`/`Sign`/`Verify` → `Call` → `decodeEnvelope` → `DecodeObject` → `CheckDocument` against the fake signer binary | 29 rows / 38 of 38 hello+call entries driven; **9 new nested rows**: `format.public` (verbatim, escaped), `origin.user` (escaped), `validity.not_before`, `meta.owner` (verbatim, escaped), `operations[0].name` (verbatim, escaped), `operations[2].via` (last array element); each asserts `ErrProtocol`, no `*Error`, next call `ErrProtocol`, `Close` reports the kill. 2 new controls admitted: honest `describe` (sibling operation entries share names), nested escape-spelt single member |
| `TestCheckDocument` | signerclient | `CheckDocument`, `DecodeSingleJSON` | 20 refused (depth 0/1/2/3, arrays, arrays of arrays, `[3].o[0]`, escape-spelt, top-level-after-nested, two documents, empty), 9 malformed, 18 admitted controls (siblings, depths, escaped single, whitespace, scalars/arrays as documents), 3 nested `DecodeSingleJSON` rows + control |
| `TestDecodeObject` | signerclient | `DecodeObject` | +2 nested rows |
| `TestSignerServeRefusesDuplicateMembers` | keyvault | `SignerServer.Serve` | +6 nested rows (`id` object verbatim/escaped, depth 2, array first/later element escaped, array of arrays) → `bad_request` under `id:null` naming the member, zero backend calls; +2 nested controls (`missing_id` / `bad_request` NOT naming a duplicate) |
| `TestSignerServeGoldenWire` | keyvault | `SignerServer.Serve`, byte-exact | new goldens `signer-40-duplicate-member-nested`, `signer-41-duplicate-member-in-array`, `signer-42-sign-after-nested-duplicates` (control), `signer-43-two-documents-one-line` |
| `TestDecodeRecordRefusesNestedDuplicateMembers` | keyvault | `DecodeRecord` (persisted tag) | 7 forged tags (format/origin/validity/meta, escaped, top-level, nested-in-meta) → read failure naming the duplicate; 1 control readable |
| `TestRunMetaJSONRejectsTrailingDocument` | cmd/mac-keyvault | `run(init --meta-json …)`, `run(meta set --json-value …)` | +4 duplicate rows (top-level, escaped, nested, json-value) → `usage`, exit 2, no store call |

AC coverage unchanged from rev8 (12 of 15 rows driven; 3 process rows). This rework adds no AC row.

## Mutants (narrowing; harness `TASK-260915-2ny9kd_mutants-rev9.py`, log `_mutants-rev9.log`; sources restored and verified after each)

| Mutant | Narrows the gate to | Status | Named failing tests |
|---|---|---|---|
| M1 depth-0-only | nested object members consumed raw, never compared | KILLED | TestClientRefusesDuplicateMembers, TestCheckDocument, TestDecodeObject, TestSignerServeRefusesDuplicateMembers, TestSignerServeGoldenWire, TestDecodeRecordRefusesNestedDuplicateMembers, TestRunMetaJSONRejectsTrailingDocument (18 subtests) |
| M2 arrays-not-entered | objects inside arrays skipped | KILLED | TestClientRefusesDuplicateMembers, TestCheckDocument, TestDecodeObject, TestSignerServeRefusesDuplicateMembers, TestSignerServeGoldenWire (9) |
| M3 first-array-element-only | only `[0]` judged | KILLED | TestClientRefusesDuplicateMembers (operations-last-via), TestCheckDocument, TestSignerServeRefusesDuplicateMembers, TestSignerServeGoldenWire (6) |
| M4 adjacent-repeats-only | non-adjacent repeat admitted | KILLED | TestClientRefusesDuplicateMembers, TestCheckDocument, TestDecodeObject, TestDecodeRecordRefusesNestedDuplicateMembers (16) |
| M5 nested-escaped-repeat-admitted | nested repeat refused only when spelt verbatim twice | KILLED | TestClientRefusesDuplicateMembers, TestCheckDocument, TestDecodeObject, TestSignerServeRefusesDuplicateMembers, TestSignerServeGoldenWire, TestDecodeRecordRefusesNestedDuplicateMembers (10) |
| M6 detached-from-DecodeSingleJSON | record tag / CLI JSON input skip the pass | KILLED | TestDecodeRecordRefusesNestedDuplicateMembers, TestRunMetaJSONRejectsTrailingDocument, TestCheckDocument (7) |
| M7 detached-from-DecodeObject (top-level per-object check retained) | wire lines: only top level judged | KILLED | TestSignerServeRefusesDuplicateMembers, TestSignerServeGoldenWire, TestDecodeObject (4) |
| M8 second-document-admitted | trailing document after the first admitted by the pass | KILLED | TestSignerServeGoldenWire (signer-43), TestCheckDocument, TestDecodeObject (4) |

No survivors. Note on M7: the client fake corpus does not fail it because the `describe` result — the only client-side result with nested objects — is read by both entry points (`DecodeObject` on the line, `DecodeSingleJSON` on the typed record); the server suite and `TestDecodeObject` kill it. Stated as a bound, not a gap.

## Gates (each a standalone process, real exit codes)

| Gate | Exit | Evidence |
|---|---|---|
| `gofmt -l cmd internal` | 0 files | inline |
| `go vet ./...` | 0 | inline |
| `go build ./...` | 0 | inline |
| `git diff --check` | 0 | inline |
| `go test -count=1 ./internal/keyvault/...` (live login keychain, test labels) | 0 | `_go-test-keyvault-rev9.log` |
| `go test -count=1 ./cmd/...` | 0 (9 ok) | `_go-test-cmd-rev9.log` |
| `go test -count=1 <remaining 17 pkgs>` | 0 | `_go-test-rest-rev9.log` (34 packages total across the three bounded calls) |
| `go test -count=1 -race ./internal/keyvault/...` | 0 | `_go-test-race-rev9.log` |
| mutant harness (8 mutants, 3 package masks each) | 0, 8/8 killed | `_mutants-rev9.log` |
| `mac-keyvault list --json` after the suite | `[]` — no throwaway item left, no foreign item touched | inline |

## Docs
README Key Vault section (CheckDocument, entry points, test names, goldens 36..43), SKILL.md kvctl paragraph (nested objects, tag and input guard), `signerclient/wire.go` contract doc, LOGBOOK 2026-09-15 2330 (finding, root cause, fix, rule, bounds).

## Bounds
- No live kvctl interop (kvctl is not code yet); the vendored Go client is the contract boundary.
- `json.Decoder.Token` decodes names, so the "escape-spelt repeat admitted" mutant is modelled by re-comparing raw spellings.
- Reviewer's rev8 probe binary was not re-run verbatim; its five shapes are the nine nested `describe` rows driven through the same production path.
