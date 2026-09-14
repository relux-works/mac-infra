# TASK-260915-2ny9kd review verdict — CR revision 9

Verdict: **accepted**.

## Candidate identity

- Base: `39131c7b28152fda50ed6224ef7afe566d8829f2`
- Candidate: `99e7ec22603b41bf27b219bb571beedb2a9b1c28`
- Independently materialising tracked, deleted, and untracked non-ignored work through an alternate index produced the exact candidate tree `99e7ec22603b41bf27b219bb571beedb2a9b1c28`.
- The downloaded CR patch SHA-256 is `adcd3eeb669355b1ddb334733f83e5f493578764a5c76bd854a3b83403499275`, matching the revision record.

## Review of rev8 F1 rework

The repeated duplicate-member bypass is closed structurally, not per probed object. `signerclient.CheckDocument` is one recursive `json.Decoder.Token` pass over the complete inbound document. Both typed-decode entry points call it before lossy decoding: `DecodeObject` carries client hello/responses and `SignerServer.handle` requests; `DecodeSingleJSON` carries describe records, persisted record tags, `--meta-json`, and `--json-value`.

The attack covered identical and escape-equivalent duplicate decoded names at depths 0–3, objects inside arrays and arrays of arrays, a later array element, non-adjacent repeats, sibling-object positive controls, and a second document. Production-entry regressions require client protocol failure plus process reap/unusable state, server `bad_request` plus stream continuation and zero backend calls, persisted-tag read failure, and CLI input refusal.

The producer's exact-candidate mutant evidence is substantive: 8 of 8 narrowing mutants were killed. In particular, the suite kills depth-0-only, arrays-skipped, first-array-element-only, adjacent-only, nested-escape-admitted, each entry-point-detachment, and second-document-admitted variants. These are narrowing shapes, not delete-only evidence. I found no surviving bypass in the reviewed scope.

## Acceptance-criteria coverage

Coverage is **12 of 12 executable behavior rows driven**, plus **3 of 3 process/artifact rows evidenced** (**15 of 15 total**):

- `TestRunSignerServeRoundTrip`, `TestSignerServeGoldenWire`, `TestSignerServeEOFAndBlankLines`, and the refusal/continuation cases drive hello plus describe/pub/sign/verify, malformed input, unknown op, missing id, invalid digest, `usage_refused`, `expired`, byte-exact fixtures, and clean EOF through `run(signer serve)` / `SignerServer.Serve`.
- `TestClientAgainstBuiltBinaryAndLoginKeychain` drives the built binary through `signerclient`, rotates after hello to test session binding, and verifies the returned signature with Go `crypto/ecdsa`.
- `TestSignerGoldenCoversStreamErrorCodes` and `TestSignerStreamCodesEmittedByProduction` cover 21 of 21 declared stream error codes against the golden corpus and production command entry.
- README Tools/Key Vault documentation, `agents/skills/mac-infra/SKILL.md`, `LOGBOOK.md`, the `scripts/setup.sh` mac-keyvault build line, and CR revision 9 are present. The stated no-live-kvctl bound is correct because kvctl does not yet exist as code; the vendorable Go client is the delivered integration boundary.

## Reviewer validation

- `gofmt -l cmd internal`: no output
- `git diff --check`: exit 0
- `go vet ./...`: exit 0
- `go build ./...`: exit 0
- Targeted adversarial signerclient suite (`-count=1`): exit 0
- `go test -count=1 ./...`: exit 0
- `TestGuardedStoreRefusesNonTestLabels`, `TestRunForeignLabelRefusedAtEntry`, `TestRunSignerServeAgainstLoginKeychain`, and `TestClientAgainstBuiltBinaryAndLoginKeychain`: exit 0
- Post-suite `mac-keyvault --json list --service test`: zero test-label records

The prefix guard refuses production, lookalike, foreign, raw-label, and empty inputs before store mutation; the live tests use only derived `works.relux.mac-keyvault.key.test.*` labels and clean them up. No existing Keychain item was touched by reviewer execution.

No review findings remain. `repeat-of` is not applicable to an accepted verdict; the prior class was revision 8 F1 / revision 6 F1 and is satisfied by the named recursive regressions and narrowing mutants above.
