# TASK-260915-2mf19o review verdict — CR revision 7

Verdict: **accepted**

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `e322b08ef1beddb79717a4d7a94b817a606e6633`, repository delta `present`. All 20 declared changed paths matched the frozen candidate byte-for-byte (`20/20`). The rev6-to-rev7 delta is limited to six intended files: strict persisted-record decoding, production and decoder regressions, README/SKILL guidance, and the LOGBOOK entry. No candidate file was modified during review.

## Review result

F14 is closed. `DecodeRecord` reaches the shared `DecodeSingleJSON` production boundary, which now uses `DisallowUnknownFields` together with `UseNumber` and the existing exactly-one-document EOF gate. Unknown top-level and nested struct members therefore become `RecordProblem` before `ValidateStored`; open `meta` maps remain accepted.

`TestRunUnknownRecordFieldIsUnreadableEverywhere` drives `run()` for four unknown-member shapes through `rotate`, `meta set`, `meta unset`, and `describe`. The write paths return exit 3 `metadata_unknown`, make zero create/update calls, and preserve the original tag byte-for-byte; the read path emits `record_unreadable`. Two valid open-meta controls still describe, rotate, and update successfully. `TestRecordEncodingAndLegacyTags` independently covers the decoder boundary.

Reviewer attack: in an isolated archive of the exact candidate tree, only `decoder.DisallowUnknownFields()` was removed. The EOF gate and `ValidateStored` remained present. `TestRunUnknownRecordFieldIsUnreadableEverywhere` failed on all 4 forbidden shapes because `run(rotate)` returned success and created a key; `TestRecordEncodingAndLegacyTags` failed because the unknown member was erased. This is a valid narrowing mutant (M31), not a delete-only gate test. The unmodified candidate's targeted packages passed first.

## Evidence

- AC coverage: **12 of 12 test-driven rows driven**. Rows 1–5 and 7–12 retain the named production-entry tests and mutants documented in rev6; row 6 is re-closed by the F14 run/Manager/decoder regressions above. The CR publication row is satisfied by revision 7.
- Reviewer-run `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault`: pass.
- Reviewer-run F5 tests `TestSecurityStorePrivateKeyIsNotExtractable`, `TestSecurityStoreACLTrustsOnlyCallingBinary`, and `TestSecurityStoreKeychainRoundTrip`: pass.
- Reviewer-run `go vet ./...`, `go build ./...`, `gofmt -l cmd internal`, and exact-candidate `git diff --check`: pass.
- Attached CR validation log for the exact candidate records `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` with exit 0; the full test run reports 27 packages green.
- Consolidated model-v2 resource was re-read. README, skill guidance, and LOGBOOK describe the strict schema boundary and the intentionally open `meta` map consistently.

No blocking, high, medium, or low findings remain. Stated bounds are unchanged: the cross-process duplicate proof uses in-process racers with separate flock descriptors; F5 attests the installed ACL; T7 owns extraction ACL mechanics; setup/install was not required for this one-line decoder rework.
