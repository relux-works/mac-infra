# TASK-260915-2mf19o review verdict — CR revision 6

Verdict: **changes requested** → `to-dev`

repeat-of: none

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `58ad1919e0064aee6f38bf99e4a00894fe0869eb`, repository delta `present`. All 20 changed worktree paths matched the frozen candidate byte-for-byte. Review performed 2026-09-15. Product code and candidate files were not modified; reviewer probes live under ignored `.temp/review-rev6/`.

## Finding

### F14 — High — persisted schema-2 unknown fields are erased before the invariant gate, then rotate/meta mutate the record

The consolidated model v2 defines the schema-2 field set and says a field that starts driving behaviour moves into the model with a schema bump (§2–§3). `DecodeSingleJSON` at `internal/keyvault/record.go:306` decodes a `Record` without `json.Decoder.DisallowUnknownFields`; `DecodeRecord` calls it at line 341. Therefore an unrecognized top-level field or an unrecognized nested `format` field is silently discarded before `ValidateStored` sees the record. The new “one row per field” invariant table cannot validate bytes the decoder already erased.

The reviewer drove both production layers:

- `Manager.Rotate` accepted a schema-2 tag carrying `future_top_level_policy:"deny"` and `format.future_format_policy:"deny"`, called `Backend.Create` once, and emitted v2 with both fields absent.
- `Manager.MetaSet` accepted the same v1 record, called `Backend.UpdateTag` once, and rewrote the old tag with both fields absent.
- A reviewer-only test against the frozen candidate drove `run(--json rotate ...)`. Both top-level and nested cases returned exit 0 with `findings: []` and one create; the test expected `metadata_unknown`, zero creates, and failed for the intended reason.

This is a **bypass path around the check** and **check input erased before production**. It also contradicts `README.md:308` and the rev6 result claim that every persisted record field is checked before rotate/meta. A future policy-bearing field can be silently downgraded under schema 2 rather than reported unknown, preserving the exact failure class F4/F8/F12/F13 were meant to close.

Required rework:

1. Decode persisted schema-2 `Record` values with a strict unknown-field boundary while preserving the current exactly-one-document and `json.Number` guarantees. Unknown top-level and nested struct fields must produce `RecordProblem`; do not make arbitrary `meta` keys closed.
2. Add production `run(...)` regressions for at least one unknown top-level field and one unknown nested field. `describe` must expose an unreadable-record finding; `rotate` and `meta set|unset` must return `metadata_unknown`, make zero create/update calls, and leave the original tag byte-identical. Keep a valid schema-2 positive control.
3. Add a narrowing mutant that leaves the EOF/document gate and `ValidateStored` present but removes only strict unknown-field rejection from the persisted-record decoder. The named CLI regressions must kill it.
4. Update the measured AC ratio and documentation. Record F14 and the decoder-before-gate root cause in `LOGBOOK.md` during producer rework.

## Evidence assessment

- Producer-reported coverage is `12 of 12`; F14 falsifies row 6 (schema-2 record round-trip/write-path enforcement), so reviewer-verified coverage is at most `11 of 12`.
- Independent `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault` passed (`.temp/review-rev6/targeted-tests.log`). The attached full `go test -count=1 ./...`, vet and build logs are complete and green for the frozen candidate.
- The rev6 F13 rework itself is sound for fields that survive decoding: `validity.not_before` on a key is refused through Manager and CLI paths, write effects stay zero, positive controls remain, and M30 is a valid narrowing mutant.
- The 50-mutant table has no persisted unknown-field mutant. Its field-completeness test reflects over the decoded Go struct, so it cannot observe JSON members that `encoding/json` drops before the table; this is the blind spot demonstrated by the reviewer control.
- Reviewer probe: `.temp/review-rev6/probe_unknown_fields.go` / `probe_unknown_fields.log`.
- CLI red control: `.temp/review-rev6/frozen/cmd/mac-keyvault/reviewer_unknown_field_test.go` / `.temp/review-rev6/reviewer-unknown-field-cli-test.log` (exit 1 because both forbidden mutations returned success).

The reviewer did not append to tracked `LOGBOOK.md`, because doing so would mutate the frozen candidate under review; the required producer rework owns that entry.
