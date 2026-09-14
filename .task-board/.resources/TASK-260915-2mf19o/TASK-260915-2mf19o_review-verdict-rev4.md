# TASK-260915-2mf19o review verdict — CR revision 4

Verdict: **changes requested** → `to-dev`

repeat-of: CR revision 2 F6 (the same second-JSON-document validation class, now bypassing the input decoder through the persisted-record decoder)

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `101372df9ee7aa92df05a4a41c3616683e41ba75`, repository delta `present`. The alternate-index snapshot of the live uncommitted worktree reproduced that candidate tree exactly. Review performed 2026-09-15. Product code and candidate files were not modified; probes and logs are under ignored `.temp/review-rev4/`.

## Finding

### F12 — High — a schema-2 tag with a trailing JSON document is treated as readable and rotated

`internal/keyvault.DecodeRecord` performs one `json.Decoder.Decode` at `internal/keyvault/record.go:407-418` but never requires EOF. A valid schema-2 record followed by a second JSON document is therefore returned with `problem == ""` and `schema == 2`. The production `Manager.Rotate` path at `internal/keyvault/keyvault.go:423-460` treats it as known metadata and creates the next generation instead of returning `metadata_unknown` with zero creates.

Reviewer probe (`.temp/review-rev4/probe_trailing_tag.go`, output `.temp/review-rev4/trailing-tag-probe.log`) used a recording `Backend` and called the production `Manager.Rotate` entry:

```text
decode_problem="" decoded_schema=2 rotate_error=<nil> creates=1 new_label="works.relux.mac-keyvault.key.test.trailing-tag.v2"
```

This is the **bypass path around the check** and **failure-to-read presented as valid** shapes. The model-v2 negative contract says rotate must refuse an unreadable record and never guess/reproduce its policy. The existing M23/M23b mutants and `TestRunMetaJSONRejectsTrailingDocument` cover only caller-provided `--meta-json`; they do not exercise the separate `DecodeRecord` path used for `kSecAttrApplicationTag`. Grep confirms there is no trailing-document record test.

Required rework:

1. Make schema-2 record decoding require exactly one JSON document (trailing whitespace remains valid; a second document, token, or garbage produces a non-empty `RecordProblem`).
2. Add a production-path regression through `Manager.Rotate` and `run(...)`: malformed persisted tags must return `metadata_unknown`, create zero keys, and leave the old tag/item unchanged. Keep a valid schema-2 positive control that rotates.
3. Because this repeats the F6 document-boundary class, add a narrowing mutant that keeps record decoding present but admits exactly a well-formed second JSON document while still rejecting trailing garbage; the named rotate regression must kill it.

## Acceptance and evidence assessment

- Producer reports `12 of 12` test-driven AC rows. F12 falsifies the F4/read-integrity row, so reviewer-verified coverage is at most `11 of 12`.
- The exact rev4 candidate validation log is complete: `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` exit 0.
- Reviewer reran `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault`: pass.
- Reviewer reran the real Security.framework non-exportability, exact private-operation ACL, and explicit missing-entitlement attestations: pass; post-run keychain count for the tool prefix was zero.
- Built-binary attacks confirm F9 and F10 are repaired: `--json=TRUE`, `--json=1`, and `-json=t` usage errors return exit 2, parseable JSON on stdout, and empty stderr; `list --kind bogus` returns `invalid_kind`, exit 3, empty stderr.
- The rev4 mutant log is complete and reports 0 of 40 survivors, but contains no persisted-record document-boundary mutant; its M23/M23b scope is `decodeSingleJSON` for `--meta-json` only.
- F11 numeric-meta regressions pass in the targeted suite and its three narrowing mutants are present in the attached producer evidence.

## Reviewer artifacts

- `.temp/review-rev4/trailing-tag-probe.log`
- `.temp/review-rev4/targeted-tests-rerun.log`
- `.temp/review-rev4/security-attestations.log`
- `.temp/review-rev4/binary-adversarial.log`
- `.temp/review-rev4/keychain-count.log`

The reviewer cannot edit tracked `LOGBOOK.md` without invalidating the frozen CR. The rev5 producer should record F12 and its fix there.
