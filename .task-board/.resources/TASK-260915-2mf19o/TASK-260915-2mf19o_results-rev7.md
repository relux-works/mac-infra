# TASK-260915-2mf19o — results rev7 (CR rev6 F14 rework)

Scope per orchestrator directive: strict unknown-field decoding for the persisted schema-2 record, two `run()` regressions + describe finding + narrowing mutant, LOGBOOK entry. Nothing else changed in product code.

## Root cause and fix

`DecodeSingleJSON` (`internal/keyvault/record.go:316`) decoded the persisted `Record` without `DisallowUnknownFields`; `encoding/json` erased undefined members (top-level and nested struct) before `ValidateStored` ran, so `Rotate` reproduced and `MetaSet` rewrote the record minus the member. The invariant table reflects over the decoded struct and cannot see members that never reach it.

Fix: `decoder.DisallowUnknownFields()` added next to `UseNumber()` and the EOF gate. One line of product code. `Record.Meta` (`map[string]any`), `--meta-json` (`map[string]any`) and `--json-value` (`any`) are non-struct targets and stay open — proven by positive controls that put the same names into `meta`.

## Tests (production call sites)

| Test | Entry point | Proves |
| --- | --- | --- |
| `TestRunUnknownRecordFieldIsUnreadableEverywhere` (`cmd/mac-keyvault/main_test.go`) | `run(--json rotate ...)`, `run(--json meta set|unset ...)`, `run(--json describe ...)` | 4 shapes (unknown top-level; nested `format`, `origin`, `validity`): rotate exit 3 `metadata_unknown` naming "unreadable record"; meta set/unset exit 3 `metadata_unknown`; 0 `Backend.Create`, 0 `Backend.UpdateTag`, old tag byte-identical; describe exit 0 with `record_unreadable` finding. 2 positive controls: same names inside `meta` → describe `findings: []`, rotate creates once, meta set updates once. |
| `TestRecordEncodingAndLegacyTags` (`internal/keyvault/keyvault_test.go`) | `DecodeRecord` | 4 unknown-member paths → problem contains "unknown field", schema 0, store unknown; `meta` member stays readable. |

## Mutant

| Mutant | Narrows the gate to | Named failing test | Survivor? |
| --- | --- | --- | --- |
| M31: `decoder.DisallowUnknownFields()` removed; EOF/document gate and `ValidateStored` intact | admits records with undefined members (exactly the F14 class), still refuses trailing documents and forged known fields | `TestRunUnknownRecordFieldIsUnreadableEverywhere` (4/4 sub-tests fail), `TestRecordEncodingAndLegacyTags` | no |

Log: `.temp/TASK-260915-2mf19o/mutant-M31.log`. Source restored after replay (`grep -n DisallowUnknownFields record.go` = line 317, one call). The rev6 table M1–M30h is unchanged and not replayed (unchanged rows; identity of the changed line is covered by M31).

## Gates (standalone processes, real exit codes)

| Command | rc | Log |
| --- | ---: | --- |
| `gofmt -l cmd internal` | 0 (no output) | `.temp/TASK-260915-2mf19o/gofmt-rev7.log` |
| `go vet ./...` | 0 | `vet-rev7.log` |
| `go build ./...` | 0 | `build-rev7.log` |
| `git diff --check` | 0 | `diffcheck-rev7.log` |
| `go test -count=1 ./...` | 0 (27 ok) | `test-rev7.log` |
| `mac-keyvault --json list` after suite | `[]` | — |

## AC coverage

12 of 12 test-driven AC rows driven (row 6, schema-2 round-trip / write-path enforcement, re-closed by the test above; the other 11 unchanged from rev6). Row 13 (new CR revision) is produced by the handoff.

Stated bounds unchanged from rev6 (in-process flock proof, ACL attestation of the installed ACL, SecItemUpdate mutant not replayed, `user_presence` as request flag). `./scripts/setup.sh` end-to-end install not run. No new anomalies; the rev6 keychain listing flake did not reproduce in this run.

Docs: README (persisted-record paragraph), SKILL (operator note), LOGBOOK 1845.
