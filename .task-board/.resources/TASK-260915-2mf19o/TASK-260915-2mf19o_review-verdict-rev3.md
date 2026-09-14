# TASK-260915-2mf19o review verdict — CR revision 3

Verdict: **changes requested** → `to-dev`

repeat-of: CR revision 2 F6 (itself repeat of CR revision 1 F3)

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `d8f7df5c6c4c56af6d65cb99afad5585ab15e8b1`, repository delta `present`. Review performed 2026-09-15 15:23 MSK. Product code and the managed worktree candidate were not modified.

## Findings

### F9 — High — F3 JSON usage-error class still has a bypass path

`flag.Bool("json", ...)` accepts Go boolean spellings including `TRUE`, `1`, and `t`, but the pre-parser mode detector at `cmd/mac-keyvault/main.go:178-185` recognizes only the bare flag and lowercase `=true`. The production entry therefore treats `version --json=TRUE extra`, `version --json=1 extra`, and `version -json=t extra` as text mode. Each returns exit 2 with an empty stdout and a text error on stderr instead of the required parseable error envelope on stdout with empty stderr.

This is a **bypass path around the check** and repeats the same class as rev2 F6 / rev1 F3. The common emitter and the command parser are both present; mode detection supplies the wrong routing fact before parsing.

Reproduction against the built frozen candidate (`.temp/review-TASK-260915-2mf19o/json-spelling-probes-01.log`):

```text
spelling=--json=TRUE rc=2 stdout_bytes=0 stderr_bytes=91
spelling=--json=1    rc=2 stdout_bytes=0 stderr_bytes=91
spelling=-json=t     rc=2 stdout_bytes=0 stderr_bytes=91
```

Required rework: add a production-`run(...)` regression covering every true spelling the accepted flag parser admits, with JSON-first and JSON-after-command controls, exit 2, parseable envelope, empty stderr, and zero backend calls. Add a narrowing mutant that keeps JSON detection present but admits only the currently enumerated spellings; the named regression must kill it.

### F10 — Medium — `list --kind` bypasses the closed kind validator and reaches Security.framework

The model-v2 kind vocabulary is closed, but `runList` validates only `--service` at `cmd/mac-keyvault/main.go:476-496`; it passes an arbitrary `--kind` directly to `Manager.List`. `--json list --kind bogus` succeeds with `result: []` and invokes `Backend.List` instead of refusing `invalid_kind` before any Security call.

Reviewer production-entry probe `TestReviewerProbeListRejectsInvalidKindBeforeBackend` failed:

```text
invalid list kind admitted: code=0 response={OK:true Command:list Result:[] Error:<nil>}
```

Required rework: route list-kind validation through the same closed vocabulary used by address parsing before constructing/calling the manager. Add a positive control for an allowed kind and a narrowing mutant that admits one unknown kind only on the list path.

### F11 — Medium — numeric meta does not round-trip through schema 2

The model permits numeric meta and requires record round-trip through the commands. `runMeta set --json-value` parses with `UseNumber` but immediately converts every `json.Number` to `float64` at `cmd/mac-keyvault/main.go:730-738`; `DecodeRecord` also uses plain `json.Unmarshal` at `internal/keyvault/record.go:386-403`. Consequently `9007199254740993` is silently persisted/read as `9007199254740992`, and a later rotate can rewrite the altered value.

Reviewer production-entry probe `TestReviewerProbeMetaJSONNumberRoundTrips` failed:

```text
numeric meta did not round-trip: value=9.007199254740992e+15 type=float64
```

Required rework: preserve JSON numeric values through `meta set`, schema-2 decode, describe/list, and rotate. Add an exact raw-envelope/tag regression using an integer outside float64's exact range, plus a nearby small-number positive control and a narrowing mutant that converts only numeric meta to float64.

## Acceptance and evidence assessment

- Producer reported `12 of 12` test-driven AC rows. Reviewer falsified the F3 row and the record-round-trip row; verified satisfaction is therefore at most `10 of 12` for that declared set.
- Rev3 configured validation log is complete: `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` all exit 0.
- Reviewer reran `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault`: both packages pass before adversarial probes.
- Reviewer reran the real Security.framework attestations for private-key non-exportability, exact private-operation ACL trust, explicit missing-entitlement behavior, and the legacy duplicate-label bound: pass.
- Reviewer launched two built CLI processes against one unique `works.relux.mac-keyvault.key.test.*` label: exactly one init succeeded, one returned `duplicate`/exit 3, both stderr streams were empty, and cleanup deleted the test item. This independently confirms the cross-process lock shape.
- Rev3 mutant log is complete and reports `0 of 32` survivors, but it does not contain the F9/F10/F11 narrowing shapes above.
- The candidate's key source hashes match the frozen tree. The managed worktree remains at the producer's uncommitted candidate state.

## Reviewer validation artifacts

- `.temp/review-TASK-260915-2mf19o/reviewer-probes-01.log`
- `.temp/review-TASK-260915-2mf19o/json-spelling-probes-01.log`
- `.temp/review-TASK-260915-2mf19o/review-targeted-tests-01.log`
- `.temp/review-TASK-260915-2mf19o/review-security-attestations-01.log`
- `.temp/review-TASK-260915-2mf19o/review-cross-process-race-01.log`

Logbook note: the reviewer role is read-only and changing the tracked `LOGBOOK.md` would mutate the frozen candidate and make CR revision 3 stale. This verdict records the regression durably; the producer should add the concise logbook entry as part of rev4 rework.
