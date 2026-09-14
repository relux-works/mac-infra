# TASK-260915-2mf19o review verdict — CR revision 5

Verdict: **changes requested** → `to-dev`

repeat-of: none

Reviewed frozen candidate: base `f9ec756b123ea66a02545369ed007d9ddd8c5540`, candidate tree `6c93e3f04203be1853399d2b9e3d53e54393ab8b`, repository delta `present`. The reviewed `record.go` and `keyvault.go` blobs match that candidate tree exactly. Review performed 2026-09-15. Product code and candidate files were not modified; probes are under ignored `.temp/review-rev5/`.

## Finding

### F13 — High — rotate reproduces a model-v2-forbidden `validity.not_before` on a key

The consolidated model-v2 resource states that `validity.not_before` is certificate-derived and must be null for a key; a key may carry only caller-supplied `not_after`. `ValidateNew` at `internal/keyvault/record.go:277` checks only the ordering when both timestamps are present. A schema-2 key record with non-null `not_before` and null `not_after` therefore passes validation.

The production `Manager.Rotate` path at `internal/keyvault/keyvault.go:423` copies that record, calls the incomplete `ValidateNew` gate at line 453, and creates the next generation. The reviewer probe called `Manager.Rotate` with a recording `Backend` and observed:

```text
error=<nil> creates=1 new_label="works.relux.mac-keyvault.key.test.forged-not-before.v2" new_validity=map[not_after:<nil> not_before:2026-09-15T10:00:00Z] old_tag_unchanged=true
```

This is a **bypass path around the check** and an **unchecked refusal clause against the normative source**. The candidate's targeted suites remain green because their invalid-validity case covers only `not_after <= not_before`; no test drives the kind-specific nullability invariant through `Manager.Rotate` or `run(...)`.

Required rework:

1. Enforce the model-v2 kind-specific validity rule: for `kind=key`, `validity.not_before` must be null; the existing optional `not_after` remains valid. Keep future certificate behavior scoped to its owning task.
2. Add regressions through `Manager.Rotate` and `run(...)` using a persisted schema-2 key tag with non-null `not_before`: require `metadata_unknown`, zero `Backend.Create` calls, and byte-identical old tag/item.
3. Keep nearby positive controls: a key with both validity fields null and a key with only a future `not_after` must rotate successfully.
4. Add a narrowing mutant that leaves validity validation present but admits exactly non-null `not_before` on a key while the reversed-interval refusal remains active; the named rotate regressions must kill it.
5. Record F13 and its fix in `LOGBOOK.md` during producer rework. The reviewer did not edit the tracked logbook because that would change the frozen candidate under review.

## Evidence assessment

- Producer-reported AC coverage is `12 of 12`; F13 falsifies the model-v2 record/rotate row, so reviewer-verified coverage is at most `11 of 12`.
- Rev5 fixes F12 correctly: the shared exactly-one-document decoder is called by input decoding and persisted-record decoding; targeted F12 regressions pass.
- Independent `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault` passed, including real login-keychain non-exportability, exact private-operation ACL, missing-entitlement, end-to-end CRUD/rotate, and cleanup checks.
- Independent built-binary attacks passed: JSON usage (`rc=2`, empty stderr), invalid list kind (`rc=3`), foreign raw label (`rc=3`), trailing `--meta-json` document (`rc=2`), and a real two-process duplicate race (exactly one success and one `duplicate`, key removed afterward).
- The attached rev5 validation transcript is complete: `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` exit 0. Green evidence does not cover F13.
- The producer's 42-mutant table reports 0 survivors and includes narrowing F12 mutants, but no mutant for the key-specific `validity.not_before` rule.

## Reviewer artifacts

- `.temp/review-rev5/probe_not_before.go`
- `.temp/review-rev5/trailing-record.json`
- `.temp/review-rev5/race-1.out`, `.temp/review-rev5/race-2.out` and stderr captures
- `.temp/review-rev5/mac-keyvault`
