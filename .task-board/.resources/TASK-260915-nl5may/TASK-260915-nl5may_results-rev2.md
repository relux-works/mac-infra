# TASK-260915-nl5may — results rev2 (rework of review verdict rev1, F1 + F2)

Builds on the rev1 candidate (see `TASK-260915-nl5may_results.md`); rev1 AC table, gates and mutants M1–M13 are unchanged and not re-derived here except where rev2 changed the source. Candidate left uncommitted in the story worktree; `git status` shows only the candidate files.

## F1 — `GuardedStore.Sign` bypass (fixed)

- `internal/keyvault/security_darwin_test.go`: `(*GuardedStore).Sign` added, calls `guard(label)` before delegating; the type comment records the rule (every mutating or private-key-using `Backend` method is overridden; a promoted embedded method is a bypass).
- `TestGuardedStoreRefusesNonTestLabels` now drives `Sign` for all seven foreign labels against a wrapped fake that holds a **signing-capable** production key (`installSigner`), asserts `ErrGuardedLabel`, nil signature and `len(inner.signs)==0`; positive control: `key.test.ok.v1` signs through the guard and is the only recorded sign.
- The rev1 attestation "GuardedStore guards Sign" was wrong; it is true now and the named test above proves it.

## F2 — high-S refusal after `Backend.List` (fixed)

- `cmd/mac-keyvault/main.go` `runVerify`: the `high_s_refused` gate runs directly after `keyvault.ParseSignature`, before `os.ReadFile(--spki)` and before `singleAddress`/`newManager`/`Manager.PublicKeyFor`. The refusal envelope carries `hash/digest/digest_source/format/low_s/high_s_allowed/verified:false` and no key fields.
- New `TestRunVerifyHighSRefusedBeforeStore` (`cmd/mac-keyvault/sign_test.go`): signatures prepared independently with `crypto/ecdsa` (never via `run(sign)`), fresh recording `memStore` holding the addressed key per case, asserts exit 3 `high_s_refused`, JSON `verified:false`, `low_s:false`, no `label` in the result, `store.touched()==false`. Cases: DER by label, raw by label, DER by label with `@file` digest+sig, DER by absent address (still `high_s_refused`, not `not_found`), DER by absent `--spki` path (still `high_s_refused`, not usage). Positive control: the low-S form of the same signature lists once and verifies.
- `TestRunVerifyVerdicts/high-s_*` cases now run on a fresh store and assert `touched()==false` too.

## AC coverage delta

Rev1: 15 of 15 rows driven, 1 stated bound (kvctl verifier not in repo). Rev2 changes row 7 and row 15:

| # | AC row | Named test | Production call site |
| --- | --- | --- | --- |
| 7 | high-S refused unless `--allow-high-s`, **before any backend call** | `TestRunVerifyHighSRefusedBeforeStore` (5 cases + control), `TestRunVerifyVerdicts/high-s_*` | `run(verify)` → `runVerify` high-S gate directly after `ParseSignature` |
| 15 | throwaway labels only; existing keychain items untouched — **Sign included** | `TestGuardedStoreRefusesNonTestLabels` (Create/Delete/UpdateTag/Sign) | `GuardedStore.Sign` → `guard` |

Still 15 of 15 driven, 1 stated bound. `mac-keyvault --json list --service test` after the suite: `[]`.

## Narrowing mutants rev2 (`.temp/TASK-260915-nl5may/mutants-rev2.py`, log `mutants-rev2-01.log`, source restored byte-exact after each)

| Mutant | Narrows the gate to | Named failing test | Survivor? |
| --- | --- | --- | --- |
| M14 `GuardedStore.Sign` guard skipped for `key.kvctl.*` labels (guard present) | admits one foreign service class | `TestGuardedStoreRefusesNonTestLabels` (sign `key.kvctl.pki.v1` returned a non-guard error, signs recorded) | no |
| M15 `GuardedStore.Sign` override deleted (existence control) | Sign unguarded | `TestGuardedStoreRefusesNonTestLabels` (production label returned a real signature) | no |
| M16 high-S refusal moved after key resolution (rev1 order; gate present) | refusal after `Backend.List` | `TestRunVerifyHighSRefusedBeforeStore/*` (all 5), `TestRunVerifyVerdicts/high-s_der_by_label`, `/high-s_raw_by_label` | no |
| M17 early refusal only for DER, late gate kept | one raw high-S reaches `List` | `TestRunVerifyHighSRefusedBeforeStore/raw_by_label`, `TestRunVerifyVerdicts/high-s_raw_by_label` | no |
| M18 early refusal only for `--spki`, late gate kept | label-path high-S reaches `List` | `TestRunVerifyHighSRefusedBeforeStore/der_by_label`, `/raw_by_label`, `/der_by_label_@file`, `/der_by_absent_label`, `TestRunVerifyVerdicts/high-s_*_by_label` | no |

Rev1 survivors M3 and M12 stay stated bounds (unchanged source). Rev1 M4 is superseded by M17 (M4 proved the raw refusal existed, M17 proves its position). Mutant-harness bound: the harness executes the behavioural `go test` suite; no source-text checker exists in this scope.

## Gates (standalone processes, real exit codes)

| Command | rc | Log |
| --- | ---: | --- |
| `gofmt -l cmd internal` | 0, no output | — |
| `go vet ./...` | 0 | — |
| `go build ./...` | 0 | — |
| `git diff --check` | 0 | — |
| `go test -count=1 ./...` (before the doc-only edits) | 0 (27 ok) | `go-test-rev2-01.log` |
| `go test -count=1 ./cmd/mac-keyvault ./internal/keyvault` (after all edits) | 0 | `go-test-rev2-keyvault-02.log` |
| `python3 mutants-rev2.py` | 0 (5 killed, 0 survivors) | `mutants-rev2-01.log` |

Not rerun in rev2: openssl / login-keychain binary smoke (`TestRunSignVerifyAgainstLoginKeychain` covers it in the suite and is included in the green runs above; the standalone `binary-smoke-01.log` from rev1 is unchanged source-wise for the sign path). Change Request is produced by the handoff.
