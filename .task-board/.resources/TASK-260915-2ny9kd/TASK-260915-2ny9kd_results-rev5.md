# TASK-260915-2ny9kd — rev5 results (after rev4 changes_requested, F1 envelope; repeat-of rev3 F1)

Scope of this revision: `internal/keyvault/signerclient` only (client.go, client_test.go) plus README / SKILL / LOGBOOK. Server (`internal/keyvault/signer.go`, `cmd/mac-keyvault`) and golden fixtures untouched, per the orchestrator note.

## F1 — envelope validated as one shape before `ok` is read

- `checkEnvelope(resp Response, resultOnError bool) error` (client.go) is the single function used by `Start` (after the contract check, `resultOnError=false`) and `Call` (after the id check, `resultOnError = req.Op == OpVerify`). It runs before anything branches on `ok`.
- Admitted shapes: `{ok:true, result}` with no `error` member; `{ok:false, error}` with `IsStreamCode(error.code)`; `{ok:false, result, error}` only when `resultOnError` (verify's documented false verdict / high_s_refused partial verdict).
- Refused (`ErrProtocol`, process killed, client unusable, `Close` returns the kill status): error member next to `ok:true` (declared or not), `ok:true` without result or with `result: null`, `ok:false` without error, `ok:false` with a result for any op but verify (and for the hello), undeclared/empty code on either side of `ok`.
- `checkError` is gone; its check is the error-member branch of `checkEnvelope`. `TestClientFailsClosedOnUndeclaredErrorCode` (rev4) still passes unchanged.

## Regression (production entry points `signerclient.Start`, `(*Client).Call`)

`TestClientRefusesMalformedEnvelopeBeforeReadingOK` — fake signer subprocess (the test binary under `SIGNERCLIENT_FAKE_SERVER=envelope-hello-<shape>` / `envelope-<shape>`), table `envelopeShapes`: every combination of ok × result-present × error {absent, declared `signature_invalid`, undeclared `self_minted`} (12) plus `ok:true, result:null` (13). Each shape is driven three times: startup hello, mid-stream as `pub`, mid-stream as `verify` → 39 subtests. Expected verdict table in the test (`want`), sized against `envelopeShapes` so a shape without a row fails.

| shape | hello | pub | verify |
|---|---|---|---|
| ok-result-noerr | success (control) | success (control) | success (control) |
| ok-null-noerr | protocol | protocol | protocol |
| ok-result-declared (reviewer probe) | protocol | protocol | protocol |
| ok-result-undeclared (reviewer probe) | protocol | protocol | protocol |
| ok-noresult-noerr | protocol | protocol | protocol |
| ok-noresult-declared | protocol | protocol | protocol |
| ok-noresult-undeclared | protocol | protocol | protocol |
| fail-result-noerr | protocol | protocol | protocol |
| fail-result-declared | protocol | protocol | refusal + verdict (control) |
| fail-result-undeclared | protocol | protocol | protocol |
| fail-noresult-noerr | protocol | protocol | protocol |
| fail-noresult-declared | refusal (control) | refusal (control) | refusal (control) |
| fail-noresult-undeclared | protocol | protocol | protocol |

Assertions per `protocol` row: `errors.Is(err, ErrProtocol)`, no `*Error`, no client returned at startup; mid-stream the returned `Response` is empty (no member leaks), the next `Call` fails with `ErrProtocol` without writing, `Close` returns non-nil (kill reaped — the fake would exit 0 on EOF otherwise). Admitted rows: the session answers a second request and `Close` returns nil; `verify/fail-result-declared` additionally decodes `result.verified == false` next to the `signature_invalid` `*Error`.

## Mutants (`.temp/TASK-260915-2ny9kd/mutants-rev5.sh`, log attached)

| mutant | narrows the gate to | named failing test | status |
|---|---|---|---|
| R5-M1 call-check-only-when-not-ok (reviewer-named) | `Call` keeps `checkEnvelope` but runs it only under `!resp.OK` — the rev4 bypass | `…/pub/ok-result-declared`, `…/pub/ok-result-undeclared`, `…/verify/ok-*` (+ ok-noresult rows) | KILLED |
| R5-M2 hello-check-only-when-not-ok | same in `Start` | `…/hello/ok-result-declared`, `…/hello/ok-result-undeclared` | KILLED |
| R5-M3 ok-with-declared-error-admitted | `ok:true` + error refused only for undeclared codes | `…/pub|verify/ok-noresult-declared`, `…/verify/ok-result-declared` | KILLED |
| R5-M4 result-on-refusal-any-op | result next to a refusal admitted for every op but describe | `…/pub/fail-result-declared` | KILLED |
| R5-M5 hello-result-on-refusal | hello admits result next to a refusal | `…/hello/fail-result-declared` | KILLED |
| R5-M6 ok-without-result-admitted | `ok:true` with no result admitted | `…/pub|verify/ok-noresult-noerr`, `…/pub/ok-null-noerr` | KILLED |
| R5-M7 null-result-present | `result: null` counts as present | `…/pub|verify/ok-null-noerr` | KILLED |
| R5-M8 fail-without-error-admitted | `ok:false` with no error admitted | `…/hello|pub|verify/fail-result-noerr` | KILLED |
| R5-M9 self-minted-admitted | code set admits exactly `self_minted` | `TestClientFailsClosedOnUndeclaredErrorCode`, `…/hello|pub/fail-noresult-undeclared` | KILLED |
| R5-M10 envelope-not-fatal | malformed envelope is an error for this call but session not broken/reaped | `…/pub|verify/fail-noresult-noerr`, `…/pub/fail-noresult-undeclared` | KILLED |

10 of 10 killed, 0 survivors. Baseline (no mutant) exit 0.

## Gates (standalone processes, real exit codes)

| gate | exit | log |
|---|---:|---|
| `gofmt -l <tracked+untracked .go>` | 0, 0 files | gofmt-rev5.log |
| `go vet ./...` | 0 | go-vet-rev5.log |
| `go build ./...` | 0 | go-build-rev5.log |
| `go test -count=1 ./...` (28 pkgs, live login keychain) | 0 | go-test-all-rev5.log |
| `go test -count=1 -race ./internal/keyvault/... ./cmd/mac-keyvault/` | 0 | go-test-race-rev5.log |
| `git diff --check` | 0 | — |
| `mac-keyvault --json list --service test` after the suites | `result: []` (no test-label item left; no other label addressed) | — |
| `scripts/setup.sh` build line for mac-keyvault (lines 119–120) | present; full setup.sh not run (repoints ~/.local/bin symlinks) | — |

## AC coverage

Unchanged from rev4: 12 of 15 AC rows driven by named tests through `run()` / `Serve` / `signerclient.Start`/`Call`; 3 process rows (docs, vet/build/test gates, CR publication). This revision adds `TestClientRefusesMalformedEnvelopeBeforeReadingOK` (call sites: `signerclient.Start` → `checkEnvelope`; `(*Client).Call` → `checkEnvelope`) under the "signerclient test drives the binary / error contract" rows.

## Bounds

- `resultOnError` is decided by op (`verify`), not by code: a future contract that documents a partial result for another op needs a client change; a `verify` refusal with any declared code may carry a result (the server today emits one only for `signature_invalid` and `high_s_refused`).
- No live kvctl interop (kvctl not code yet). Server and goldens not re-verified beyond the full suite run.
- The listing flake recorded in rev2/rev4 (e2e `rotate` answering `not_found` right after `init`) did not occur in this run; it remains a stated bound.
