# TASK-260915-2ny9kd — rev6 results (rework after rev5 changes_requested, F1: envelope presence gate bypassed by lossy typed decode; repeat-of rev4 F1)

Scope: client side only (`internal/keyvault/signerclient`); server and goldens untouched. Docs: README, SKILL, LOGBOOK (2130 rev6 entry), `wire.go` package doc.

## Fix

- New `internal/keyvault/signerclient/envelope.go`: `decodeEnvelope(line, hello)` is the one gate in `(*Client).readResponse` for the hello (`Start`) and every reply (`Call`). It decodes the line as `map[string]json.RawMessage` first and enforces the member contract by PRESENCE and JSON type — `ok` present and literally `true`/`false`; `id` present, non-null, string-or-number on a response and absent on the hello; `contract` absent on a response; no unknown member; `result`, when present, a non-null object; `error`, when present, a non-null object with exactly `code`/`message`/`hint` present as non-null strings and optional numeric `os_status`, no other member — and only then unmarshals the typed `Response`. `checkEnvelope` (rev5) keeps its job on the now-faithful struct.
- `Call` aborts (kills + reaps) the server on a decode failure so `Close` reports the kill; previously only the id/shape checks aborted.
- A missing `contract` on the hello stays `ErrContract` (documented on `Start`); `contract:"1"` is `ErrProtocol`.

## Regression test (production entry: `signerclient.Start` → `readResponse(ctx, true)`, `(*Client).Call` → `readResponse(ctx, false)`)

`TestClientRefusesEnvelopeMissingOrNullMembers` — `rawEnvelopeRows`, 47 raw JSON rows written verbatim by the fake server (`raw-hello-<row>` / `raw-<row>` scenarios; `$HEAD`/`$ID`/`$RESULT` substituted; never marshalled from `Response`). 86 of 86 applicable entries driven (`hello` × `call`, `rawSkip` where the row names the other entry's head member). Controls: `control-success`, `control-refusal`, `control-refusal-os-status`, `control-verify-verdict` (result next to `signature_invalid` on verify admitted; on pub or hello refused). Rows include every reviewer probe: `ok-missing` / `ok-missing-with-error` (hello and call), `error-null-on-ok`, `error-code-only`, `error-message-missing`, `error-hint-missing`, plus `ok-null`, `ok-string`, `ok-number`, `error-null-on-fail`, `error-*-null`, wrong-typed members, `result-null-*`, `result-array/string`, extra members at both levels, `id-*`, `contract-*`, non-object top level, trailing document. Every `rawProtocol` row asserts: `ErrProtocol`, no `*Error`, no leaked members, next call refused, `Close` non-nil (kill) mid-stream / no client at startup.

## Mutants (`.temp/TASK-260915-2ny9kd/mutants-rev6.sh`, log `mutants-rev6.log`; gate kept, one member class admitted each)

| Mutant | Narrows the gate to | Named failing test | Bound (survivors) |
|---|---|---|---|
| M1 absent `ok` admitted (read as false) | everything but ok-presence | `…/hello/ok-missing-with-error`, `…/call/ok-missing-with-error` | — |
| M2 `error:null` read as absent | everything but null-error | `…/hello/error-null-on-ok`, `…/call/error-null-on-ok` | — |
| M3 `error.message` optional | everything but message presence | `…/error-message-missing`, `…/error-message-null` | — |
| M4 `error.hint` optional | everything but hint presence | `…/error-hint-missing`, `…/error-hint-null` | — |
| M5 unknown top-level member admitted on responses | hello still strict | `…/call/contract-on-response`, `…/call/extra-member`, `…/call/extra-member-on-fail` | — |
| M6 absent `id` admitted on a response | id presence | none — SURVIVED | `Call`'s id-equality check (`bytes.Equal(resp.ID, req.ID)`) refuses the empty id with `ErrProtocol`; the raw id-presence rule is defence in depth, the test cannot tell which layer refused |
| M7 `result:null` read as absent | null-result | `…/call/result-null-on-ok`, `…/call/result-null-on-verify-fail` | — |
| M8 raw gate skipped for the hello (typed decode only) | responses only | `…/hello/error-code-only`, `…/hello/error-extra-member`, `…/hello/error-hint-missing` | — |
| M9 raw gate skipped for responses (typed decode only) | hello only | `…/call/contract-on-response`, `…/call/error-code-only`, `…/call/error-extra-member` | — |
| M10 `error.code:null` admitted by the raw gate | code null | none — SURVIVED | typed decode yields `""`, `IsStreamCode("")` is false → `ErrProtocol` from `checkEnvelope`; raw rule is defence in depth |
| M11 string `os_status` admitted by the raw gate | os_status type | none — SURVIVED | typed decode of `"os_status":"-25300"` into `int` fails → `ErrProtocol`; raw rule is defence in depth |
| M12 unknown error-object member admitted | error members | `…/hello/error-extra-member`, `…/call/error-extra-member` | — |
| M13 result of any type admitted (only null refused) | result type | `…/call/result-array`, `…/call/result-string` | — |
| M14 non-boolean, non-null `ok` admitted | ok type | none — SURVIVED | typed decode of `"ok":"true"` / `1` into `bool` fails → `ErrProtocol`; raw rule is defence in depth |

10 of 14 killed; the 4 survivors are members with a second, independent refusal layer and are reported as bounds (the raw gate is the SOLE gate for the ten killed classes, which are exactly the classes the rev5 review named: absent/null `ok`, `error:null`, missing/null `message`/`hint`, `result:null`, unknown members).

## Gates (standalone, real exit codes)

| Command | Exit | Log |
|---|---:|---|
| `gofmt -l <tracked .go + envelope.go>` | 0 (0 files) | `gofmt-rev6.log` |
| `go vet ./...` | 0 | `go-vet-rev6.log` |
| `go build ./...` | 0 | `go-build-rev6.log` |
| `git diff --check` | 0 | `git-diff-check-rev6.log` |
| `go test -count=1 ./...` (28 packages, live login keychain, built-binary e2e included) | 0 | `go-test-all-rev6.log` |
| `go test -count=1 -race ./internal/keyvault/... ./cmd/mac-keyvault/` | 0 | `go-test-race-rev6.log` |
| `mac-keyvault list --json` afterwards | `result: []` (no test-label item left; no existing Keychain item touched — prefix guard unchanged) | — |

Not run: full `./scripts/setup.sh` from the worktree (would repoint `~/.local/bin` symlinks at the worktree); unchanged since rev1. Bound unchanged: no live kvctl interop (kvctl is not code yet).

AC coverage unchanged from rev5 (12 of 15 rows driven by named tests; docs / vet-build-test / CR are process rows); this rev adds one named test for the client gate the review named.
