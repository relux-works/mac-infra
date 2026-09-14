# TASK-260915-2ny9kd — rev3 rework results (after CR rev2 `changes_requested`)

Worktree: `.temp/STORY-260915-3r0ys5/worktree`, branch `task-board/story/STORY-260915-3r0ys5`, base `39131c7` (T2). Candidate left uncommitted for the handoff snapshot.

## Findings addressed

### F1 (repeat-of rev1 F2) — declared error set was circular
- `internal/keyvault/signerclient/codes.go`: one registry `ErrorContract` (39 rows: every §8 code plus the T1–T3 rows; `Code`, `Exit` 1/2/3, `Stream`, `When`), `Lookup`, `IsStreamCode`, `StreamErrorCodes()` (derived: the 21 `Stream` rows, sorted). The old hand-written `StreamErrorCodes` slice is gone.
- Every `keyvault.Code*` constant is now an alias of the registry constant (`keyvault.go`, `record.go`, `ecdsa.go`, `invariants.go`); `CodeUsage`/`CodeFailure`/`CodeNotFound` added; the CLI literal `"usage"` → `keyvault.CodeUsage`. `ClassifyError` takes the exit class from the registry row (`registered()`); the CLI `classify`/`exitCodeOf` read it transitively.
- Corpus (`internal/keyvault/testdata/signer-v1`, 84 fixtures + material): new server sessions `bad-spki` (invalid_public_key on verify, security on sign), `entitlement` (missing_entitlement on sign, os_status -34018), `backend-failure` (failure), `hello-security`, `hello-entitlement`, `hello-failure` (ok=false hellos); new CLI-driven `startup` session (12 fixtures: args + exit + hello line for usage ×5, foreign_label ×2, invalid_service, invalid_purpose ×2, invalid_kind, failure via unavailable lock path). Shared loader `internal/keyvault/signertest` (Load/Save/ErrorCodes) used by both suites.
- Reachable set enumerated by reading every emit path: `runSigner` (usage, ParseAddress → foreign_label/invalid_service/invalid_purpose/invalid_kind, newManager → failure), `Serve` hello (`Describe`→`List`: not_found, security, missing_entitlement, failure), `handle` (bad_request, missing_id, unknown_op), `sign` (invalid_digest, metadata_unknown, unsupported_primitive, usage_refused, expired, not_found, security, missing_entitlement, failure), `pub` (security), `verify` (invalid_signature, high_s_refused, signature_invalid, invalid_public_key, security). 21 codes.

### F2 — explicit zero-valued members bypassed the op gate
- `internal/keyvault/signer.go` `handle`: the line is decoded as `map[string]json.RawMessage`; id → op (unknown_op) → `requireMembers(op, members, allowedMembers[op])` refuses by **name** any member the op does not take (`describe`: none; `pub`: format; `sign`: format, digest; `verify`: format, digest, signature, allow_high_s) before any value is read; the typed decode runs afterwards only for types. `noParams` and the `!= ""`/`AllowHighS` value checks in describe/pub/sign are removed (they are what let false/"" through).
- Gate order now: not-one-object → missing_id → unknown_op → inapplicable member → wrong type → op value checks → Manager gates. Two existing golden messages changed (`signer-12`, `signer-22`) — same code, more specific message; reviewed.

## Tests added / changed (production call site in brackets)
| Test | Package | Proves |
| --- | --- | --- |
| `TestSignerServeRefusesInapplicableZeroValueMembers` | keyvault | 10 negative rows (`allow_high_s:false` on describe/pub/sign, `allow_high_s:true` on describe, `""` digest/format/signature where not taken, a real signature on sign) → bad_request naming the member, under the request id; zero `Sign`, one listing per control; controls: verify with explicit false, pub with explicit `""` format, plain sign [`SignerServer.Serve`→`handle`→`requireMembers`] |
| golden `signer-28…35` | keyvault | byte-exact wire for the same class + controls [`Serve`] |
| `TestSignerGoldenCoversStreamErrorCodes` (rewritten) | keyvault | registry Stream set ↔ corpus (startup + server) both directions; logs `21 of 21` [corpus is produced by `Serve` / `run`] |
| `TestSignerServedErrorCodesAreDeclared` | keyvault | re-serves every session and checks each emitted code directly against `IsStreamCode`, not against the fixture file [`Serve`] |
| `TestRunSignerServeStartupGolden` | cmd/mac-keyvault | startup fixtures: `run(args)` → exactly one hello line byte-exact, exit code, empty stderr, store untouched [`run`→`runSigner`→`WriteStartupFailure`] |
| `TestSignerStreamCodesEmittedByProduction` | cmd/mac-keyvault | one driver per declared code through `run(signer serve …)`; emitted code must equal the key, be declared, and have a golden; driver set = declared set both directions; logs `21 of 21` [`run`] |
| `TestErrorContractRegistryComplete` | signerclient | `go/parser` over `codes.go`: every `Code*` constant has a row and every row a constant; unique; Exit ∈ {1,2,3}; stream-only codes are Stream; `StreamErrorCodes`/`IsStreamCode`/`Lookup` agree |

## AC coverage — 12 of 15 rows driven by named tests
| AC row | Named test(s) | Production call site |
| --- | --- | --- |
| round-trips describe/pub/sign/verify against a test-label key | `TestRunSignerServeRoundTrip`, `TestRunSignerServeAgainstLoginKeychain` | `run`→`runSigner`→`SignerServer.Serve` |
| hello announces contract 1 | `TestSignerServeEOFAndBlankLines`, every `*-00-hello` fixture | `Serve` |
| golden fixtures byte-exact | `TestSignerServeGoldenWire`, `TestRunSignerServeStartupGolden` | `Serve`, `run` |
| malformed line → error, stream continues | `TestSignerServeGatesBeforeStore`, `signer-11` | `handle` |
| unknown op | `signer-16`, `TestSignerServeGatesBeforeStore` | `handle` |
| missing id | `signer-13/14/15`, gates test | `handle`/`validID` |
| wrong digest length | `signer-17`, `signer-26`, gates test | `digestParam`→`ValidateDigest` |
| usage_refused | `verify-only-01` | `Manager.Sign`→`authorize` |
| expired | `expired-01` | `Manager.Sign`→`authorize` |
| EOF exits 0 | `TestSignerServeEOFAndBlankLines`, `TestRunSignerServeRoundTrip` | `Serve`/`runSigner` |
| signerclient drives the built binary, verifies with crypto/ecdsa | `TestClientAgainstBuiltBinaryAndLoginKeychain` | `signerclient.Start`→`exec` binary |
| one negative per error code (description) | `TestSignerGoldenCoversStreamErrorCodes`, `TestSignerStreamCodesEmittedByProduction` | `Serve`, `run` |
| README/SKILL/LOGBOOK updated | process row — diff in CR | — |
| go vet/build/test -count=1 ./... green | process row — gate table below | — |
| Change Request published | process row — produced by the handoff | — |

## Mutants (all narrowing; harness `TASK-260915-2ny9kd_mutants-rev3.sh`, log `TASK-260915-2ny9kd_mutants-rev3.log`)
| Mutant | Narrows the gate to | Named failing test | Result |
| --- | --- | --- | --- |
| M1 members with raw value `false`/`""` treated as absent | admits exactly the zero-value class | `TestSignerServeRefusesInapplicableZeroValueMembers`, `TestSignerServeGoldenWire/signer` | killed |
| M2 `sign` allowed set gains `allow_high_s` | admits one member on one op | same two | killed |
| M3 only `allow_high_s:false` admitted | admits one member with one value | same two | killed |
| M4 registry row `invalid_kind` → `Stream:false` (token kept) | declared set shrinks by one production code | `TestSignerGoldenCoversStreamErrorCodes` | killed |
| M4b same mutant, CLI side | driver set ≠ declared set | `TestSignerStreamCodesEmittedByProduction` | killed |
| M5 row `failure` → `Stream:false` | one mid-stream/hello code undeclared | `TestSignerGoldenCoversStreamErrorCodes`, `TestSignerServedErrorCodesAreDeclared` | killed |
| M6 CLI emits `usage_error` instead of `usage` | production emits an undeclared code | `TestRunSignerServeStartupGolden` (5 fixtures), `TestSignerStreamCodesEmittedByProduction/usage` | killed |
| M7 row `invalid_public_key` removed, constant kept | registry loses one row (source-text gate, token preserved) | `TestErrorContractRegistryComplete` | killed |
| M8 `signature_invalid` exit class 1 → 3 | registry exit class drives the CLI | `TestRunVerifyVerdicts` (4 cases) | killed |
| M9 duplicate `not_found` row | registry uniqueness | `TestErrorContractRegistryComplete` | killed |
| M10 startup fixture `invalid_service` deleted | declared code without golden | `TestSignerGoldenCoversStreamErrorCodes`, `TestSignerStreamCodesEmittedByProduction/invalid_service` | killed |

11 mutants, 11 killed, 0 survivors. Harness ran with `MAC_KEYVAULT_SKIP_KEYCHAIN=1` (the mutated tests do not touch the keychain); worktree restored and verified after each mutant.

## Gates (each a standalone command, real exit code)
| Command | Exit | Log |
| --- | ---: | --- |
| `gofmt -l .` | 0 | `gofmt-rev3.log` — 6 paths listed, all reviewer scratch under `.temp/review-*` (gitignored, not in the delta); tracked and candidate files clean |
| `go vet ./...` | 0 | `go-vet-rev3.log` |
| `go build ./...` | 0 | `go-build-rev3.log` |
| `go test -count=1 ./...` (live login keychain) | 0 | `TASK-260915-2ny9kd_go-test-all-rev3.log` — 28 ok |
| `go test -race -count=1 ./internal/keyvault/... ./cmd/mac-keyvault/` | 0 | `go-test-race-rev3.log` |
| mutant harness | 0 (11/11 killed) | `TASK-260915-2ny9kd_mutants-rev3.log` |
| live probe of the built binary (reviewer's rev2 probes) | serve 0 / invalid_service 3 / usage 2 | `TASK-260915-2ny9kd_live-probe-rev3.log` — `allow_high_s:false` on describe/pub/sign → bad_request, plain sign ok; throwaway label deleted; `list` empty afterwards |

`scripts/setup.sh` builds `bin/mac-keyvault` (lines 119–120, 133) — verified by reading; the full script was not run from the worktree (it repoints `~/.local/bin` symlinks); the binary was built with `go build -o` instead.

## Bounds
- A code emitted only by a production path that no driver, fixture or test exercises is invisible to all three enumeration tests; the reachable set was fixed by reading every emit path (listed above), not by instrumentation.
- Two golden messages embed Go library text (`asn1: structure error…`, `json: cannot unmarshal number…`); a toolchain upgrade may require `-update` with a reviewed diff.
- kvctl is not code yet; no live kvctl interop (unchanged from rev1).
