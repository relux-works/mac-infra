# TASK-260915-2ny9kd — t3 signer contract for kvctl + docs — developer results

Worktree `.temp/STORY-260915-3r0ys5/worktree`, branch `task-board/story/STORY-260915-3r0ys5`, base `39131c7` (T2). Candidate left uncommitted.

## Delivered

| Piece | Where |
| --- | --- |
| `mac-keyvault signer serve --address <s>/<p> [--kind K] [--version N]` — JSON lines, contract 1, hello line, `{id, ok, result\|error}` per request, errors never end the stream, EOF exit 0, startup failures as a one-line hello with `ok:false` | `cmd/mac-keyvault/main.go` (`runSigner`), `internal/keyvault/signer.go` (`SignerServer.Serve/handle`, `WriteStartupFailure`) |
| Shared pieces moved out of `cmd`: `Key.View`, `ClassifyError` (`ContractError`) | `internal/keyvault/signer.go`; `cmd` `keyView`/`classify` now delegate |
| Wire types + stdlib-only Go client (`Start`, `Call`, `Describe`, `PublicKey`, `PublicKeyPEM`, `Sign`, `Verify`, `Close`, `CryptoSigner`) | `internal/keyvault/signerclient/{wire,client}.go` |
| Golden wire fixtures: 35 request/response files + `fixture-key.json`, sessions `signer` (25), `verify-only` (3), `expired` (3), `missing` (1); 17 error responses in the signer session, one per server-side code; `-update` regenerates | `internal/keyvault/testdata/signer-v1/` |
| Docs: README Tools row + Key Vault "Signer contract for kvctl" paragraph; SKILL.md "Signer contract for kvctl" section (when to use, wire, how kvctl selects the backend, keychain vs enclave, ACL prompts incl. the one-time prompt after a rebuild, extraction policy / never `--human-authorized`); LOGBOOK 2140 entry | `README.md`, `agents/skills/mac-infra/SKILL.md`, `LOGBOOK.md` |
| `scripts/setup.sh` already builds `mac-keyvault` (lines 119–120, symlink 133) — verified with `bash -n` and by running its build line | not changed |

## AC coverage — 12 of 15 rows driven by named tests; 3 rows are process evidence

| AC row | Named test(s) | Production call site |
| --- | --- | --- |
| describe/pub/sign/verify round-trip over JSON lines against a test-label key | `TestRunSignerServeRoundTrip`, `TestRunSignerServeAgainstLoginKeychain` (cmd), `TestClientAgainstBuiltBinaryAndLoginKeychain` (signerclient, real binary + login keychain) | `run` → `runSigner` → `SignerServer.Serve` → `handle` → `Manager.Describe/Sign/PublicKeyFor` |
| hello announces contract 1 | `TestSignerServeGoldenWire/{signer,verify-only,expired,missing}` (hello fixtures), `TestRunSignerServeRoundTrip`, client `Start` contract check | `SignerServer.Serve` |
| golden fixtures byte-exact | `TestSignerServeGoldenWire` (35 lines compared `==` as strings) | `SignerServer.Serve` |
| malformed line → documented error, stream continues | fixture `signer-11-malformed-line` (bad_request, id null) + `signer-27-pub-after-errors`; `TestSignerServeGatesBeforeStore` | `SignerServer.handle` |
| unknown op | fixtures `signer-16`, `signer-25` (case-exact) | `handle` |
| missing id | fixtures `signer-13/14/15` (absent, null, object) | `handle`/`validID` |
| wrong digest length | fixtures `signer-17` (sign), `signer-26` (verify); client e2e short digest → `invalid_digest` | `digestParam` → `ValidateDigest`, `Manager.Sign` |
| usage_refused, stream continues | `verify-only-01` + `verify-only-02` | `Manager.Sign` → `authorize` |
| expired, stream continues | `expired-01` + `expired-02` | `Manager.Sign` → `authorize` |
| EOF exits 0 | `TestSignerServeEOFAndBlankLines` (Serve nil, trailing line without newline), `TestRunSignerServeRoundTrip` (exit 0), client `Close` nil in e2e | `Serve`, `runSigner` |
| signerclient drives the built binary end to end, verifies with crypto/ecdsa | `TestClientAgainstBuiltBinaryAndLoginKeychain` (`go build` of `cmd/mac-keyvault`, init via CLI, `ecdsa.VerifyASN1`/`ecdsa.Verify`, self-signed X.509 via `CryptoSigner`, tampered → `signature_invalid`, raw label → `foreign_label`, absent → `not_found`, `Close` → exit 0, key deleted) | `signerclient.Start` → `exec` `mac-keyvault signer serve` |
| existing keychain items untouched / prefix guard | `TestRunSignerServeRefusesBeforeStore` (raw label inside and outside the prefix, bad kind, negative version: zero store calls, then a positive control), `guardedBackend` in both cmd keychain tests (every touched label is a test label), client e2e asserts `hello.Label` under `works.relux.mac-keyvault.key.test.` | `runSigner` → `ParseAddress` before `newManager` |
| README/SKILL/LOGBOOK updated | not test-driven — see files | — |
| go vet/build/test -count=1 ./... green | not test-driven — commands below | — |
| Change Request published | not test-driven — `task-board handoff` | — |

## Mutants (all narrowing; harness `.temp/TASK-260915-2ny9kd/mutants.sh`, log `mutants-01.log`)

| Mutant | Narrows the gate to | Named failing test | Result |
| --- | --- | --- | --- |
| M1 `validID` admits `null` (absent still refused) | missing_id minus the null member | `TestSignerServeGoldenWire/signer` (fixture 14) | KILLED |
| M2 op matched case-insensitively (`SIGN` admitted) | unknown_op minus case variants | `TestSignerServeGoldenWire/signer` (fixture 25) | KILLED |
| M3 server digest-length gate skipped for `sign` only | invalid_digest on sign left to `Manager.Sign` | `TestSignerServeGoldenWire/signer` (fixture 17: `Manager.Sign` still refuses with `invalid_digest`, the CLI-worded hint differs) | KILLED — bound: the class stays refused by the Manager; the kill is on the wire bytes |
| M3b server digest-length gate skipped for `verify` only | invalid_digest on verify removed (verify has no Manager gate) | `TestSignerServeGoldenWire/signer` (fixture 26) | KILLED |
| M4 a `bad_request` response ends the stream (other errors continue) | "errors never end the stream" minus bad_request | `TestSignerServeGoldenWire/signer` (line count) | KILLED |
| M5 high-S refusal moved after `PublicKeyFor` (store listed first) | refusal still present, ordering weakened | `TestSignerServeGatesBeforeStore` (lists count) | KILLED |
| M9 request decoded loosely (unknown member admitted; malformed still refused) | bad_request minus unknown members | `TestSignerServeGoldenWire/signer` (fixture 12) | KILLED |
| M6 client accepts `contract >= 1` | contract check minus newer contracts | `TestStartRefusesForeignContractAndSurfacesStartupErrors` | KILLED |
| M7 client skips the id check when `ok: true` | id match minus successful responses | `TestCallProtocolViolationsAndRemoteErrors` | KILLED |
| M10 `CryptoSigner` accepts any hash (nil opts still refused) | SHA-256-only minus other hashes | `TestTypedCallsAgainstFake` | KILLED |
| M8 `runSigner` admits a well-formed raw label inside the prefix (`ParseLabel`) | foreign_label minus in-prefix raw labels | `TestRunSignerServeRefusesBeforeStore` | KILLED |
| M11 `signer serve` usage errors printed as text on stderr | one-line hello contract minus usage | `TestRunSignerServeRefusesBeforeStore` | KILLED |

No survivors. No source-text-inspecting gate exists in this delta (the source-text mutant row is inapplicable).

## Commands (real exit codes)

| Command | Exit | Log |
| --- | ---: | --- |
| `gofmt -l cmd internal` (empty) | 0 | — |
| `go vet ./...` | 0 | — |
| `go build ./...` | 0 | — |
| `go test -count=1 ./...` (live login keychain, 28 packages ok) | 0 | `.temp/TASK-260915-2ny9kd/go-test-all-01.log` |
| `go test -count=1 ./internal/keyvault/... ./cmd/mac-keyvault/` | 0 | `go-test-keyvault-01.log` |
| `MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -race` on the new tests | 0 | `go-test-race-01.log` |
| `.temp/TASK-260915-2ny9kd/mutants.sh` (12 mutants + baseline) | 0 | `mutants-01.log`, `mutant-*.log` |
| `bash -n scripts/setup.sh`; setup's build line for `mac-keyvault` into `.temp/…/bin`; `signer serve --address kvctl/pki-root < /dev/null` → one-line `not_found` hello, exit 1 | 0 / 0 / 1 (expected) | — |

Not run: `./scripts/setup.sh` in full — from a disposable worktree it would repoint `~/.local/bin/*` symlinks at the worktree's `bin/` and replace the heartbeat launcher; the orchestrator runs it from trunk. `go test ./...` requires the login keychain; `MAC_KEYVAULT_SKIP_KEYCHAIN=1` skips the three keychain tests (stated in each).

## Bounds

- kvctl is not code (bsim `EPIC-260915-3slg4l` planned); mac-keyvault defines contract 1 and `signerclient` is the only consumer it is proven against. No live kvctl interop.
- `store: enclave` cannot be served: creation is refused with `missing_entitlement` on this ad-hoc signed binary (T1 decision); documented in SKILL.
- The keychain prompt after a rebuild is documented from the T1 ACL findings and macOS legacy-keychain behaviour; it was not reproduced in this run (the e2e builds a fresh binary that creates and serves its own key, so no prompt fires).
- Golden fixtures pin exact bytes including hint text; the M3 kill is on wording, the class itself is double-gated.
