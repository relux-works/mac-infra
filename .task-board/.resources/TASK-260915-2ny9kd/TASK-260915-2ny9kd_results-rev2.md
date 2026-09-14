# TASK-260915-2ny9kd — rev2 rework results (after review verdict rev1: changes_requested)

Worktree: `.temp/STORY-260915-3r0ys5/worktree`, branch `task-board/story/STORY-260915-3r0ys5`, base `39131c7`, candidate left uncommitted.

## F1 — unversioned sessions bypassed the hello attestation (bypass path around the check)

Fix (`internal/keyvault/signer.go`): `SignerServer.Serve` resolves the address once for the hello, then `pinGeneration` copies the version of the resolved label into `s.bound`; `describe`, `pub`, `sign`, `verify` all pass `s.bound` to `Manager.Describe/Sign/PublicKeyFor`. The hello `version` is now the bound generation (never 0). A rotate after the hello does not move the session; a new generation needs a new session.

Client (`internal/keyvault/signerclient/client.go`): `Start` refuses (`ErrProtocol`) a hello with `version < 1` and, when `Options.Version` was requested, a hello whose `version` differs. `Options.Version` and `Hello.Version` docs updated; package doc states the binding.

Regressions (production call sites named):
- `TestSignerServePinsGenerationAcrossRotate` (`internal/keyvault/signer_test.go`) — `SignerServer.Serve` over a pipe; `Manager.Rotate` between hello and first request; describe/pub/sign/verify must answer with the v1 label+fingerprint; the store's `Sign` is asserted to have been called with the v1 label only; controls: a fresh unpinned session after the rotate binds v2 (hello version 2), a `Version: 1` session binds v1.
- `TestClientAgainstBuiltBinaryAndLoginKeychain` (`signerclient/client_test.go`) — the reviewer's exact probe through the built binary (`runSigner` → `Serve`): `init` v1, `Start`, `rotate` via CLI, `PublicKey` fingerprint == hello fingerprint, `Describe` label == hello label, `Sign` fingerprint == hello fingerprint; controls: fresh `Start` binds v2 with a different fingerprint, `Start{Version:1}` binds v1. Both generations deleted by `--version` in cleanup.
- `TestStartRefusesUnpinnedOrMismatchedGeneration` (`signerclient/client_test.go`) — fake-server scenarios `unpinned` (version 0) and `version-3` against requested 1 are `ErrProtocol`; positive control version 1 requested/announced.

## F2 — golden negatives covered 10 of 13 documented stream codes

Fix: the documented set is now data — `signerclient.StreamErrorCodes` (13 codes). `TestSignerGoldenCoversStreamErrorCodes` (`internal/keyvault/signer_test.go`) walks every fixture response and compares the code set with the list in both directions, logging the ratio. Four golden sessions added under `internal/keyvault/testdata/signer-v1/` (16 fixture files, 52 total incl. key material):

| session | store shape | fixtures |
|---|---|---|
| `unreadable` | tag is not a record | hello, describe (findings), sign → `metadata_unknown`, verify → `metadata_unknown`, pub ok (stream continues) |
| `no-row` | `store: enclave`, no registry row | hello, sign → `unsupported_primitive`, verify → `unsupported_primitive`, describe ok |
| `no-spki` | public half unreadable | hello (fingerprint `""`), pub → `security`, verify → `security`, describe ok |
| `corrupt` | backend returns r=1,s=1 DER | hello, sign → `security` (does not verify under own key), pub ok |

Measured: **13 of 13** documented stream error codes have a byte-exact golden negative; 0 undocumented codes in the corpus. README claim rewritten to the measured statement.

## Mutants (all killed)

| # | mutant | narrows the gate to | named failing test | survivor bound |
|---|---|---|---|---|
| M1 | `pub` resolves `s.Address` (per-request newest) while other ops stay pinned | pin covers sign/verify/describe only | `TestSignerServePinsGenerationAcrossRotate` (response 2 answered v2) | — |
| M2 | `pinGeneration` returns the requested version unchanged (rev1 behaviour restored) | no pin at all | `TestSignerServePinsGenerationAcrossRotate` (hello version 0); also `TestSignerServeGoldenWire` (5 hello fixtures) | — |
| M3 | `unsupported_primitive` dropped from `StreamErrorCodes` | documented set of 12 | `TestSignerGoldenCoversStreamErrorCodes` ("carry codes StreamErrorCodes does not list") | — |
| M4 | both `unsupported_primitive` fixtures removed | corpus of 12 codes | `TestSignerGoldenCoversStreamErrorCodes` ("12 of 13 … without a byte-exact golden negative") | — |
| M5 | client `hello.Version < 1` → `< 0` (unpinned hello admitted) | client accepts version-0 servers | `TestStartRefusesUnpinnedOrMismatchedGeneration` (unpinned: nil) | — |
| M6 | client `!= opts.Version` → `< opts.Version` (newer generation than requested admitted) | client accepts a hello ahead of the request | `TestStartRefusesUnpinnedOrMismatchedGeneration` (version-3 for requested 1: nil) | — |

No surviving mutants. No gate in this delta inspects source text (source-text mutant row inapplicable).

## AC coverage (rev2 delta rows)

| AC row | driven by | production call site |
|---|---|---|
| hello announces the bound generation; rotate after hello does not move the session | `TestSignerServePinsGenerationAcrossRotate`, e2e | `SignerServer.Serve` → `pinGeneration`; handlers → `Manager.*(s.bound)` |
| client refuses unpinned / mismatched hello | `TestStartRefusesUnpinnedOrMismatchedGeneration` | `signerclient.Start` |
| one byte-exact negative per documented stream code (13 of 13) | `TestSignerGoldenCoversStreamErrorCodes`, `TestSignerServeGoldenWire` | `SignerServer.handle` → `Manager.authorize` / `PublicKeyFor` / `Sign` self-verify |
| README/SKILL/LOGBOOK updated | edited | — |

Rev1 coverage (12 of 15 rows driven; docs/vet/CR are process rows) stands; the golden-error row moves from incomplete to 13 of 13.

## Gates run (exit codes)

| command | exit | log |
|---|---:|---|
| `gofmt -l .` (only `.temp/` reviewer probes listed, outside the module's tracked tree) | 0 | — |
| `go vet ./...` | 0 | vet.log |
| `go build ./...` | 0 | build.log |
| `go test -count=1 ./...` (live keychain, 28 pkgs ok) | 0 | test-all.log |
| `go test -count=1 -race ./internal/keyvault ./internal/keyvault/signerclient ./cmd/mac-keyvault` | 0 | test-race.log |
| `go -C . build -trimpath -o … ./cmd/mac-keyvault` (setup.sh build line) | 0 | — |
| `mac-keyvault --json list` after the suite: 0 items | 0 | — |

Not run: full `scripts/setup.sh` from the worktree (would repoint `~/.local/bin` symlinks at the worktree build); its build line was run instead.

## Anomaly

One earlier `go test -count=1 ./internal/keyvault/... ./cmd/mac-keyvault/` run (packages in parallel, all hitting the login keychain) had the e2e `rotate` answer `not_found` ("no version of test/signerclient-e2e-… exists for any kind") one second after `init` succeeded and the signer hello had resolved the same key. Five isolated reruns, the full `./...` run and the `-race` run all passed. Suspected transient keychain listing under concurrent test-label churn; not reproduced, recorded in LOGBOOK as a stated bound. The pin itself is not involved (the failure is in the CLI `rotate` list, before any stream request).

## Bounds

- kvctl is not code yet (bsim `EPIC-260915-3slg4l`): the Go client in this repo is the only consumer the contract is proven against.
- `security` with `os_status` (a real Security.framework status) is not golden-pinned: the two `security` goldens are the vault's own trust refusals (no `os_status`), which is the deterministic branch.
