# TASK-260915-2ny9kd — rev4 results (after rev3 changes_requested)

Scope per orchestrator note: client side (`internal/keyvault/signerclient`) only. Server (`signer.go`), CLI and golden fixtures untouched.

## F1 — closed error surface enforced at the consumer (repeat-of rev2 F1 class)

- `client.go`: `checkError(*Error)` = present **and** `IsStreamCode(code)`; applied in `Start` (ok:false hello) and `Call` (every ok:false response).
- Undeclared/empty code → `ErrProtocol`, `abort()` (kill, then close stdin, reap), `c.broken` set → every later call fails. Declared code → `*Error`, session usable (unchanged).
- Production call sites: `signerclient.Start` (`client.go` hello branch), `(*Client).Call` (used by Describe/PublicKey/PublicKeyPEM/Sign/Verify/CryptoSigner).
- Regression: `TestClientFailsClosedOnUndeclaredErrorCode` (subprocess entry via fake server scenarios `startup-undeclared-code`, `startup-empty-code`, `undeclared-code`, `no-error-object`; reaped status asserted via `Close() != nil`; controls: `startup-error`/not_found and `ok`/unknown_op stay `*Error` with the session usable; registry sweep: all 21 `StreamErrorCodes()` accepted, 6 non-stream strings refused).

## F2 — hello accepted only as one coherent binding

- `wire.go`: `Tool = "mac-keyvault"`, `KindKey = "key"`; `Hello` doc states the binding rule.
- `client.go`: `checkHello(Hello, Options)` — tool, address == requested, kind == requested-or-key, version pinned (≥1) and == requested when set, label present, fingerprint present, ops == `Ops` exactly (length + order). Mismatch → `ErrProtocol` + reap.
- Regression: `TestStartRefusesHelloBoundToAnotherIdentity` — 13 negative rows (`helloBindingScenarios`: tool wrong/missing, address wrong/missing, kind wrong/missing, label missing, fingerprint missing, ops empty/missing/subset/superset/renamed), each error text names the member; controls: `binding-ok`, and `binding-kind-certificate` accepted with `Kind: certificate`, refused with kind omitted. Generation rows stay in `TestStartRefusesUnpinnedOrMismatchedGeneration`.
- e2e `TestClientAgainstBuiltBinaryAndLoginKeychain` (live keychain, built binary) still passes: the real hello satisfies the binding.

## Mutants (harness `.temp/TASK-260915-2ny9kd/mutants-rev4.sh`, log `mutants-rev4.log`)

| Mutant | Narrows the gate to | Named failing test | Result |
| --- | --- | --- | --- |
| R4-M1 self-minted admitted | closed set minus exactly `self_minted` | TestClientFailsClosedOnUndeclaredErrorCode | KILLED |
| R4-M2 startup code unchecked | hello checks error presence only | TestClientFailsClosedOnUndeclaredErrorCode | KILLED |
| R4-M3 undeclared code not fatal | ErrProtocol returned but session not broken/reaped | TestClientFailsClosedOnUndeclaredErrorCode | KILLED |
| R4-M4 empty code admitted | `""` treated as declared | TestClientFailsClosedOnUndeclaredErrorCode | KILLED |
| R4-M5 hello version-only (reviewer-named) | checkHello keeps only the version comparisons | TestStartRefusesHelloBoundToAnotherIdentity | KILLED |
| R4-M6 tool impostor admitted | tool check admits exactly `impostor` | TestStartRefusesHelloBoundToAnotherIdentity | KILLED |
| R4-M7 address missing admitted | empty address passes | TestStartRefusesHelloBoundToAnotherIdentity | KILLED |
| R4-M8 kind default unchecked | kind checked only when requested | TestStartRefusesHelloBoundToAnotherIdentity | KILLED |
| R4-M9 ops count only | ops compared by member length | TestStartRefusesHelloBoundToAnotherIdentity | KILLED |
| R4-M10 fingerprint optional | fingerprint required only when label also empty | TestStartRefusesHelloBoundToAnotherIdentity | KILLED |

10 of 10 killed, 0 survivors. Baseline (no mutant) exit 0. Source restored (`cmp` check in harness; `git status` shows no `.orig`).

## Gates (standalone processes, real exit codes)

| Command | Exit | Log |
| --- | ---: | --- |
| `gofmt -l <all .go>` | 0 (0 files listed) | gofmt-rev4.log |
| `go vet ./...` | 0 | go-vet-rev4.log |
| `go build ./...` | 0 | go-build-rev4.log |
| `go test -count=1 ./...` (28 pkgs, live keychain) | 0 | go-test-all-rev4.log |
| `go test -count=1 -race ./internal/keyvault/... ./cmd/mac-keyvault/` | 0 | go-test-race-rev4.log |
| `mac-keyvault --json list --service test` afterwards | 0, `result: []` | — |

`scripts/setup.sh` builds `mac-keyvault` (lines 119–133); its full install was not run from the worktree (would repoint `~/.local/bin` symlinks) — unchanged from rev1–3.

## AC coverage

Unchanged from rev3: 12 of 15 AC rows driven by named tests (signer serve round-trip, hello contract 1, goldens byte-exact, malformed/unknown op/missing id/wrong digest/usage_refused/expired without stream end, EOF exit 0, signerclient e2e with crypto/ecdsa verification); README/SKILL/LOGBOOK, vet/build/test, CR published are process rows. rev4 adds the two client-side gates above with 2 named regressions and 10 narrowing mutants.

## Docs

README Key Vault section, SKILL.md "How kvctl selects this backend" and LOGBOOK (`0030 — mac-keyvault T3 rev4`) updated for the client-side binding and closed-set enforcement.

## Bounds

- No live kvctl interop (kvctl not code yet); this Go client is the only proven consumer.
- The hello binding compares against what the consumer requested; it does not compare `fingerprint` against a kvctl-configured value (that remains kvctl's documented check).
- `abort` kill-before-close makes the reaped status deterministic for a server blocked on stdin; a server that has already exited on its own reports its own status.
