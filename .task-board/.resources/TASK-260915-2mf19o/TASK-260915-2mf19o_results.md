# TASK-260915-2mf19o — mac-keyvault init/list/pub/rotate/delete

Evidence gathered in the Story worktree `.temp/STORY-260915-3r0ys5/worktree` (branch `task-board/story/STORY-260915-3r0ys5`, uncommitted candidate on top of `f9ec756`), macOS Darwin 25.5, Apple Silicon, Go 1.25.5, 2026-09-15.

## Delivered

- `cmd/mac-keyvault/main.go` — `run(args, stdout, stderr) int`, subcommands `init|list|pub|rotate|delete|version|help`, `--json` envelope `{ok, command, result|error{code,message,os_status}}`, exit codes `0` ok / `1` failure / `2` usage / `3` policy refusal.
- `internal/keyvault/keyvault.go` — `Manager` with the policy gates (`ResolveLabel`, `RequireOwnLabel`, duplicate, confirmation, explicit -34018 refusal, rotate versioning), `Backend` interface, SPKI/fingerprint/PEM helpers.
- `internal/keyvault/security_darwin.{c,h,go}` — cgo bridge to Security.framework (`SecKeyCreateRandomKey`, `SecItemCopyMatching`, `SecItemDelete`, `SecAccessCreate` + `SecTrustedApplicationCreateFromPath(NULL)`); `security_unsupported.go` for `!darwin || !cgo`.
- `scripts/setup.sh` / `scripts/deinit.sh` build, symlink, and remove `mac-keyvault`; README "Key Vault Workflow" + Tools row; SKILL.md "Key Vault Workflow" + triggers.

## Store / bridge decision (recorded, re-verified)

Probe `.temp/TASK-260915-2mf19o/probe/probe.c` on this Mac, throwaway label `works.relux.mac-keyvault.test.probe`, deleted after each run:

| Shape (login keychain, permanent, non-extractable, ad-hoc signed CLI) | Result |
| --- | --- |
| plain `kSecAttrIsPermanent` + `kSecAttrIsExtractable=false` | OK |
| `kSecAttrAccessControl` (`kSecAccessControlPrivateKeyUsage`) | -34018 — routes the item into the Data Protection keychain |
| `kSecAttrAccessControl` (`kSecAccessControlUserPresence`) | -34018 |
| `kSecAttrAccess` = `SecAccessCreate(trusted=[SecTrustedApplicationCreateFromPath(NULL)])` | OK — **this is the ACL the tool uses** |
| `kSecAttrTokenID=kSecAttrTokenIDSecureEnclave` + permanent | -34018 |

- Bridge choice: cgo (C, no Objective-C needed), consistent with `internal/chromectl` and `internal/audiodevice`; a Swift helper binary would add a second toolchain and a process boundary for nothing.
- The legacy key schema has no creation-date attribute (`SecItemCopyMatching` returns `atag bsiz class decr drve encr esiz kcls klbl labl perm sign type unwp vrfy wrap` only). `created` and `store` are therefore written into `kSecAttrApplicationTag` as `mac-keyvault/1 store=keychain created=<RFC3339>`; an unreadable tag or public half is reported as `unknown`, never guessed.
- The bridge only runs per-key operations (`SecKeyCopyPublicKey`) for labels that carry `works.relux.mac-keyvault.`; foreign keys are filtered on attributes alone.
- Public key bytes cross the cgo boundary hex-encoded (first version used raw bytes and a generated point containing `0x1e` broke the record framing — caught in the smoke run, fixed, now pinned by `TestParseListRecords`).
- Deleting a pair created by a *different* build of the binary worked without a prompt in the smoke run (rebuild between `init` and `delete`); private-key *use* from another binary is subject to the keychain's own prompt — documented as a bound, not exercised (no sign command in T1).

## AC coverage — 13 of 13 rows driven

| AC row | Production call site | Named test |
| --- | --- | --- |
| init/list/pub/rotate/delete against the login keychain | `cmd/mac-keyvault.run` → `keyvault.Manager` → `keyvault.SecurityStore` | `TestRunAgainstLoginKeychain` (cmd), `TestSecurityStoreKeychainRoundTrip` (internal) |
| `--enclave` refuses with -34018 and the documented reason | `runInit` → `Manager.Init` → `SecurityStore.Create` (`MacKeyVaultCreate` with `kSecAttrTokenIDSecureEnclave`) | `TestRunAgainstLoginKeychain` (real -34018 via `run`), `TestRunInitEnclaveRefusalIsExplicit`, `TestManagerInitMissingEntitlementIsExplicitRefusal`, `TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement` |
| no silent fallback | same; asserts exactly one create of the requested shape and no persisted key | `TestManagerInitMissingEntitlementIsExplicitRefusal`, `TestRunInitEnclaveRefusalIsExplicit`, `TestRunAgainstLoginKeychain` (delete of `-se` label → ErrNotFound) |
| duplicate label refused | `Manager.Init` | `TestManagerInitDuplicateRefusedBeforeCreate`, `TestRunJSONEnvelopeAndExitCodes/init_duplicate`, `TestRunAgainstLoginKeychain`, `TestSecurityStoreDoesNotRefuseDuplicateLabelsItself` (bound: the keychain itself admits duplicates, the gate is the Manager) |
| delete without `--confirm` refused | `Manager.Delete` via `runDelete` | `TestManagerDeleteGates/own_unconfirmed`, `TestRunDeleteGatesBeforeStore/unconfirmed`, `TestRunJSONEnvelopeAndExitCodes/delete_unconfirmed*`, `TestRunAgainstLoginKeychain` |
| delete outside the prefix refused before any Security call | `Manager.Delete` → `RequireOwnLabel` (backend not called); CLI cannot address a foreign item because `ResolveLabel` always prefixes | `TestManagerDeleteGates/{foreign_*,sibling_namespace,bare_prefix_confirmed,prefix-only_lookalike}` (asserts `store.deletes` empty), `TestRequireOwnLabel`, `TestRunDeleteGatesBeforeStore` |
| list shows label, store, created, fingerprint (base64url SHA-256 SPKI DER) | `runList`, `Key.Fingerprint` | `TestRunListShowsAllColumns`, `TestFingerprintAndPEM`, `TestRunAgainstLoginKeychain` |
| pub writes SPKI DER or PEM | `runPub`, `keyvault.EncodePEM` | `TestRunPubWritesDERAndPEM`, `TestRunAgainstLoginKeychain` (`x509.ParsePKIXPublicKey` on the written DER) |
| rotate creates `<label>.v<N>` and keeps the old key | `Manager.Rotate` | `TestManagerRotate` (8 cases), `TestRunRotateKeepsOldKey`, `TestRunAgainstLoginKeychain` |
| JSON mode for every command | `output.success/fail` | `TestRunJSONEnvelopeAndExitCodes` (13 cases, JSON and text) |
| go vet/build/test -count=1 ./... green | — | see commands below |
| tests never touch a non-test-prefixed item (guard asserted) | `GuardedStore` (internal) / `guardedBackend` (cmd) wrap `SecurityStore` in every integration test | `TestGuardedStoreRefusesNonTestLabels` (control: production-prefixed and foreign labels refused, wrapped store untouched) |
| Change Request published for review | `task-board handoff` | — |

## Mutants (all narrowing; harness `.temp/TASK-260915-2mf19o/mutants/run.sh` runs the behavioral suites of both packages per mutant, log `results-clean.log`)

| Mutant | Narrows the gate to | Named failing test | Survived? |
| --- | --- | --- | --- |
| M1 `RequireOwnLabel` admits the bare prefix | prefix check without the length check | `TestRequireOwnLabel`, `TestManagerDeleteGates/bare_prefix_confirmed` | no |
| M2 `Manager.Delete` admits unconfirmed deletes for `test.` labels | confirmation required only outside the test namespace | `TestManagerDeleteGates/own_unconfirmed`, `TestRunJSONEnvelopeAndExitCodes/delete_unconfirmed`, `TestRunAgainstLoginKeychain` | no |
| M3 `Manager.Init` admits duplicates for the keychain store | duplicate check only for enclave | `TestManagerInitDuplicateRefusedBeforeCreate`, `TestRunJSONEnvelopeAndExitCodes/init_duplicate`, `TestSecurityStoreDoesNotRefuseDuplicateLabelsItself` | no |
| M4 `Manager.Init` silently falls back to the keychain on enclave -34018 | refusal only for user-presence | `TestManagerInitMissingEntitlementIsExplicitRefusal/enclave`, `TestRunInitEnclaveRefusalIsExplicit/enclave`, `TestRunAgainstLoginKeychain` | no |
| M5 `Manager.Delete` admits `works.relux.*` sibling namespaces | own-label check loosened to `works.relux.` | `TestManagerDeleteGates/sibling_namespace` (+ lookalike, bare prefix) | no |
| M6 `ResolveLabel` admits `..` | regex only | `TestResolveLabel/double_dot` | no |
| M7 `Manager.List` keeps `com.*` foreign labels | filter with one exception | `TestManagerListFiltersAndPublicLooksUpExact` | no |
| M8 CLI reports refusals with exit 1 | envelope kept, exit code class merged | `TestRunJSONEnvelopeAndExitCodes` (9 cases), `TestRunDeleteGatesBeforeStore`, `TestRunInitEnclaveRefusalIsExplicit` | no |
| M9 CLI skips `--confirm` in `--json` mode | confirmation only in text mode | `TestRunJSONEnvelopeAndExitCodes/delete_unconfirmed`, `TestRunDeleteGatesBeforeStore/unconfirmed`, `TestRunAgainstLoginKeychain` | no |
| M10 CLI ignores `--enclave` unless `--user-presence` | enclave request downgraded to keychain | `TestRunInitEnclaveRefusalIsExplicit/enclave`, `TestRunAgainstLoginKeychain` | no |
| M11 `Manager.Rotate` deletes the old key | rotate-and-replace | `TestManagerRotate` (6 cases), `TestRunRotateKeepsOldKey`, `TestRunAgainstLoginKeychain` | no |

Stated bounds:
- No gate inspects source text, so the "token-preserving mutant" row does not apply.
- No mutant was run against `MacKeyVaultDelete`'s label predicate in the C bridge: weakening that query would delete real keychain items on this Mac. The Go-side guard (`RequireOwnLabel`, M1/M5) plus the CLI's forced prefixing are the tested defense; the bridge's own query is exact-label by construction and is exercised only with test labels.
- `--enclave` success on a provisioned binary is not exercised (no such binary exists here); `TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement` would fail on such a binary and force a re-decision.

## Commands run (standalone, real exit codes)

| Command | Exit | Notes |
| --- | ---: | --- |
| `gofmt -l .` | 0 | no output |
| `go vet ./...` | 0 | |
| `go build ./...` | 0 | |
| `go test -count=1 ./...` | 0 | 27 packages ok, log `.temp/TASK-260915-2mf19o/go-test-01.log` |
| `go test -count=1 ./internal/keyvault/ ./cmd/mac-keyvault/` per mutant ×11 | 1 each | expected red, see table |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | |
| `go build -trimpath -o .temp/TASK-260915-2mf19o/mac-keyvault ./cmd/mac-keyvault` | 0 | setup.sh build shape |
| manual smoke: `init`, duplicate `init` (3), `--enclave` (3, -34018), `--user-presence` (3, -34018), `list`, `pub --out .der/.pem` (openssl parses), `rotate` ×2 → `.v2`, `.v3`, `delete` without confirm (3), `delete --confirm` ×3, `delete` missing (1) | as noted | test labels only, `list` empty afterwards |

Not run: `./scripts/setup.sh` end-to-end (it installs into `~/.local/bin` and re-signs the browser launcher; out of scope for a keyvault change). No linter beyond `gofmt`/`go vet` exists in the repository.
