# TASK-260915-nl5may — results rev1 (T2 sign / verify)

Built on the T1 checkpoint (story branch, 1a150bd). Candidate left uncommitted in the story worktree.

## Delivered

- `mac-keyvault sign <s>/<p> (--digest <hex|@file> | --data-file F | --stdin) [--raw | --format ecdsa-der-low-s|ecdsa-raw] [--out FILE] [--kind K] [--version N]` — ECDSA P-256 over a 32-byte SHA-256 digest through `SecKeyCreateSignature(kSecKeyAlgorithmECDSASignatureDigestX962SHA256)` (new bridge `MacKeyVaultSign`, `internal/keyvault/security_darwin.c`); output strict DER folded to low-S (`normalized: true` when the bridge value was high-S), or 64-byte r||s; the record's `format.signature` is the default. `--data-file`/`--stdin` hash explicitly and the output says so (`hash`, `digest`, `digest_source`).
- `mac-keyvault verify (<s>/<p> | --spki FILE) (--digest|--data-file|--stdin) --sig <hex|@file> [--raw] [--allow-high-s]` — exit 0 `verified: true`; exit 1 `signature_invalid` with `verified: false`; exit 3 `invalid_signature` (non-strict DER, wrong raw length, r/s out of range), `high_s_refused` (unless `--allow-high-s`), `invalid_public_key`. `--spki` makes zero store calls.
- Gates (`Manager.Sign`, `internal/keyvault/keyvault.go`), all before the bridge: digest length → namespace → readable/valid record (`metadata_unknown`) → registry row (`unsupported_primitive`, exit 1) → `usages ∋ sign` (`usage_refused`) → `validity.not_after` (`expired`). `Manager.authorize` derives the decision from `Operations()` (the same registry derivation `describe` prints) — nothing added outside the `(key, ec-p256, keychain)` row; `via` of `ecdsa-sha256-sign`/`-verify` is now `sign`/`verify`.
- Every T1 guard kept: address-only (`ParseAddress`), prefix guard, JSON envelope on every path (`failWith` carries the verdict result with the error), no backend call before validation.
- Docs: README key-vault section + tools table, SKILL workflow bullets, LOGBOOK 1930.

## AC coverage — 15 of 15 rows driven through `run()` (`cmd/mac-keyvault`) or the Manager, 1 stated bound

| # | AC row | Named test | Production call site |
| --- | --- | --- | --- |
| 1 | sign over 32-byte digest → strict DER low-S, verifies with Go crypto/ecdsa | `TestRunSignFormatsAndInterop` | `run(sign)` → `runSign` → `Manager.Sign` → `memStore.Sign` |
| 2 | … and with openssl | `TestRunSignVerifyAgainstLoginKeychain` (`openssl dgst -sha256 -verify` on a real keychain signature) | `run(sign)` → `SecurityStore.Sign` → `MacKeyVaultSign` |
| 3 | `--raw` → 64-byte r‖s | `TestRunSignFormatsAndInterop` | `runSign` / `Signature.Encode` |
| 4 | verify by label, exit 0/1, JSON verdict | `TestRunVerifyVerdicts` | `run(verify)` → `runVerify` → `Manager.PublicKeyFor` → `VerifyDigest` |
| 5 | verify by SPKI (DER and PEM), no store call | `TestRunVerifyVerdicts` | `runVerify` → `ParseSPKI` |
| 6 | interop: signature made here verifies with Go, and vice versa | `TestRunVerifyVerdicts` (Go sig → `verify --spki` and by label), `TestRunSignVerifyAgainstLoginKeychain` (openssl-made sig → `verify --spki`) | `runVerify` |
| 7 | high-S refused unless `--allow-high-s` (DER, raw, by label, by spki) | `TestRunVerifyVerdicts/high-s_*` | `runVerify` high-S gate |
| 8 | wrong digest length refused before any Security call | `TestRunSignVerifyRefuseBadInputBeforeStore` (31/33/0 bytes, hex and @file, sign and verify; `store.touched()==false`), `TestManagerSignGates/mis-sized_digest_before_any_call`, `TestSecurityStoreSign` | `digestFlags.resolve` → `ValidateDigest`; `Manager.Sign`; `SecurityStore.Sign` |
| 9 | tampered signature verdict false | `TestRunVerifyVerdicts` (tampered r, raw tampered, other digest, other key), `TestRunSignVerifyAgainstLoginKeychain` | `VerifyDigest` |
| 10 | sign on usages without sign → exit 3 `usage_refused` | `TestRunSignPolicyGates/verify_only`, `/wrap_only`, `TestManagerSignGates/usages_without_sign`, `TestRunSignVerifyAgainstLoginKeychain` (real key `--usages verify`) | `Manager.authorize` |
| 11 | sign after not_after → `expired` | `TestRunSignPolicyGates/expired`, `/expires_now`, `TestManagerSignGates/expired_*`, `TestRunSignVerifyAgainstLoginKeychain` | `Manager.authorize` (manager clock = CLI `now`) |
| 12 | sign on a foreign address refused | `TestRunSignVerifyRefuseBadInputBeforeStore/sign_raw_label`, `/verify_raw_label`, `/sign_bad_kind` | `ParseAddress` |
| 13 | describe reflects via: sign/verify | `TestRunSignPolicyGates/describe_via`, `TestRunDescribeOperationsAndLegacy`, `TestOperationsRegistry` | `keyView` → `Operations` |
| 14 | forged / rev1 / no-row record never reaches the private key | `TestForgedStoredRecordRefusedEverywhere` (27 forgeries + controls now drive `Sign`/`PublicKeyFor`), `TestRunSignPolicyGates/rev1_tag`, `/forged_title`, `/no_registry_row` | `Manager.authorize` |
| 15 | throwaway labels only, existing keychain items untouched | `guardedBackend`/`GuardedStore` (`Sign` now guarded too), `TestGuardedStoreRefusesNonTestLabels`; `list --service test` = 0 after the suite | test guard |
| — | kvctl's verifier | **stated bound**: kvctl is not in this repository; interop is proven against Go `crypto/ecdsa` and openssl 3.6.3 | — |

Mutant-harness bound: the harness executes the behavioural suite (`go test`), there is no static checker in this scope.

## Narrowing mutants (`.temp/TASK-260915-nl5may/mutants.py`, log `mutants-03.log`)

| Mutant | Narrows the gate to | Named failing test | Survivor? |
| --- | --- | --- | --- |
| M1 `ValidateDigest` admits 31..33 | off-by-one digests | `TestRunSignVerifyRefuseBadInputBeforeStore/sign_digest_31_hex`, `TestManagerSignGates/mis-sized_digest_before_any_call`, `TestSecurityStoreSign` | no |
| M2 no low-S folding in `Manager.Sign` | admits high-S out of sign | `TestRunSignFormatsAndInterop`, `TestManagerSignGates/high-S_from_the_backend_is_normalised` | no |
| M3 strict re-encode check relaxed | admits non-minimal DER | `…/verify_padded_der`, `TestParseSignatureStrictness/non-minimal_integer` both still pass | **yes — bound**: `encoding/asn1` already refuses non-minimal integers and long-form lengths; the re-encode check is defence in depth, not the effective gate |
| M4 high-S gate skipped for raw | admits high-S r‖s | `TestRunVerifyVerdicts/high-s_raw_by_label` | no |
| M5 usage verify implies sign | admits sign on verify-only record | `TestRunSignPolicyGates/verify_only`, `TestManagerSignGates/usages_without_sign` | no |
| M6 24h expiry grace | admits sign 1h after not_after | `TestRunSignPolicyGates/expired`, `TestManagerSignGates/expired_one_hour` | no |
| M7 self-check only when normalised | admits a low-S signature under another key | `TestManagerSignGates/signature_under_another_key_is_refused` | no |
| M8 `VerifyDigest` accepts any low-S | admits tampered signature | `TestRunVerifyVerdicts/tampered_r`, `TestRunSignVerifyAgainstLoginKeychain` | no |
| M9 `ParseSPKI` accepts any EC curve | admits P-384 SPKI | `…/verify_spki_p384`, `TestParseSPKI/p-384` | no |
| M10 `@FILE` hex-decoded when hex-looking | misreads one raw digest file | `…/hex-looking_file_is_raw_bytes` | no |
| M11 `PublicKeyFor` skips operations gate | admits verify against a no-row record | `TestRunSignPolicyGates/verify_by_label_no_registry_row`, `TestManagerPublicKeyFor/no_registry_row` | no |
| M12 CLI digest check removed | digest refused after a listing | `…/sign_digest_31_hex` still passes | **yes — bound**: `Manager.Sign` validates before listing, so the CLI check is redundant defence; see M12c |
| M12b `Manager.Sign` validates after resolve | digest refused after a listing | `TestManagerSignGates/mis-sized_digest_before_any_call` | no |
| M12c M12 + M12b together | both gates after the listing | `…/sign_digest_31_hex`, `…/verify_digest_31` (store touched) | no |
| M13 trust gate skips `ValidateStored` | admits a forged record to the private key | `TestRunSignPolicyGates/forged_title`, `TestForgedStoredRecordRefusedEverywhere/title_81_characters` | no |

Source restored byte-exact after every mutant (`git status` shows only the candidate changes).

## Gates (standalone processes, real exit codes)

| Command | rc | Log |
| --- | ---: | --- |
| `gofmt -l cmd internal` | 0, no output | `gofmt-01.log` |
| `go vet ./...` | 0 | `vet-01.log` |
| `go build ./...` | 0 | `build-01.log` |
| `git diff --check` | 0 | `diffcheck-01.log` |
| `go test -count=1 ./...` | 0 (27 ok) | `test-01.log` |
| `python3 mutants.py` | 1 (two stated-bound survivors, see above) | `mutants-03.log` |
| binary smoke on the login keychain (init/sign/pub/openssl verify/verify/delete, 0 test keys left) | all 0 | `binary-smoke-01.log` |
| `mac-keyvault --json list --service test` after the suite | 0 keys | — |

Not run: `./scripts/setup.sh` end-to-end install (not required for this delta). Change Request is produced by the handoff.

## Anomaly

`crypto/ecdsa.SignASN1` emits high-S about half the time; an early test asserting `normalized: false` on a fake-store signature flaked 2/6 runs. Fixed by making the fakes pick the half deterministically (low-S by default, `signHighS` for the twin); 8/8 subsequent runs green (`cli-flake-*.log`).
