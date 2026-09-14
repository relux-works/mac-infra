# TASK-260915-2ny9kd — rev7 results (rework after rev6 changes_requested: F1 duplicate members, repeat-of rev5 F1; F2 unowned result validation, repeat-of rev3 F2)

Scope: client (`internal/keyvault/signerclient`) and the server request decoder (`internal/keyvault/signer.go` `handle`), as the orchestrator note directs. Goldens: one message text changed (`signer-11`: `member "op": unexpected EOF`), four fixtures added (`signer-36..39`); every other fixture is byte-identical to rev6 (diffed against the rev6 CR patch). Docs: README, SKILL, LOGBOOK (2215 rev7 entry), `wire.go` package doc.

## F1 — one token-level object reader, both ends

- `signerclient.DecodeObject` (`object.go`): `json.Decoder.Token` in source order; a second member of one DECODED name is `ErrDuplicateMember` naming it (the decoder resolves `\u` escapes before the comparison, so `"contract"` after `"contract"` is a repeat); exactly one JSON object (not scalar/array/null/empty), nothing after it; values kept raw. `Object.Get/Has/Names`.
- Client: `decodeEnvelope` and `checkErrorMember` (`envelope.go`) read through it; `decodeHelloResult` and every op result (`resultObject`, `result.go`) read through it. No `map[string]json.RawMessage` is decoded anywhere on the wire path before that gate.
- Server: `SignerServer.handle` reads the request line through it; a repeated member is `bad_request` under `id: null` (no id is trusted on a contradictory line) naming the duplicate, before any value is read; `requireMembers` takes the `Object`.
- Production call sites: `signerclient.Start → readResponse(ctx,true) → decodeEnvelope → DecodeObject`; `(*Client).Call → call → readResponse(ctx,false) → decodeEnvelope`; `checkErrorMember → DecodeObject`; `Start → decodeHelloResult → resultObject → DecodeObject`; `call → checkResult → {checkDescribe,checkPub,checkSign,checkVerify} → resultObject → DecodeObject`; `keyvault.(*SignerServer).Serve → handle → signerclient.DecodeObject`.

## F2 — one owner of result validation

- `checkResult(req, resp, hello, pub)` (`result.go`) runs inside `call` after `checkEnvelope` (and the id check) and before any typed helper returns; a mismatch is `ErrProtocol`, `fail()` kills and reaps the server, the client is unusable, `Close` reports the kill.
- Per op: **describe** — `label`/`fingerprint` == hello, `kind`,`version`,`service`,`purpose`,`schema`,`exposure`(non-empty),`operations`(array),`findings`(array) present and non-null (record vocabulary not closed: stated bound). **pub** — closed set {label,fingerprint,format,der_base64|pem}; identity == hello; `format` == effective request; encoding decodes (base64 / one `PUBLIC KEY` PEM block, nothing after), parses as P-256 SPKI, `Fingerprint(der)` == hello fingerprint. **sign** — closed set of 9; identity == hello; `hash` sha256; `digest` == sent; `format` == requested (or one of the two when the record default was requested); `signature` hex parses strictly in that format (DER strict / 64 raw bytes, r,s in [1,n-1]); `signature_base64` same bytes; s low-S and `low_s` true; `ecdsa.Verify` under the attested key. **verify** — only `ok`, `signature_invalid`, `high_s_refused` may carry a verdict, and must; closed set (identity members required on ok/signature_invalid, forbidden on high_s_refused); `hash`/`digest`/`format`/`high_s_allowed` as sent; `low_s` == computed from the sent signature; `high_s_refused` only for a high-S signature without `allow_high_s`; a verdict on a high-S signature without `allow_high_s` refused; `verified` == `ecdsa.Verify` under the attested key (true on ok, false on signature_invalid). **hello** — closed set of 8, all present and non-null (then `checkHello` as before).
- The attested key: `Call` on `sign`/`verify` first performs one `pub` (spki-der) request through the same gate when `c.pub` is nil; `attestedKey` reads it after `checkPub` admitted it. Exported for kvctl: `Fingerprint`, `ParseSignature`, `IsLowS`, `ParseSPKI`, `DecodeObject`; `keyvault.Key.Fingerprint` now delegates to `signerclient.Fingerprint` (one definition).

## Regression tests (all through production entry points)

| Test | Entry | Rows | Result |
|---|---|---:|---|
| `TestClientRefusesDuplicateMembers` | `Start` (hello) / typed helpers → `Call` | 18 rows, 27 of 27 hello+call entries; contradictory value first, honest last (the map-collapse order); escape-spelt repeats at envelope, `error`, hello result, pub/sign results; controls: honest line, single escape-spelt member (admitted), declared refusal | pass |
| `TestSignerServeRefusesDuplicateMembers` | `SignerServer.Serve` | 7 negatives (digest/op/id/signature, verbatim + escaped), 2 controls (an escape-spelt SINGLE digest reaches the backend once; plain sign once); 0 backend calls for negatives | pass |
| goldens `signer-36..39` | `Serve` byte-exact | duplicate member, escaped duplicate, duplicate id → `bad_request` id null; sign after → ok | pass |
| `TestDecodeObject` | `DecodeObject` | order, nested, 16 refusals, `ErrDuplicateMember` | pass |
| `TestClientRefusesResultNotBoundToRequestOrHello` | `Describe`/`PublicKey`/`PublicKeyPEM`/`Sign`/`Verify` → `Call` | 77 of 77 rows: describe 11, pub 19, sign 22, verify 25; every refusal names its reason (log in the -v output); controls per op and format; `describe-extra-record-field` admitted (bound) | pass |
| `TestSignVerifiesUnderTheHelloKey` | `Sign`/`PublicKey`/`Verify` | hello fingerprint == `Fingerprint(spki)` == sign fingerprint; signature verifies under the returned key | pass |
| updated `TestClientRefusesMalformedEnvelopeBeforeReadingOK` | `Call` | verify column now sends a real (or tampered) signature from the fake key; `fail-noresult-declared` for verify is `protocol` (signature_invalid must carry a verdict) | pass |
| updated `TestClientRefusesEnvelopeMissingOrNullMembers` | `Start`/`Call` | 86 of 86 entries unchanged; fake answers the attested-key `pub` honestly on verify rows | pass |

The fake server (`fake_test.go`) now owns a real P-256 key per process and produces honest answers for every op (`fakeKey.answer`); each negative scenario is the honest answer changed in exactly the way its row states. A fake with `fingerprint: "f"` cannot drive a client that checks fingerprints.

## Full client attack matrix (rev3 → rev7)

| Class | Gate (owner) | Test | Rev |
|---|---|---|---|
| undeclared / empty error code | `checkEnvelope` + `IsStreamCode` | `TestClientFailsClosedOnUndeclaredErrorCode` | 4 |
| hello identity (tool, address, kind, version, label, fingerprint, ops) | `checkHello` | `TestStartRefusesHelloBoundToAnotherIdentity`, `TestStartRefusesUnpinnedOrMismatchedGeneration` | 2, 4 |
| envelope shape (ok × result × error) | `checkEnvelope` | `TestClientRefusesMalformedEnvelopeBeforeReadingOK` (13 shapes × 3) | 5 |
| member presence / null / type / unknown | `decodeEnvelope`, `checkErrorMember` | `TestClientRefusesEnvelopeMissingOrNullMembers` (47 raw rows) | 6 |
| duplicate members (verbatim, escape-spelt; envelope, error, hello, results) | `DecodeObject` | `TestClientRefusesDuplicateMembers` (18 rows), `TestDecodeObject` | 7 |
| result binding to request + hello (+ crypto re-derivation) | `checkResult` | `TestClientRefusesResultNotBoundToRequestOrHello` (77 rows) | 7 |
| protocol basics (foreign id, EOF, silence, garbage, contract ≠ 1) | `call`, `readResponse`, `Start` | `TestCallProtocolViolationsAndRemoteErrors`, `TestStartRefusesForeignContractAndSurfacesStartupErrors` | 1 |
| built binary end to end (rotate mid-session, DER/raw, X.509) | all | `TestClientAgainstBuiltBinaryAndLoginKeychain` | 1–2 |

## Mutants (`mutants-rev7.sh`, log `mutants-rev7.log`; gate kept, one class admitted each; 18 of 18 killed)

| Mutant | Narrows the gate to | Named failing test | Bound |
|---|---|---|---|
| M1 escape-spelt repeat admitted (verbatim still refused) | verbatim repeats | `…DuplicateMembers/hello/envelope-contract-escaped`, `/call/envelope-contract-escaped`, `TestSignerServeGoldenWire/signer` (signer-37), `TestSignerServeRefusesDuplicateMembers` | — |
| M2 repeat of `ok` admitted | every name but ok | `…/hello/envelope-ok`, `/call/envelope-ok`, `…-escaped` | — |
| M3 nested `error` read through a map | envelope only | `…/hello/error-code`, `/call/error-code`, `…-escaped` | — |
| M4 hello + op results read through a map | envelope + error only | `…/hello/hello-tool`, `/hello/hello-fingerprint`, `/call/describe-label`, `/call/pub-fingerprint`… | — |
| M5 server request read through a map | client only | `TestSignerServeRefusesDuplicateMembers`, `TestSignerServeGoldenWire/signer` (36–38) | — |
| M6 data after the object admitted | object itself | `TestDecodeObject` | — |
| M7 fingerprint not bound (label still is) | label | `…ResultNotBound/describe-fingerprint-foreign`, `/pub-fingerprint-foreign`, `/sign-…`, `/verify-…` | — |
| M8 sign: no `ecdsa.Verify` (shape, low-S kept) | shape | `/sign-signature-foreign-key`, `/sign-signature-other-digest` | — |
| M9 sign: digest not bound | rest of sign | `/sign-digest-other` | — |
| M10 verify: verdict not re-derived | claims only | `/verify-false-on-valid`, `/verify-true-on-tampered` | — |
| M11 verify: `high_s_allowed` not bound | rest of verify | `/verify-high-s-allowed-flipped` | — |
| M12 pub: SPKI parsed, not fingerprinted | parse only | `/pub-der-foreign-key`, `/pub-pem-foreign-key` | — |
| M13 describe not validated (other ops are) | 3 ops | `/describe-*` (7 rows), `…DuplicateMembers/call/describe-label` | — |
| M14 sign judged, verdict ignored | 3 ops | `/sign-*` (19 rows), `…DuplicateMembers/call/sign-digest` | — |
| M15 verify: result next to an undocumented refusal admitted | documented codes | `/verify-result-on-not-found` | — |
| M16 undefined result members admitted | presence + binding | `/pub-both-encodings`, `/pub-extra-member`, `/sign-extra-member`, `/verify-extra-member`, `/verify-label-on-high-s` | — |
| M17 verify: `low_s` claim not checked | rest | `/verify-low-s-flipped` | — |
| M18 `Call` judges results only on refusals | refusals | every ok-result row of both corpora | — |

## Gates (standalone, real exit codes)

| Command | Exit | Log |
|---|---:|---|
| `gofmt -l` (tracked + untracked .go) | 0 (0 files) | `gofmt-rev7.log` |
| `go vet ./...` | 0 | `go-vet-rev7.log` |
| `go build ./...` | 0 | `go-build-rev7.log` |
| `git diff --check` | 0 | `git-diff-check-rev7.log` |
| `go test -count=1 ./...` (28 packages, live login keychain, built-binary e2e included) | 0 | `go-test-all-rev7.log` |
| `go test -count=1 -race ./internal/keyvault/... ./cmd/mac-keyvault/` | 0 | `go-test-race-rev7.log` |
| `mac-keyvault list --json` afterwards | `result: []` — no test-label item left; no existing Keychain item touched (prefix guard unchanged) | — |

Not run: full `./scripts/setup.sh` from the worktree (would repoint `~/.local/bin` symlinks at the worktree); unchanged since rev1.

## AC coverage

Unchanged ratio: 12 of 15 AC rows driven by named tests (docs / vet-build-test / CR are process rows). This rev adds two named client gates (`DecodeObject`, `checkResult`) and one server gate (`handle` duplicate refusal) with their regression tests and mutants.

## Bounds

- `describe`'s record vocabulary is not closed by the client (the record model owns it; kvctl compares fingerprint/label, which are bound). Extra record fields are admitted (`describe-extra-record-field` control).
- `Call` with an op outside the four is refused as `ErrProtocol` only when the server answers `ok`; a declared refusal (e.g. `unknown_op`) is returned as `*Error`.
- No live kvctl interop (kvctl is not code yet); the vendored Go client remains the contract boundary.
- One golden message text changed (`signer-11`): the token reader reports `member "op": unexpected EOF` where the map decoder said `unexpected EOF`.
