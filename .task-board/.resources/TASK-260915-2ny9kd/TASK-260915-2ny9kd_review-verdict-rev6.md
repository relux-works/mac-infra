# TASK-260915-2ny9kd review verdict — CR revision 6

Verdict: **changes requested** → `to-dev`.

Candidate: CR-TASK-260915-2ny9kd-6 revision 6, base `39131c7b28152fda50ed6224ef7afe566d8829f2`, candidate tree `9c3c9c6003581c5125d2748232c81a4d983f656d`, repository delta present.

Producer evidence reviewed: AC coverage reported as 12 of 15 rows driven; raw-envelope corpus 86 of 86 applicable entries; frozen-candidate validation log completed `go test -count=1 ./...`, `go vet ./...`, and `go build ./...` with exit 0. Reviewer reran `go test -count=1 ./internal/keyvault/signerclient ./internal/keyvault ./cmd/mac-keyvault`; all three packages passed. These green checks do not cover the findings below.

## F1 — duplicate decoded member names bypass the raw envelope gate

`repeat-of: revision 5 F1`

Negative shape: **bypass path around the check**; established project incident: **JSON maps are too late for duplicate-key gates**.

Production call site: `signerclient.Start` → `(*Client).readResponse` → `decodeEnvelope` (`internal/keyvault/signerclient/envelope.go`). `decodeEnvelope` first unmarshals into `map[string]json.RawMessage`; Go collapses identical and escape-equivalent keys before the gate can count or reject them. The reviewer fake signer emitted one hello with both `"contract":2` and `"co\\u006etract":1`. `Start` returned `nil` and a live client (`start_error=<nil> accepted=true`), so contradictory contract evidence was accepted.

Evidence: `TASK-260915-2ny9kd_review-duplicate-envelope-probe-rev6.log`.

Required rework: consume object tokens in source order and reject a second decoded member name before materializing a map or typed value. Apply the same rule to every contract-bearing object parsed by this wire path, including nested `error`; audit the server request decoder for the same map-collapse bypass. Add production-entry regressions for identical and escape-equivalent duplicates, with nearby valid controls, and a narrowing mutant that retains the token parser but admits exactly one duplicate class.

## F2 — typed result paths bypass the hello identity and operation-result contract

`repeat-of: revision 3 F2`

Negative shape: **bypass path around the check** and **many variants, one unowned decision**.

Production call site: `signerclient.Sign` → `(*Client).Call` → `checkEnvelope`, then typed `Signature` decode. The envelope is valid, but the result has no owned validator against the pending request or accepted hello. The reviewer fake signer answered a SHA-256/DER request with `label="foreign-label"`, `fingerprint="foreign-fingerprint"`, `hash="sha512"`, `digest="00"`, `format="wrong-format"`, `signature="00"`, and `low_s=false`. `Sign` returned `nil` error and byte `00`; a subsequent `Describe` also returned `nil`, proving the malformed result did not break/reap the session.

This defeats the package claim that the hello fingerprint attests later signatures and lets a vendored kvctl client treat a foreign/malformed result as a successful signing operation.

Evidence: `TASK-260915-2ny9kd_review-malformed-result-probe-rev6.log`.

Required rework: give operation-result validation one owner before any typed helper returns success. Validate result shape and its binding to the accepted hello and pending request (identity, hash, digest, effective format, encodings, low-S/signature semantics as applicable) across `describe`, `pub`, `sign`, and `verify`; any mismatch must be `ErrProtocol`, reap the process, and leave the client unusable. Add production-entry fake-signer negatives plus positive controls. Because this repeats the client identity-binding class, include a named regression test and a narrowing mutant that keeps validation present but admits exactly one mismatched result member. Record the finding/fix in `LOGBOOK.md` during producer rework; the reviewer did not modify the candidate tree.

## Bounds

- No live kvctl interop is possible because kvctl does not exist yet; the vendored Go client is therefore the contract boundary under review.
- Existing Keychain items were not touched by reviewer probes; both fakes are standalone subprocesses.
- The four reported rev6 mutant survivors still refuse through second-layer checks and are not findings by themselves.
