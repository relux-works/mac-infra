# TASK-260915-2ny9kd review verdict — CR revision 3

Verdict: **changes_requested** → `to-dev`

repeat-of: CR revision 2 / F1. F2 below is also a neighboring repeat of CR revision 1 / F1.

Reviewed candidate: base `39131c7b28152fda50ed6224ef7afe566d8829f2`, candidate tree `c0ef73f5460f5e1cb24d337025eedf25c9cc7618`, 103 changed paths, repository delta present. An alternate-index snapshot of the current worktree reproduced the candidate tree exactly. The CR patch SHA-256 is `bcb137b0cb995f331b9c42b737dc526dcf1e131cfd901da187f9c9d734be16ec`, matching the handed-off digest. The publication validation log is complete and ends with exit 0 for `go test -count=1 ./...`, `go vet ./...`, and `go build ./...`. This review reran `MAC_KEYVAULT_SKIP_KEYCHAIN=1 go test -count=1 ./internal/keyvault/... ./cmd/mac-keyvault`; all focused packages passed. No Keychain item was touched by this review.

## F1 — signerclient accepts codes outside the closed contract

Shape: **bypass path around the check** / **declared gate not enforced at the consumer**. This repeats the closed-error-surface class from CR revision 2 F1.

The package contract says the only stream codes are the `Stream` rows of `ErrorContract` and “any other code is a contract break” (`internal/keyvault/signerclient/wire.go:19-22`; the same instruction appears in `agents/skills/mac-infra/SKILL.md:521`). `signerclient.Call`, however, returns every non-nil wire error as an ordinary `*signerclient.Error` without consulting `IsStreamCode` (`client.go:166-172`). The startup-error branch has the same bypass (`client.go:108-113`).

The review probe drove the public `signerclient.Start`/`Call` entry points against a subprocess that spoke contract 1 and returned `error.code: "self_minted"`. `Call` returned it as a normal remote error (`errors.As(*signerclient.Error)=true`, `errors.Is(ErrProtocol)=false`) and the next call succeeded, so the exact client intended for kvctl treats an undeclared code as recoverable even though its contract declares it a protocol break.

Required rework: enforce the closed code set on both startup and post-hello errors. An undeclared code must make the client fail closed with `ErrProtocol` and become unusable; a declared refusal remains a typed `*Error` and leaves the stream usable. Because this repeats the prior closed-set finding, revision 4 must include a named subprocess-entry regression and a narrowing mutant that keeps the check present but admits exactly one undeclared code (not a delete-only mutant).

## F2 — signerclient accepts a hello bound to a different signer identity

Shape: **bypass path around the hello attestation**. Neighboring repeat of CR revision 1 F1.

`Start` validates `contract` and the generation only (`client.go:104-129`). It does not validate the hello's `address`, `kind`, `tool`, or required operation set against the process it requested. The same public-entry probe requested `Address: "test/fake"`, `Kind: "key"`, `Version: 1`; the subprocess announced `tool: "impostor"`, `address: "other/key"`, `kind: "certificate"`, and `ops: []`. `Start` accepted the session. A consumer can therefore configure one key/backend and receive a successful client bound to another identity, while the comments say the hello attests every later signature.

Required rework: validate the successful hello as one coherent contract-1 binding before returning a client: the announced tool, requested address, effective kind (`key` when omitted), pinned/requested version rule, and complete contract-1 operation set must match. Reject a mismatch or missing required member with `ErrProtocol` and reap the process. Add production-entry negative rows with nearby valid controls and a narrowing mutant that retains only the current version comparison so the named regression kills it. Keep configured fingerprint comparison as the documented kvctl-side check; this finding does not ask signerclient to invent kvctl configuration that does not exist yet.

## AC and evidence summary

- Producer evidence maps **12 of 15 AC rows** to named tests and production call sites; the remaining three are explicit process rows. The executable server/golden/e2e rows are green.
- Revision 3 closes the two revision-2 server-side findings: op-member presence is checked before value, and 21 of 21 declared stream codes have driven golden evidence with narrowing mutants.
- The vendorable client does not enforce the same closed error surface or the hello binding it documents. The stable consumer contract is therefore not fail-closed yet.
- README, SKILL, LOGBOOK, setup build wiring, and the no-live-kvctl bound are present. The full live-Keychain publication run reports cleanup to an empty test-label listing; this review used the skip flag and created no Keychain item.

Review probe: `TASK-260915-2ny9kd_review-client-contract-probe-rev3.log`.
