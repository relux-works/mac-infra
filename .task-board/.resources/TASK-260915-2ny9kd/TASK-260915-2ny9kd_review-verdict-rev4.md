# TASK-260915-2ny9kd review verdict — CR revision 4

Verdict: **changes requested** → `to-dev`

repeat-of: revision 3 / F1

## Finding

### F1 — the closed error-code gate is bypassed by `ok:true`

`signerclient.Start` and `(*Client).Call` invoke `checkError` only inside `if !resp.OK` (`internal/keyvault/signerclient/client.go:112` and the corresponding Call branch). `Response` independently decodes both `ok` and `error` (`internal/keyvault/signerclient/wire.go:89`). A signer can therefore preserve an undeclared/self-minted `error.code`, flip only `ok` to `true`, and bypass the rev4 closed-set gate.

Production-entry probes through public `signerclient.Start`/`Call`:

- startup hello `{contract:1, ok:true, valid result, error:{code:"self_minted"}}` returned a non-nil client and nil error; `Close` returned nil;
- a normal hello followed by `{id:1, ok:true, result:{}, error:{code:"self_minted"}}` returned nil error; a second request was also accepted and `Close` returned nil.

Evidence: `TASK-260915-2ny9kd_review-hello-ok-true-error-rev4.log` and `TASK-260915-2ny9kd_review-response-ok-true-error-rev4.log`.

This is the **bypass path around the check** shape and repeats rev3 F1: an undeclared code is still treated as success and the session remains usable. It contradicts the rev4 claim that an undeclared error code in the hello or any response becomes `ErrProtocol`, is reaped, and leaves the client unusable.

Required rework:

1. Validate the response envelope before branching on `ok`: an `ok:true` hello or response carrying any `error` object must be `ErrProtocol`; abort/reap the process and make the client unusable. Preserve the contract's intentional `ok:false` verify response that may carry both `result.verified:false` and a declared error.
2. Add a named subprocess-entry regression covering both startup and mid-stream `ok:true + error`, with nearby controls for a valid success envelope and a declared `ok:false` refusal. Assert `ErrProtocol`, no returned client at startup, unusable client after the mid-stream case, and non-clean `Close`/reap evidence where observable.
3. Add a narrowing mutant that retains envelope/error validation but applies it only when `!resp.OK` (the current bypass); the named regression must kill it.
4. Add the repeated regression to `LOGBOOK.md` during producer rework; the reviewer did not mutate the CR candidate.

## Review evidence

- AC coverage evidence: producer reports **12 of 15 AC rows driven**; named production tests cover the 12 behavioral rows. Three process rows are docs, gates, and CR publication.
- Candidate integrity: observed snapshot tree `a94765c956e829aee3cae8817b776710c8efa2d1` equals CR rev4; patch SHA-256 equals `589290ae542c58b811533e66f2103b44d0a4dc962982e1588ef1854f3ca29514`.
- `gofmt -l` over tracked/non-ignored Go files: exit 0, no output.
- `git diff --check` for the exact CR delta: exit 0.
- `go vet ./...`: exit 0.
- `go build ./...`: exit 0.
- `go test -count=1 ./...`: exit 0.
- Targeted three-package run: exit 1 because `TestRunSignerServeAgainstLoginKeychain` returned `not_found` immediately after init. The same test then passed 5 of 5 isolated reruns. This reproduces the producer's previously recorded parallel-package Keychain listing anomaly; it is retained as an observed flake, not presented as a passing first run and not the verdict driver.
- `scripts/setup.sh:119-120` builds `mac-keyvault`; full setup was not run because it performs user-level installation/symlink mutations.
- Prefix/foreign-label guards and throwaway `test` labels remain exercised by the existing production-entry and live-Keychain tests; no reviewer probe addressed a Keychain item.

Reviewer scratch and logs are under `.temp/review-TASK-260915-2ny9kd/`; no repository candidate file was modified.
