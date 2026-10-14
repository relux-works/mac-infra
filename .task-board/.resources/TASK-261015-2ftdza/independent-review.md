# CORE Source Trust-Boundary Review

Verdict: **ACCEPT** for the frozen source files in `reviewed-hashes.json`. No blocking findings remain. This acceptance is source/fixture review, not approval to install or a claim that the live daemon is remediated.

Task: TASK-261015-2ftdza. Review worktree: `/Users/alexis/src/mac-infra/.temp/TASK-261015-2ftdza/worktree`.
Baseline: `809e03381351219fe2c95b4a33ed9f61727ff2a3`; 0 commits behind local main when reviewed.

## Scope and findings

Reviewed the complete tracked diff and all nine untracked production/test files, plus README/authoring skill changes and `.temp/core-trust/handoff.md`. The review freeze is the exact per-file `git hash-object` map in `.temp/core-review/reviewed-hashes.json` (16 changed files). Any source change invalidates this verdict until its changed scope is reviewed again.

- The privileged writer receives a bounded pre-elevation executable byte snapshot via stdin. It never reopens the user source pathname with root privilege. Only fixed absolute OS command paths and a fixed shell body are used; the shell destination is a positional argument inside the root-created private staging directory.
- Production directory/file validation starts at `/`, walks descriptors using openat and O_NOFOLLOW, and checks each root-owned ancestor. Group/world-writable modes, modification-grant ACLs, nonregular files, set-ID bits and multiple regular-file hardlinks fail closed. Nonblocking opens prevent FIFO hangs. Harmless deny/read-only ACLs are explicitly admitted. Unsupported native ACL builds refuse installation/startup.
- Root-private staging plus protected ancestors makes the subsequent pathname publication safe against the intended unprivileged actor. Same-filesystem checks preserve pinned inodes. Binary digest, inode/creation-time identities and complete expected plist bytes are verified before activation and again at daemon startup. This does not attest already mapped code or protect against a root adversary, as documented.
- Server admission uses kernel Unix peer credentials for the intended UID or root. Default production clients require a root peer. Socket directory names remain root-controlled even if the owner broadens the socket's file permissions. Independent client-side fixtures confirm a non-root fake server is rejected.
- Failure paths preserve prior bytes AND inode identities, and retain recovery originals when restoration fails. Independent first-install publication failure controls confirm partial final names are removed. File rollback does not restore a stopped launchd job; crash-atomic binary/plist/launchd updates are neither implemented nor claimed.
- Installation, startup and uninstall enforce fixed production scope. Stale socket cleanup rejects regular files and symlinks. Existing protocol/action tests exercise the internal fixture server while public RunDaemon retains installation admission checks.

## Independent verification

Reviewer: source-only/isolated fixtures; macOS darwin/arm64, Go 1.25.5. No sudo, install, service restart, live configuration/ACL inspection, keychain access or excluded-project inspection was performed by this review.

1. `go test -count=1 ./internal/maccore ./cmd/mac-infra-core` — PASS. `.temp/core-review/tests-01.log` (maccore 23.066s; CLI 1.024s).
2. `go test -count=1 -overlay .temp/core-review/overlay.json ./internal/maccore -run '^TestReview'` — PASS. `.temp/core-review/controls-02.log`.
   Independent overlay tests live only in `.temp/core-review/extra_review_test.go`: paired valid controls and actual isolated `writesecurity`, `chown`, `delete`, `append`, `writeextattr` ACL plants must reject for the ACL-authority reason; client-side normal-user server must reject when UID 0 is required; first-install rename failures must leave no partial final pair.
3. `GORACE=atexit_sleep_ms=0 go test -race -count=1 -overlay .temp/core-review/overlay.json ./internal/maccore -run 'Test(Review|InstalledTrust|TrustRejects|TrustAllows|InstallReviewed|InstallStaging|InstallFailure|InstallRollback|InstallRejects|ReviewedExecutable|StaleSocket|SocketPeer)'` — PASS, no race reports. `.temp/core-review/race-03.log`. Linker emitted an LC_DYSYMTAB diagnostic; build/test completed successfully. GORACE only removes the diagnostic one-second process-exit delay; race instrumentation remains active.
4. `go vet ./internal/maccore ./cmd/mac-infra-core` — PASS. `.temp/core-review/vet-04.log`.
5. `git diff --check` — PASS. `.temp/core-review/diff-check-05.log`.

Producer evidence additionally records a successful real macOS build/version smoke, unsupported-cgo refusal, full package tests/vet, and a passing full race run with the same diagnostic-exit-delay adjustment. The producer's initial default-delay race run failed helper timing expectations without race reports; it is retained as failed evidence, not presented as success.

## Acceptance limits

The initial installer/artifact must already be reviewed/authenticated by the administrator. Fixtures deliberately validate descendants of a private current-user root; they do not simulate actual root ownership, live sudo/launchd integration, privileged installation, production socket availability, or crash recovery. A separately authorized reviewed reinstall and live verification remain necessary to remediate/migrate an existing daemon. These documented boundaries are consistent with the implementation and do not block this source change.
