# TASK-260823-zwtxq3 — Reviewer rework evidence

Run: `RUN-260825-e91742`
Scope: CR revision 1 findings F1 and F2 only.

## Changes

- `internal/chromectl/slack_test.go`: the production `Session.SlackRead` test now captures the start and poll evaluations separately, asserts the start source independently, and proves the origin/workspace guards precede both the browser-secret lookup and `fetch`.
- `internal/browsersession/session_test.go`: the blocked-token contract is pinned to a literal expected list independent of `BlockedJavaScriptTokens()`.
- `cmd/mac-chrome-session/main_test.go`: the production `run()` path drives every literal blocked token and proves no refused payload reaches `osascript`.
- `LOGBOOK.md`: records the two evidence anti-patterns and their correction.

## Mutation evidence

Each expected-red command was run directly with `-count=1`; non-zero results below are intentional failures proving the narrowed production gate is detected.

| Mutant | Command | Exit | Result |
| --- | --- | ---: | --- |
| Replace only Slack start-evaluation origin and workspace guards with `if (false)`; leave poll guards intact | `go test -count=1 ./internal/chromectl -run '^TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv$'` | 1 | Named test failed because the separately captured start source lacked `location.origin !== __origin` |
| Remove `cookiestore` from `BlockedJavaScriptTokens()` | `go test -count=1 ./internal/browsersession ./cmd/mac-chrome-session -run '^(TestGuardJavaScriptRejectsEveryBlockedToken|TestRunJSProductionEntryCoversEveryBlockedToken)$'` | 1 | Literal set assertion and production CLI refusal both failed |
| Remove `opendatabase` from `BlockedJavaScriptTokens()` | same command | 1 | Literal set assertion and production CLI refusal both failed |

Production files were restored from task-scoped copies, compared byte-for-byte, and verified at:

- `internal/chromectl/slack.go`: SHA-256 `9d24561bcb72421014eb142fbe74bcba940096b0257d1222f4f0bc1b7d56015f`
- `internal/browsersession/session.go`: SHA-256 `b04be005c4f6d985e9b9748bf9a7bb0425f5588c35f706acf846d253be2492c9`

## Green validation after restore

| Command | Exit | Result |
| --- | ---: | --- |
| Narrow three-test rework suite across `internal/browsersession`, `internal/chromectl`, and `cmd/mac-chrome-session` | 0 | All three packages passed |
| `go test -count=1 ./...` | 0 | All 28 packages passed |
| `go vet ./...` | 0 | Clean |
| `go build ./...` | 0 | Clean |
| `gofmt -l cmd/**/*.go internal/**/*.go scripts/**/*.go` | 0 | Empty output |
| Scoped gofmt empty-output assertion | 0 | Clean |
| `git diff --check` | 0 | Clean |

Diagnostic disclosure: `gofmt -l .` exited 0 but listed one unrelated sibling-task scratch mutant under `.temp/TASK-260823-17qhsl-review4/`; it is gitignored and outside production source. The scoped production-source lint above is the clean gate. A separate `git diff --check --no-index /dev/null <untracked file>` diagnostic exited 1 solely because `--no-index` reports the new file itself as a difference; it emitted no whitespace diagnostic and was not counted as a passing gate.

## Live-state preservation

No browser, LaunchAgent, named heartbeat, installed binary, or authenticated session was touched during this test-only rework. Revision 1 live evidence and the independent reviewer attacks remain applicable; this run did not repeat stateful smokes merely to validate test-fixture changes.
