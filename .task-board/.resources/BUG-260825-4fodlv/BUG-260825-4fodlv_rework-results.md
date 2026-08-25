# BUG-260825-4fodlv rework results

## Candidate

- Story candidate HEAD: `95833153ca6e2165a51f628800fcd8ff9c99e93e`.
- Task delta against HEAD: `LOGBOOK.md`, `internal/chromectl/slack.go`, `internal/chromectl/slack_test.go`, and `cmd/mac-chrome-session/main_test.go`.
- Production call site: `internal/chromectl.Session.SlackRead` -> `sanitizeSlackResponse` -> `decodeSanitizedSlackValue`.

## Rework

- Replaced the lossy response `map[string]any` decode with a recursive `json.Decoder.Token` walk that consumes object members in source order.
- Counts every raw JSON value before materialization, including values belonging to duplicate members and structured-secret branches.
- Sanitizes keys before insertion, preserves safe keys byte-for-byte, and records decoded/normalized collisions without overwriting the first value.
- Continues consuming a colliding object so an oversized duplicate-member response reaches the raw-node refusal rather than collapsing to one map entry.
- Applies the same collision and bound logic at every nested object level.
- Added the 2026-08-26 0529 logbook entry `JSON Maps Are Too Late for Duplicate-Key Gates`.

## Negative production evidence

The new tests first ran against the pre-fix production path and failed with exit 1. `Session.SlackRead` and `runSlackRead` both admitted identical and escape-equivalent duplicate secret-shaped keys, retained only the last value, and admitted 20,001 duplicate members as one node.

Added named production-path coverage:

- `TestSlackReadProductionPathFailsClosedOnIdenticalDuplicateSecretShapedKeys`
- `TestSlackReadProductionPathFailsClosedOnEquivalentEscapedDuplicateKeys`
- `TestSlackReadProductionPathFailsClosedOnNestedDuplicateSecretShapedKeys`
- `TestSlackReadProductionPathCountsDuplicateMembersAgainstRawNodeBound`
- `TestSlackReadProductionEntryFailsClosedOnDuplicateMembersWithoutLeakingResponseMaterial`

The CLI test asserts the stable bounded error envelope and absence of original keys and values.

Two narrowing mutants ran with `-count=1` and failed as required:

| Mutant | Exit | Killed by |
| --- | ---: | --- |
| Detect collisions only below the root object (`depth > 0`) | 1 (expected red) | Identical and escape-equivalent duplicate-key production tests |
| Widen the raw-node refusal by two nodes | 1 (expected red) | Duplicate-member raw-node production test; observed result narrowed to `response-key-collision` instead of `response-too-complex` |

`internal/chromectl/slack.go` was restored from `.temp/BUG-260825-4fodlv/slack.go.before-mutants`; `cmp` exited 0 after each restoration and before final gates.

## Validation

Every gate was run directly as a standalone foreground process.

| Command | Exit | Result |
| --- | ---: | --- |
| Focused new `Session.SlackRead` and `runSlackRead` tests with `-count=1` | 0 | Pass |
| All Slack tests in `internal/chromectl` and `cmd/mac-chrome-session` with `-count=1` | 0 | Pass |
| `go test -count=1 ./...` | 0 | Full uncached suite passed |
| `go vet ./...` | 0 | No diagnostics |
| `go build ./...` | 0 | All packages built |
| `gofmt -l` plus empty-output assertion on changed Go files | 0 / 0 | No unformatted files |
| `git diff --check HEAD` | 0 | No whitespace errors |
| `./scripts/setup.sh` | 0 | Tests, builds, signing, stable launcher install, CLI symlinks, and skill refresh passed |
| `mac-chrome-session version` | 0 | Installed binary reports `v0.1.0-32-g9583315` (HEAD-based version label) |
| `mac-chrome-session list` | 0 | Silent no-focus enumeration passed; 15 sanitized tabs, zero exact Slack targets |

Logs are under `.temp/BUG-260825-4fodlv/`.

## Live-smoke honesty

A new count-only Slack read was not run because silent enumeration found no exact `https://app.slack.com/client/<workspace>` target. The Chrome-session contract forbids navigating, focusing, or replacing a borrowed user tab to manufacture one. The earlier attached `BUG-260825-4fodlv_results.md` retains the previous successful count-only smoke, but this rework does not claim it as current-candidate evidence. No Slack write or browser-state mutation occurred.
