# BUG-260825-4fodlv developer evidence

## Outcome

- `Session.SlackRead` recursively sanitizes JSON object keys through the same bounded string sanitizer used for values.
- Safe keys remain byte-for-byte stable.
- If two keys normalize to the same redacted key, the response fails closed with `response-key-collision`; no partial data or original key/value material reaches the CLI envelope.
- Existing response byte, depth, node, and linear-cost bounds remain in force.
- README documents key redaction and collision refusal.

Production call sites covered:

- `internal/chromectl.Session.SlackRead` -> `sanitizeSlackResponse` -> `sanitizeSlackValue`
- `cmd/mac-chrome-session.runSlackRead` versioned stdout envelope

## Tests and negative evidence

- Initial focused regression run: exit 1 as expected. Raw nested Slack/Bearer/JWT keys crossed `Session.SlackRead`, collision inputs returned success, and the response-ceiling key remained raw.
- Final focused production-path run: exit 0 for nested key classes/occurrences, safe-key stability, collision refusal, response-ceiling cost, sanitized CLI success envelope, and non-leaking CLI collision envelope.
- Nested-depth narrowing mutant: exit 1 as expected; sanitizing only depth 0 exposed all nested secret-shaped keys.
- Secret-class narrowing mutant: exit 1 as expected; sanitizing only keys with an xox/xapp match exposed Bearer-only and JWT-only keys.
- Collision narrowing mutant: exit 1 as expected; refusing only an exact `[redacted]` collision allowed two prefixed secret-shaped keys to overwrite one value.
- Every mutant ran with `go test -count=1`; source was restored from a task-scoped copy and verified byte-for-byte after each run.

## Validation

| Command | Exit | Result |
| --- | ---: | --- |
| Focused `go test -count=1` for new internal/CLI production tests | 0 | pass |
| `go test -count=1 ./...` | 0 | pass |
| `go vet ./...` | 0 | pass |
| `go build ./...` | 0 | pass |
| `./scripts/setup.sh` | 0 | pass; tests, builds, signing, install and symlinks succeeded |
| `gofmt -l` on changed Go files | 0 | no output |
| `git diff --check HEAD --` on task files | 0 | pass |
| `mac-chrome-session version` | 0 | installed CLI ready |
| `mac-chrome-session list` | 0 | silent exact Slack target resolved |
| Count-only sealed `conversations.list` smoke projected through `jq` with `pipefail` | 0 | `{version:1, ok:true, method:"conversations.list", count:1, has_more:true}` |

The preliminary readiness probe `mac-chrome-session --version` exited 2 because this CLI uses the `version` subcommand; the corrected readiness command exited 0. No live Slack write was issued. The live response was projected in-process to count/boolean fields and was not persisted.

## Concurrent Story checkpoint

During validation, the shared Story branch advanced to commit `207c321` (`BUG-260825-3ewejy: redact Slack response keys`). That checkpoint captured the sanitizer, README, internal production tests, and the existing first CLI key-redaction assertion. It later advanced through `9ae4c11` and `1d7045c`; the latter captured this run's remaining CLI-level collision refusal/non-leak test and fake-response helper. This run did not stage or commit files. The final BUG-260825-4fodlv handoff therefore has an empty repository delta because the concurrent duplicate workflow already checkpointed the validated combined tree.

The root cause and contract decision are already recorded in `LOGBOOK.md` under `Slack Response Keys Need Their Own Secret Boundary`.
