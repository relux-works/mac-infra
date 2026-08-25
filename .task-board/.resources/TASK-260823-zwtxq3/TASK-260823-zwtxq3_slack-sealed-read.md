# TASK-260823-zwtxq3 — Slack sealed-read continuation

Date: 2026-08-25 MSK
Run: RUN-260825-ebdd72

## Outcome

Added `mac-chrome-session slack-read`, a compiled allowlisted Slack Web read
primitive over the existing exact-target Chrome runtime.

- Accepts one versioned request envelope over bounded stdin.
- Allows only `auth.test` and `conversations.list`.
- Rejects writes, unknown methods/arguments, invalid origins/workspaces,
  oversized input/output, malformed responses, excessive JSON depth/complexity,
  and target/origin/workspace drift.
- Checks the exact Chrome target, `https://app.slack.com`, and
  `/client/<workspace-id>` in the same page evaluation that locates the selected
  workspace's supported `localConfig_v2` web token and starts the request.
- Keeps token material in Slack page context. It is never returned, printed,
  logged, persisted, or placed in argv/environment.
- Recursively redacts secret-bearing response keys, Slack/Bearer/JWT-shaped
  values, sensitive URL query values, URL credentials, and fragments.
- Leaves generic `run-js` guards unchanged; caller JavaScript still cannot read
  `localStorage`, cookies, authorization data, or tokens.

Production entry: `cmd/mac-chrome-session.runSlackRead` ->
`internal/chromectl.Session.SlackRead`.

## Negative evidence

- `TestSlackReadProductionEntryRejectsWritesAndInvalidGuardsBeforeExecution`
  drives the CLI and proves writes, unknown methods, wrong origin, and malformed
  workspace identifiers never reach `osascript`.
- `TestRunJSProductionEntryCoversEveryBlockedToken` drives generic `run-js` and
  still rejects every blocked storage/credential token.
- `TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv` proves the
  exact target, origin/workspace checks, token lookup, and fetch are one injected
  source; silent JXA contains no focus operation and request/schema data is not
  in argv.
- `TestSlackReadOriginAndWorkspaceDriftFailBeforePolling` proves both guard
  refusals dispatch no follow-up poll.
- `TestSlackReadMissingStorageSchemaFailsCapabilityUnavailable` proves schema
  absence cannot fall back to credential export.
- `TestSlackReadRefusesMalformedPendingTimeoutAndMissingTarget` covers forged or
  malformed envelopes, bounded timeout, and exact-target disappearance.
- `TestSlackReadProductionPathRecursivelyRedactsSecrets` fails if the recursive
  key/value/URL policy is narrowed to admit tested Slack, Bearer, JWT, API-key,
  query, or fragment shapes.
- `TestSanitizeSlackResponseBoundsDepthAndSize` covers response depth and size.

## Validation

Each command ran directly and returned the recorded real exit code.

| Command | Exit | Result |
| --- | ---: | --- |
| `gofmt` cleanliness gate | 0 | clean |
| `go test -count=1 ./...` | 0 | all packages green |
| `go vet ./...` | 0 | clean |
| `go build ./...` | 0 | build green |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | shell syntax green |
| `git diff --check` | 0 | clean |
| `bash scripts/setup.sh` | 0 | signed CLI and skill installed |
| `codesign --verify --strict bin/mac-chrome-session` | 0 | signature valid |
| installed help contains `slack-read` | 0 | command exposed |
| source/installed mac-infra skill diff | 0 | identical |

## Live smoke

Authorized test workspace: `T073GL82HJB`. The exact Slack Chrome tab was
re-enumerated before each live sequence. No browser was focused, navigated,
reloaded, closed, or reordered.

| Gate | Exit | Persisted evidence |
| --- | ---: | --- |
| sealed `auth.test` | 0 | booleans only: transport/API/workspace matched |
| sealed `conversations.list(limit=1)` | 0 | booleans plus `channel_count=1`; no channel/user/message fields |
| wrong-workspace refusal | 1 (expected red) | stable `workspace-mismatch`; no request started |
| generic `run-js localStorage` refusal | 1 (expected red) | blocked before Apple Events |

`lsappinfo front` snapshots before/after the final installed smokes were byte
identical. Managed heartbeat status was also unchanged:

- `mos-sud-court-session`: `running`
- `tbank-support`: `running`
- `tbank-retail`: `drifted` before and after this continuation

Private topology/process/frontmost snapshots remain under
`.temp/TASK-260823-zwtxq3/slack-live/` and are intentionally not attached; they
may contain user-owned browser/process metadata. No Slack response content was
persisted.

## Files in this continuation

- `internal/chromectl/slack.go`
- `internal/chromectl/slack_test.go`
- `cmd/mac-chrome-session/main.go`
- `cmd/mac-chrome-session/main_test.go`
- `README.md`
- `agents/skills/mac-infra/SKILL.md`
- `agents/skills/mac-infra/references/chrome-session.md`
- `LOGBOOK.md`

The worktree also contains separate Story sibling changes for
`TASK-260823-17qhsl`; this continuation did not edit its browser facade/query
implementation files.
