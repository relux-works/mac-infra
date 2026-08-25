# TASK-260824-2x6qiu developer evidence

## Delivered behavior

- All Chrome and Safari heartbeat LaunchAgents render the single installed executable `~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`.
- `scripts/setup.sh` atomically replaces that signed launcher while preserving the designated requirement `works.relux.mac-infra.browser-session`.
- `heartbeat start` requires exactly one positive `--ttl` or future RFC3339 `--deadline`.
- `Run`, `status`, and `list` enforce expiry. Expiry removes plist/state/log before self-`bootout` and dispatches no browser probe.
- Status JSON exposes `deadline`, `expired`, `migrationRequired`, and the `expired` / `migration-required` states.
- `heartbeat restart --name ... --ttl|--deadline` preflights the existing target before stop, migrates legacy content-addressed/deadline-free state, and garbage-collects the old pinned copy.
- Restart preflight refusal preserves the existing loaded configuration and artifacts.
- README, Chrome/Safari skill references, setup/deinit, and LOGBOOK were updated.

## Validation evidence

| Command | Exit | Result |
| --- | ---: | --- |
| `go test -count=1 ./internal/browsersession ./cmd/mac-chrome-session ./cmd/mac-safari-session ./scripts` | 0 | Targeted source lifecycle suites passed. |
| `go test -count=1 -p 1 ./...` | 0 | Full uncached suite passed serially. |
| `go vet ./...` | 0 | Vet clean. |
| `go build ./...` | 0 | All Go packages build. |
| `gofmt -l <changed Go files>` | 0 | No files reported. |
| `bash -n scripts/setup.sh scripts/deinit.sh` | 0 | Lifecycle scripts parse. |
| `git diff --check` | 0 | No whitespace errors. |
| `./scripts/setup.sh` | 0 | Full suite, builds, signatures, stable launcher install, symlinks, and skill sync passed. |
| `codesign --verify --strict <stable-launcher>` | 0 | Installed launcher signature verified. |
| `codesign -d -r- <stable-launcher>` | 0 | Requirement is `designated => identifier "works.relux.mac-infra.browser-session"`. |
| installed stable launcher `heartbeat run --name task-260824-smoke` | 0 | Bounded absent-state runtime exits without browser access. |
| installed `heartbeat status --name task-260824-smoke` | 0 | Reports `not-configured`, `expired:false`; no browser access. |
| installed `heartbeat list` | 0 | Reports five existing legacy records as `migration-required` / `missing-deadline`; no state was changed. |
| `diff -qr agents/skills/mac-infra ~/.agents/skills/mac-infra` | 0 | Installed skill matches source. |
| `wc -l agents/skills/mac-infra/SKILL.md` | 0 | Router is 496 lines, below the 500-line skill limit. |

An initial parallel uncached `go test -count=1 ./...` exited 1 because three unrelated fetch-file tests hit their 5-second test timeout under full parallel load. Each named failing production test was rerun directly and passed with exit 0. The final full suite was rerun uncached with `-p 1` and passed with exit 0.

The installed negative smoke `heartbeat start ...` without TTL/deadline exited 2 with the expected finite-deadline refusal. This is an expected-red refusal, not a passing command.

After compressing duplicated browser guidance into the existing lazy references, `scripts/setup.sh` was rerun with exit 0 and source/installed skill parity was rechecked with exit 0.

## Negative/mutation evidence

Each mutant was applied to the production call site, run with `-count=1`, then restored from a task-scoped copy and verified byte-for-byte before the final green suites.

| Narrowed production gate | Named test | Expected exit | Observed failure |
| --- | --- | ---: | --- |
| Allowed missing deadline within a one-minute grace in `HeartbeatManager.ResolveDeadline` / `NewConfig` | `TestHeartbeatStartProductionEntryRequiresFiniteDeadline` | 1 | Missing deadline reached Chrome preflight. |
| Re-admitted legacy `mac-browser-session-*` paths in `RenderHeartbeatLaunchAgent` | `TestRenderLaunchAgentRejectsLegacyContentAddressedExecutable` | 1 | Legacy content-addressed executable rendered. |
| Changed expiry boundary from `now >= deadline` to `now > deadline` in `Inspect` / `Run` | `TestInspectExpiresHeartbeatAndCleansManagedArtifactsWithoutBrowserProbe`, `TestRunRefusesExpiredHeartbeatBeforeBrowserProbeAndCleansState` | 1 | Status became unavailable instead of expired and runtime dispatched one browser probe. |

## Installed-state note

The installed no-focus list found five existing deadline-free Chrome heartbeat records. They were intentionally not auto-restarted because selecting lifetimes for user sessions is not a safe smoke-test assumption. The new explicit restart path is installed and covered through the real CLI/core entry points.
