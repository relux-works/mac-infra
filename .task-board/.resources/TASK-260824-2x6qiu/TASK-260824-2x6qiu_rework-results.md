# TASK-260824-2x6qiu developer rework evidence

## Outcome

The reviewer-requested heartbeat lifecycle gaps are closed and the candidate is
ready for another review cycle.

- `HeartbeatManager.Run` now has real-clock production-entry tests for both
  in-flight expiry paths: a probe blocked across the deadline and an interval
  sleep that is much longer than the remaining lifetime. Both tests require
  prompt return, one `bootout`, and removal of state, plist, and log.
- Stable-launcher validation now has separate negative cases for a directory
  and a non-executable regular file; neither may reach browser preflight.
- A deadline-free record that already uses the stable launcher now independently
  proves `migrationRequired=true` and strict `Load` refusal.
- Chrome and Safari start/restart use the prior 11-minute lifecycle budget. The
  budget accommodates direct plus background bounded preflights when browser
  Apple Events serialize behind an existing monitor; 90 seconds was an
  undocumented regression with less than 30 seconds of worst-case slack.
- The Flight Logbook records a separate full-suite parallel-load anomaly without
  changing the sibling fetch-file scope.

## Production call sites and negative evidence

All mutants were applied to `internal/browsersession/heartbeat.go`, tested with
`-count=1`, then restored before the final green run.

| Mutant | Production call site | Killing test | Exit |
| --- | --- | --- | ---: |
| Remove the Run-level probe deadline context and post-probe expiry check | `HeartbeatManager.Run` | `TestRunExpiresDuringProbeAtRealDeadlineAndCleansManagedState` | 1 (expected red) |
| Remove the deadline arm while waiting for the next interval | `HeartbeatManager.Run` | `TestRunExpiresDuringIntervalSleepAtRealDeadlineAndCleansManagedState` | 1 (expected red) |
| Narrow launcher rejection from regular-or-executable to regular-and-executable | `HeartbeatManager.Start` -> `validateInstalledHeartbeatLauncher` | `TestStartRefusesNonExecutableOrNonRegularStableLauncherBeforeBrowserPreflight` | 1 (expected red) |
| Treat only a legacy executable, not an absent deadline, as migration-required | `HeartbeatManager.Inspect`/`Load` -> `validateStoredConfig` | `TestStableLauncherHeartbeatWithoutDeadlineRequiresMigration` | 1 (expected red) |

Restored targeted suite: exit 0.

## Validation

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browsersession ./cmd/mac-chrome-session ./cmd/mac-safari-session ./scripts` | 0 | `go-test-heartbeat-scope-02.log` |
| `go vet ./...` | 0 | `go-vet-full-01.log` |
| `go test -count=1 ./...` | 1 | `go-test-full-01.log`; three sibling fetch-file cases timed out only under concurrent package load |
| Exact two sibling fetch-file tests, uncached and isolated | 0 | `go-test-sibling-fetch-isolated-01.log` |
| `go test -count=1 -p 1 ./...` | 0 | `go-test-full-serial-01.log` |
| `go build ./...` | 0 | `go-build-full-01.log` |
| `git diff --check` | 0 | `git-diff-check-01.log` |
| `./scripts/setup.sh` | 0 | `setup-install-01.log` |
| Installed stable launcher regular/executable + `codesign --verify --strict` | 0 | `installed-launcher-verify-01.log` |
| Installed stable launcher `heartbeat list` (no focus) | 0 | `installed-launcher-heartbeat-list-01.json` |
| Installed Safari CLI `heartbeat list` (no focus) | 0 | `installed-safari-heartbeat-list-01.json` |

The installed lists were empty, so no user heartbeat was restarted or given an
invented lifetime. Bounded runtime expiry was exercised through the real
`HeartbeatManager.Run` entry point with sub-second persisted deadlines.

The first heartbeat-scope run exited 1 because the new Chrome timeout invariant
test omitted the `time` import; this was corrected before `go-test-heartbeat-scope-02.log`.
The parallel full-suite exit 1 is retained rather than presented as passing.

## Rework files

- `internal/browsersession/heartbeat_test.go`
- `cmd/mac-chrome-session/main.go`
- `cmd/mac-chrome-session/main_test.go`
- `cmd/mac-safari-session/main.go`
- `cmd/mac-safari-session/main_test.go`
- `LOGBOOK.md`

No fetch-file production or test code was changed during this rework.
