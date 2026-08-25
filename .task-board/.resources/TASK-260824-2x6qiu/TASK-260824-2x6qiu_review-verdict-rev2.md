# TASK-260824-2x6qiu — Reviewer verdict: ACCEPTED

- Reviewer run: `RUN-260825-1027f1`
- Change Request: `CR-TASK-260824-2x6qiu-2` revision `2` (`repository_delta=present`)
- Base OID: `fa43cb316036b0b20bed8906417ab97e408fea4b`
- Candidate tree OID: `013d2426ed381d48ea4251f0c6ca640b27362160`
- Companion evidence: `TASK-260824-2x6qiu_review-mutants.log`

Revision 2 closes both blocking findings from the rev1 review
(`RUN-260825-b9688a`): the wall-clock expiry arms in `Run` are now pinned by
real-clock tests, and the heartbeat lifecycle budget is back at 11 minutes with
a test that fails if it moves.

## Acceptance criteria — verified

### 1. One stable installed launcher identity across Chrome and Safari rebuilds

`HeartbeatManager.NewConfig` no longer takes an executable from the caller; it
always writes `m.LauncherPath()` =
`~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`
(`internal/browsersession/heartbeat.go:135`, `:170`). The content-addressed
`pinExecutable` path is gone. `RenderHeartbeatLaunchAgent` refuses anything but
that exact path, and both CLIs route through the same manager, so a Safari
heartbeat and a Chrome heartbeat install the same `ProgramArguments[0]`.

### 2. Ordinary rebuilds do not create a new App Background Activity identity

This is the load-bearing claim, so it was measured rather than read. Ad-hoc
`codesign` derives the designated requirement from the cdhash unless an explicit
requirement is supplied, and the cdhash changes on every build.

Two distinct builds of `cmd/mac-chrome-session` (differing only by
`-ldflags -X main.Version`), signed the way each tree signs them:

| Tree | Build | Designated requirement |
| --- | --- | --- |
| base `fa43cb3` | v1 | `designated => cdhash H"1312eeb150cc8fc3ec3c9976c07e93cefa882d10"` |
| base `fa43cb3` | v2 | `designated => cdhash H"51893f840bf9900c802648422f4444c8fba66f4e"` |
| candidate | v1 | `designated => identifier "works.relux.mac-infra.browser-session"` |
| candidate | v2 | `designated => identifier "works.relux.mac-infra.browser-session"` |

The two candidate binaries have different content hashes
(`ae07e4ae3062b6e5…` vs `81946d3d7cb5fe99…`) and the same identity. Base changes
identity on every rebuild; the candidate does not. Combined with the stable
`ProgramArguments` path and a stable `Label`, an ordinary rebuild no longer
presents macOS with a new background item.

`scripts/setup.sh`'s own guard was attacked directly, not just grepped: feeding
it the base-style (cdhash) signature makes
`[[ "$OBSERVED" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]` fire, and the
candidate-style signature passes. Removing `--requirements` from the signing
line is additionally caught by `TestSetupBuildsAndInstallsChromeSessionCLI`
during setup's own test step.

### 3. Heartbeat start requires a finite deadline/TTL

`ResolveDeadline` enforces exactly-one-of `--ttl`/`--deadline`, RFC3339 parsing,
future-ness and an RFC3339-representable year; `NewConfig` re-checks. Both
production entry points (`cmd/mac-chrome-session/main.go` `heartbeatStart`,
`heartbeatRestart`; the same two in `cmd/mac-safari-session/main.go`) call it
before any browser contact. Defaulting `--ttl` to 8h in both CLIs is killed by
`TestHeartbeatStartProductionEntryRequiresFiniteDeadline` and
`TestSafariHeartbeatStartProductionEntryRequiresFiniteDeadline`; accepting both
flags at once is killed by `TestDeadlineGateRejectsMissingAmbiguousAndExpiredInputs/ambiguous`.

### 4. Expired heartbeats boot out and remove managed state/plist without browser focus

`expire()` removes plist, state and private log, then `launchctl bootout`s the
job, tolerating an already-absent service. It is reached from three places, each
independently pinned:

- `Run` before the probe — `TestRunRefusesExpiredHeartbeatBeforeBrowserProbeAndCleansState` (M6 killed)
- `Run` during the interval sleep — `TestRunExpiresDuringIntervalSleepAtRealDeadlineAndCleansManagedState`, real wall clock, `--interval 20m` against a 500ms deadline, 2s bound (M5b killed)
- `Inspect`/`List` — `TestInspectExpiresHeartbeatAndCleansManagedArtifactsWithoutBrowserProbe` (M7 killed)

Both `Run` tests and the `Inspect` test assert the probe count, so the expiry
path is proven to dispatch no Apple Event at all — no focus, no window raise.

### 5. Status/list expose deadline and expiry

`HeartbeatStatus` gains `deadline`, `expired` and `migrationRequired`; `Inspect`
populates them and adds the `expired` and `migration-required` states with
`errorKind` `deadline-expired` / `legacy-launcher` / `missing-deadline`.

### 6. Existing heartbeats can be migrated or restarted safely

`loadStored` classifies legacy (content-addressed launcher or absent deadline)
state as migration-required instead of failing, so `Stop`, `Inspect` and
`GarbageCollectExecutables` still work on it, while the strict `Load` used by
`Run` refuses it. `Restart` rebuilds the config on the stable launcher with the
new deadline, preflights the replacement target *before* stopping the old job,
and garbage-collects the old pinned copy.
`TestRestartPreflightRefusalPreservesExistingHeartbeat` proves a refused restart
boots out nothing and leaves deadline, executable and all three artifacts
untouched.

### 7. Tests and installed smoke pass

Candidate tree materialised with `git archive` and validated on a non-symlinked
path:

| Check | Result |
| --- | --- |
| `gofmt -l .` | clean |
| `go build ./...` | clean |
| `go vet ./...` | clean |
| `go test -count=1 ./...` | all packages ok |

(The same tree under `/tmp` shows 6 failures in `internal/cleanup` and
`cmd/mac-cleanup` — `cleanup root realpath escapes the requested root`, caused by
macOS `/tmp` → `/private/tmp`. Identical code passes those packages in the
worktree, so it is environmental and unrelated.)

**Installed smoke** — `scripts/setup.sh` run against the candidate tree with a
sandboxed `HOME`, then the *installed* `mac-chrome-session` driven directly:

| Command | Observed |
| --- | --- |
| `setup.sh` | installs `…/browser-session/bin/mac-browser-heartbeat-launcher`, mode `-rwx------`, `designated => identifier "works.relux.mac-infra.browser-session"`, `codesign --verify --strict` clean |
| `heartbeat start` (no `--ttl`/`--deadline`) | exit 2, `heartbeat requires exactly one of a positive --ttl or --deadline` |
| `heartbeat start --ttl 1h --deadline 2030-…` | exit 2, same refusal |
| `heartbeat start --deadline 2020-01-01T00:00:00Z` | exit 2, `heartbeat deadline must be a finite future time` |
| `heartbeat run --name expired-run` (deadline 2020) | exit 0, state + plist + log removed, absent launchd service tolerated, no Chrome contact |
| `heartbeat status --name expired-status` | `state=expired`, `expired=true`, `errorKind=deadline-expired`, artifacts cleaned, no browser probe |
| `heartbeat status` / `list` on legacy state | `state=migration-required`, `migrationRequired=true`, `errorKind=missing-deadline`; legacy pinned copy preserved for the restart path |

All three refusals returned instantly and no browser was launched, focused or
prompted at any point.

`scripts/deinit.sh` drops the pinned-binary term from its precondition (the
stable launcher is not a stranding risk on its own) but now re-globs
`heartbeat_states` in the post-stop assertion, which the previous version had
dropped, and `rm -rf "$BROWSER_STATE_DIR"` removes the launcher.
`TestDeinitStopsManagedHeartbeatsBeforeRemovingCLI` asserts it.

## Non-blocking findings

None of these admit anything the gates must reject; recording them so the
information is not lost.

1. **`NewConfig` past-deadline clause is untested** (M1 survived). Narrowing
   `deadline.IsZero() || !deadline.After(m.now())` to `deadline.IsZero()` keeps
   the suite green. Both production callers run `ResolveDeadline` first and that
   *is* pinned, so there is no reachable bypass — this is defence in depth only.

2. **`Run`'s post-probe expiry re-check is untested** (M5 survived). Deleting it
   leaves the deadline enforced by the `runCtx` bound (pinned) and the
   sleep-window arm (pinned); the only difference is one extra outcome line
   appended to a log `expire()` immediately deletes. Worth noting that
   `TestRunExpiresDuringProbeAtRealDeadlineAndCleansManagedState` pins the probe
   *bound*, not the clause its name suggests.

3. **`Start`'s `validateConfig` call is untested** (M11 survived). Every
   production caller builds the config through `NewConfig`, and
   `RenderHeartbeatLaunchAgent` still refuses a non-stable executable inside
   `Start`.

4. **`isMissingLaunchAgent` matches the bare substring `113`** — pre-existing and
   byte-identical at base (`fa43cb3:internal/browsersession/heartbeat.go:777`),
   but `expire()` is a new caller with inverted ordering. `runLaunchctl` formats
   errors as `launchctl <args>: <output>` and `<args>` carries
   `gui/<uid>/works.relux.mac-infra-browser-heartbeat.<name>`; heartbeat names
   match `[a-z0-9][a-z0-9-]{0,47}`, so `hb113` is legal. A probe test confirmed
   `launchctl bootout gui/501/…heartbeat.hb113: Operation not permitted…` is
   classified as "service missing". Because `expire()` removes the plist and
   state *before* bootout, a swallowed genuine failure leaves a loaded KeepAlive
   job with no plist — a throttled respawn loop until logout — instead of
   surfacing an error. Suggest a follow-up bug on the story: match
   `exit status 113` / launchd's error token rather than a bare `113`.

5. **Safari `heartbeat restart` on an expired heartbeat reports a raw ENOENT.**
   `requireSafariHeartbeat` calls `Inspect` first, which expires and deletes the
   state; the following `Restart` → `loadStored` then fails with
   `no such file or directory`. Chrome's `restart` has no `Inspect` precheck and
   renews an expired heartbeat cleanly. Cosmetic asymmetry, not a correctness
   defect.

## Structural note for the orchestrator

The candidate tree is a snapshot of the shared story worktree, so it bundles
in-flight sibling work whose own board items are **not accepted**:

- `internal/chromectl/fetch_file.go`, `fetch_file_test.go`,
  `cmd/mac-chrome-session/fetch_file_test.go` → `BUG-260825-2s6iw4` (`to-dev`)
- `internal/chromectl/trusted_input.go`, `trusted_input_test.go`,
  `ax_darwin.go`, `ax_darwin.m`, `ax_darwin_test.go`, `ax_unsupported.go`,
  the `focus` origin/`--human-authorized` rework → `BUG-260825-1wsh7n` (`to-dev`)
- the `RedactSensitiveURL` rewrite in `internal/browsersession/session.go`

None of that was reviewed here and none of it is part of this task's scope.
This acceptance covers the heartbeat identity/deadline scope only:
`internal/browsersession/heartbeat.go` + `heartbeat_test.go`, the heartbeat
subcommands in both CLIs and their tests, `scripts/setup.sh`,
`scripts/deinit.sh`, `scripts/deinit_test.go`, and the heartbeat sections of
`README.md` and the `mac-infra` skill references. Do not integrate the whole
tree as this task's accepted scope.

The worktree has also drifted past the snapshot since it was taken (further
`fetch-file` work in `cmd/mac-safari-session/main.go` and `main_test.go`, and a
new guard-sentinel test in `internal/browsersession/session_test.go`). No
heartbeat-scope file differs between the candidate tree and the worktree.

## Verdict

**ACCEPTED.** Every acceptance criterion is met and independently verified
against the composed, installed artifact — not only against the source. All ten
gate mutants that could make a gate admit what it must reject were killed; the
three survivors are redundant second layers with no reachable bypass.
