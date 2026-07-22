# TASK-260719-cigkb7 Implementation Results

## Outcome

- Added typed daemon protocol actions `sleep_prevention_enable` and
  `sleep_prevention_disable`.
- Each action resolves inside the root daemon to one fixed, shell-free command
  plan: `/usr/bin/pmset -a disablesleep 1` or
  `/usr/bin/pmset -a disablesleep 0`.
- Added read-only `/usr/bin/pmset -g` inspection and strict parsing of exactly
  one system-wide `SleepDisabled` value.
- Added `mac-infra-core sleep-prevention enable|disable|status` with
  `sleep_prevention: enabled|disabled|unavailable` and
  `applies_to: AC,battery` output.
- Missing, malformed, duplicate, and conflicting status values return the
  explicit `unavailable` state plus a non-zero CLI error.
- Documented persistence, global AC/battery coverage, unchanged display sleep
  and other power settings, and the root-daemon reinstall requirement.

## Task-Scoped Files

- `internal/maccore/protocol.go`
- `internal/maccore/protocol_test.go`
- `internal/maccore/service.go`
- `internal/maccore/service_test.go`
- `internal/maccore/sleep_prevention.go`
- `internal/maccore/sleep_prevention_test.go`
- `cmd/mac-infra-core/main.go`
- `cmd/mac-infra-core/main_test.go`
- `README.md`
- `agents/skills/mac-infra/SKILL.md`
- `scripts/setup.sh`
- `LOGBOOK.md`

Existing audio-sweep edits in overlapping docs/setup files and all unrelated
dirty files were preserved. Nothing was staged or committed.

## Validation Evidence

| Command | Exit | Result |
| --- | ---: | --- |
| `gofmt -w` on changed Go files | 0 | formatted |
| `gofmt -l` on changed Go files | 0 | no files listed |
| `go test ./internal/maccore ./cmd/mac-infra-core` | 0 | focused tests pass |
| `go test ./...` | 0 | all repository packages pass |
| `go vet ./...` | 0 | clean |
| `go build ./...` | 0 | all commands/packages build |
| `bash -n scripts/setup.sh scripts/deinit.sh setup.sh deinit.sh` | 0 | shell syntax valid |
| `./scripts/setup.sh` | 0 | tests, all CLI builds, user symlinks, and installed skill succeeded |
| `mac-infra-core version` | 0 | installed binary smoke passed |
| `mac-infra-core help` | 0 | installed top-level help exposes sleep prevention |
| `mac-infra-core sleep-prevention --help` | 0 | installed subcommand help passed |
| `mac-infra-core sleep-prevention status` | 0 | live read-only result: enabled, applies to AC and battery |
| `mac-infra-core status` | 0 | existing daemon reachable |
| `cmp agents/skills/mac-infra/SKILL.md ~/.agents/skills/mac-infra/SKILL.md` | 0 | installed skill matches source |
| `git diff --check` | 0 | no whitespace errors in tracked diff |
| `task-board validate` | 0 | board valid |

Focused coverage evidence:

- New `internal/maccore` sleep-prevention functions: 97.1%-100% statement
  coverage (`InspectSleepPrevention`, parser, apply, plan, unavailable status).
- New CLI functions: 100% statement coverage (`runSleepPrevention`, mutation,
  usage/status rendering).
- Coverage profiles are under `.temp/TASK-260719-cigkb7/`.

The first focused test invocation exited 1 because two test-only Darwin Unix
socket paths exceeded the platform path-length limit. Only the fixture prefixes
were shortened; the exact focused command then exited 0.

## Live-Mutation Boundary

No live `enable` or `disable` smoke was run because either command writes a
persistent machine-wide power policy. Daemon integration tests execute the exact
fixed plans through a real test Unix socket and cover command failure. The
already running privileged daemon was not restarted; run
`mac-infra-core install` before the first live mutation with this build.
