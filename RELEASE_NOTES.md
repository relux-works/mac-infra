# Release Notes

## Unreleased - fseventsd bloat diagnostics, guarded restart, and watchdog

### Highlights

- Added `mac-load-profile fsevents` for read-only fseventsd diagnostics without sudo:
  - fseventsd pid/RSS/CPU/elapsed against warn/critical thresholds
  - known FSEvents consumers and event generators (Colima `--inotify` daemon, Spotlight, Time Machine, iCloud Drive, git fsmonitor, watchman, sync agents, running `go test`)
  - `~/.colima/*/colima.yaml` `mountInotify` and `mounts` findings
  - `go-build*` leftover size under the temp dir
  - `--json` output
- Added `mac-infra-core fseventsd-restart`: allowlisted daemon action `launchctl kickstart -k system/com.apple.fseventsd`, refused below the RSS threshold (default 4 GB) unless `--force`, with before/after pid and RSS.
- Added `mac-infra-core fseventsd-watchdog enable|disable|status`: current-user LaunchAgent `works.relux.mac-infra-fseventsd-watchdog` that checks fseventsd on an interval (default 10m), notifies over the threshold with a cooldown, and restarts only with opt-in `--auto-restart`.

### Operational notes

- `mac-infra-core fseventsd-restart` and `fseventsd-watchdog --auto-restart` require the installed root daemon to be updated from this build (`mac-infra-core install`).
- Watchdog settings live in `~/Library/Application Support/mac-infra/fseventsd-watchdog.json`; the plist carries only the fixed check verb and state path.
- Nothing in this release renices or throttles fseventsd; a starved daemon drops events and forces client rescans.

## v0.1.0 - Mac maintenance cleanup and AnyConnect tooling

Tag: `v0.1.0`

This release ships the current mac-infra workstation maintenance toolchain, including safe cleanup planning improvements, CoreSimulator runtime cleanup, explicit sudo-permission guidance, and Cisco AnyConnect socket-filter diagnostics/cleanup tooling.

### Highlights

- Added `mac-cleanup xcode-runtimes` for unsupported CoreSimulator runtime detection and explicit `--delete` cleanup.
- Added `mac-infra-core request-permissions sudo` so agents request sudo through the core tool instead of ad hoc shell commands.
- Added `mac-load-profile anyconnect` for read-only Cisco AnyConnect diagnostics:
  - VPN connected/disconnected state
  - `com.cisco.anyconnect.macos.acsockext` process CPU/RSS
  - `vpnagentd` process CPU/RSS
  - socket-filter system extension activation state
  - optional bounded `--logs` hints
- Added `mac-infra-core anyconnect-cleanup` dry-run and `--apply` path:
  - verifies AnyConnect is disconnected by default
  - terminates the Cisco socket-filter extension process
  - restarts `com.cisco.anyconnect.vpnagentd`
  - uses allowlisted daemon actions only; no generic command runner

### Operational notes

- `mac-infra-core anyconnect-cleanup` is dry-run by default.
- `mac-infra-core anyconnect-cleanup --apply` requires the installed root daemon to be updated from this release.
- If daemon install needs sudo in an interactive shell:

```bash
mac-infra-core request-permissions sudo
mac-infra-core install
```

### Validation performed for this release

```bash
go test ./internal/anyconnect ./cmd/mac-load-profile ./cmd/mac-infra-core ./internal/maccore
go test ./...
git diff --check
go run ./cmd/mac-load-profile anyconnect
go run ./cmd/mac-infra-core anyconnect-cleanup
./scripts/setup.sh
mac-load-profile anyconnect
mac-infra-core anyconnect-cleanup
```

Live root-daemon update note:

- user-level binaries and skill installed successfully
- `mac-infra-core install` could not update the root daemon from the non-interactive shell because sudo credentials were not cached
- until daemon reinstall runs from an interactive shell, `mac-infra-core anyconnect-cleanup --apply` reports unsupported daemon action
