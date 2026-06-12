# AnyConnect Cleanup Tooling Implementation Results

Story: STORY-260612-27st48
Tasks:

- TASK-260612-3rp8vs Diagnose disconnected AnyConnect socket-filter load
- TASK-260612-2ni3yo Design AnyConnect cleanup plan and safety contract
- TASK-260612-2myu4n Add mac-infra-core AnyConnect cleanup action
- TASK-260612-1n2zkp Wire AnyConnect cleanup CLI, docs, and skill

## Implemented

- Added `internal/anyconnect` with parsers/formatters for:
  - Cisco VPN state
  - Cisco socket-filter system extension state
  - `acsockext` and `vpnagentd` process groups
  - suspicious disconnected-state CPU/RSS detection
- Added read-only CLI:
  - `mac-load-profile anyconnect`
  - `mac-load-profile anyconnect --logs`
- Added core cleanup CLI:
  - `mac-infra-core anyconnect-cleanup`
  - `mac-infra-core anyconnect-cleanup --apply`
  - `mac-infra-core anyconnect-cleanup --apply --force`
- Added allowlisted daemon action:
  - `cleanup_anyconnect`
  - guarded by `vpn status == Disconnected` unless `force` is true
  - hardcoded commands only; no shell, no generic command runner
- Updated `README.md` and `agents/skills/mac-infra/SKILL.md`.
- Added logbook entry.

## Validation

- `go test ./internal/anyconnect ./cmd/mac-load-profile ./cmd/mac-infra-core ./internal/maccore`: passed
- `go test ./...`: passed
- `git diff --check`: passed
- `go run ./cmd/mac-load-profile anyconnect`: passed
- `go run ./cmd/mac-infra-core anyconnect-cleanup`: passed
- `./scripts/setup.sh`: passed and installed user-level binaries/skill
- installed `mac-load-profile anyconnect`: passed
- installed `mac-infra-core anyconnect-cleanup`: passed

## Live State

The installed read-only diagnostic reported:

- `vpn_state: disconnected`
- `socket_filter_extension: com.cisco.anyconnect.macos.acsockext team=DE8Y96K9QP state=activated enabled`
- `socket_filter_processes: 1`
- `acsockext` RSS around `869 MB`
- `vpnagentd_processes: 1`

## Live Cleanup Blocker

`mac-infra-core install` could not update the root daemon because sudo credentials were not cached and this shell could not prompt:

```text
sudo: a terminal is required to read the password
install failed: sudo authentication: exit status 1
```

Because the running daemon is still old, installed `mac-infra-core anyconnect-cleanup --apply` returns:

```text
anyconnect-cleanup failed: unsupported mac-infra-core action "cleanup_anyconnect"
```

Next live apply step from an interactive shell:

```bash
mac-infra-core request-permissions sudo
mac-infra-core install
mac-infra-core anyconnect-cleanup --apply
mac-load-profile anyconnect
```
