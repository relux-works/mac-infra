# TASK-260915-1b1uf5: add-core-fseventsd-restart-action

## Description
Add mac-infra-core fseventsd-restart: allowlisted root-daemon action running launchctl kickstart -k system/com.apple.fseventsd. CLI refuses unless fseventsd RSS exceeds threshold (default 4 GB) or --force is given; prints before/after pid and RSS.

## Scope
cmd/mac-infra-core, internal daemon action allowlist

## Acceptance Criteria
Daemon exposes only the fixed action; below-threshold call is refused with a clear message; --force overrides; tests cover refusal, force, and daemon-unreachable
