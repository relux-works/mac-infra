# TASK-260719-cigkb7: implement-sleep-prevention-toggle-and-status

## Description
Implement mac-infra-core sleep-prevention enable, disable, and status. Enable and disable must route through the existing root daemon and execute only the allowlisted absolute command /usr/bin/pmset -a disablesleep 1 or 0. Status must inspect /usr/bin/pmset -g, parse the system-wide SleepDisabled value, and report enabled or disabled plus that the policy applies to AC and battery. Preserve all existing unrelated worktree changes.

## Scope
internal/maccore protocol and service, mac-infra-core CLI, focused tests, README, mac-infra skill instructions, setup/install verification, and logbook entry. Do not change sleep timers, standby, hibernatemode, display sleep, or other power settings. Do not stage or commit.

## Acceptance Criteria
mac-infra-core sleep-prevention enable sets the system-wide disablesleep=1 policy for all power sources; disable sets system-wide disablesleep=0; status parses the actual SleepDisabled value from pmset -g without mutation and reports all-source coverage; missing or malformed status is an explicit unavailable/error state; command execution is fixed and non-injectable; tests cover service and CLI success/failure/status cases; documentation explains persistence, battery coverage, display-sleep behavior, and daemon reinstall requirements; go test ./... and relevant installed-command smokes pass.
