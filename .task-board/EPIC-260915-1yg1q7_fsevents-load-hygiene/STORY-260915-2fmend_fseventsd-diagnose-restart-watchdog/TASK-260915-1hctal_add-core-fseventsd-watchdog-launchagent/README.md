# TASK-260915-1hctal: add-core-fseventsd-watchdog-launchagent

## Description
Add mac-infra-core fseventsd-watchdog enable|disable|status: current-user LaunchAgent (label works.relux.mac-infra-fseventsd-watchdog) running the binary in a check mode every 10 min; above RSS threshold it posts a macOS notification; --auto-restart opt-in calls the restart action through the daemon. Follow display-sleep-prevention LaunchAgent pattern.

## Scope
cmd/mac-infra-core, internal launchagent helpers

## Acceptance Criteria
enable writes plist and bootstraps agent; disable boots out and removes plist; status reports interval, threshold, auto-restart flag, last check; tests cover plist rendering, idempotent enable, disable without plist
