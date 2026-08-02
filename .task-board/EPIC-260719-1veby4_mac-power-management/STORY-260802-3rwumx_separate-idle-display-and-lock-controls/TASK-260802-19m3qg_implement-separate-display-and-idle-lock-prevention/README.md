# TASK-260802-19m3qg: implement-separate-display-and-idle-lock-prevention

## Description
Implement separate display-sleep-prevention and idle-lock-prevention enable/disable/status commands alongside existing sleep-prevention.

## Scope
Use a persistent current-user launchd display assertion plus reversible saved-state handling for the automatic screen-saver lock trigger, fixed allowlisted commands, focused Go tests, README and mac-infra skill updates, setup verification, and task evidence. Do not modify unrelated Safari or audio work and do not stage or commit.

## Acceptance Criteria
Existing sleep-prevention behavior is unchanged; display-sleep-prevention independently manages a persistent current-user caffeinate -d LaunchAgent without changing pmset timers; idle-lock-prevention independently disables the automatic screen-saver lock trigger and restores captured idleTime; status and docs state that display sleep is a separate lock trigger; manual Lock Screen remains available and immediate password policy is not weakened; go test ./... and installed command smokes pass.
