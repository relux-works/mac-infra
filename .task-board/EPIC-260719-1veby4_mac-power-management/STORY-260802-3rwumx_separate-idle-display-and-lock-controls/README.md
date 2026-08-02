# STORY-260802-3rwumx: separate-idle-display-and-lock-controls

## Description
Add independent macOS controls for display sleep and automatic idle Lock Screen triggers while preserving the existing system sleep-prevention command.

## Scope
mac-infra-core CLI, a persistent current-user display-sleep assertion, user-scoped idle-lock trigger policy, focused tests, setup/docs/skill updates, and local installed-command verification. Preserve unrelated worktree changes.

## Acceptance Criteria
System sleep, display sleep, and idle-lock prevention are exposed as separate commands; display prevention uses a reversible current-user launchd assertion without rewriting pmset timers; idle-lock changes restore captured idleTime and state their automatic screen-saver-trigger scope; manual lock and password-after-lock security remain intact; tests and installed smokes pass.
