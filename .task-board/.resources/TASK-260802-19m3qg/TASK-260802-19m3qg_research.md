# Separate display and idle-lock prevention research

## Current state

- `mac-infra-core sleep-prevention status` reports `enabled` for AC and battery.
- `/usr/bin/pmset -g custom` reports `displaysleep=0` on AC and `displaysleep=15` on battery.
- `defaults -currentHost read com.apple.screensaver idleTime` reports `3600` seconds.
- `/usr/sbin/sysadminctl -screenLock status` reports an immediate password requirement.
- The existing `sleep-prevention` implementation only changes the system-wide
  `SleepDisabled` policy and intentionally leaves display sleep and screen saver
  policy untouched.

## Platform findings

- `pmset` documents `displaysleep` as a per-power-source timer where `0` disables
  display sleep, but changing those timers requires root and creates restore-state
  complexity.
- `/usr/bin/caffeinate -d` holds only the
  `PreventUserIdleDisplaySleep` assertion. A current-user LaunchAgent can keep
  that assertion persistent across CLI exit and login without changing any
  power timer.
- `sysadminctl -screenLock off` would weaken password protection after manual or
  system-initiated locking. It is not an acceptable implementation for idle-lock
  prevention.
- Automatic idle locking has two relevant triggers on this Mac: display sleep
  and automatic screen saver start. Keeping the immediate password policy while
  disabling those two idle triggers preserves manual Lock Screen security.

## Selected contract

Expose three independent commands:

1. Existing `sleep-prevention enable|disable|status`, unchanged.
2. New `display-sleep-prevention enable|disable|status`, backed by a persistent
   current-user LaunchAgent running only `/usr/bin/caffeinate -d`. Disable boots
   out the assertion and removes its plist; `pmset` timers remain untouched.
3. New `idle-lock-prevention enable|disable|status`, backed by the current
   user's ByHost `com.apple.screensaver idleTime` preference and a captured prior
   value/presence snapshot. The user-facing name describes the automatic idle
   Lock Screen intent; the screen saver preference is the implementation
   mechanism.

There is deliberately no command that disables the manual screen-lock password policy.
Manual Lock Screen remains available and continues to require a password. The
LaunchAgent is session-scoped: it applies on AC and battery while the user is
logged in and requires no privileged-daemon reinstall.

## Tool readiness note

The first readiness wrapper used `status` as a zsh variable and failed because
`status` is read-only in zsh. The wrapper was corrected to use `rc`; subsequent
`task-board`, `mac-infra-core`, `defaults`, `sysadminctl`, and `caffeinate`
readiness checks succeeded. Failure and retry logs are under `.temp/`.
