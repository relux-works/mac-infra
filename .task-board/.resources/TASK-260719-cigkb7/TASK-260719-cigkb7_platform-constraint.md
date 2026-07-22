# TASK-260719-cigkb7 Platform Constraint

## Conclusion

`pmset disablesleep` is a single system-wide setting, not an AC/battery custom-profile setting. The requested AC/battery status model, including an inconsistent per-source state, cannot be implemented from actual `pmset` state without inventing values or conflating unrelated `sleep` timers.

## Local Evidence

All commands ran on macOS 26.5.1 (25F80) on 2026-07-19.

- `/usr/bin/pmset -g custom` exited 0 and returned separate `Battery Power:` and `AC Power:` profiles. Neither profile contained `disablesleep` or `SleepDisabled`. Their independent `sleep` timer values were `1` and `0`; those timers are explicitly outside this task's mutation scope.
- `/usr/bin/pmset -g` exited 0 and returned `System-wide power settings:` followed by `SleepDisabled 1`.
- Therefore the live machine has sleep disabled through the global switch while the custom profiles contain no per-source representation of that switch.

## Apple Source Evidence

Apple OSS PowerManagement commit `d415e45501842834a280930c3eed9186544a67f0` (`PowerManagement-1846.0.25.0.1`) was inspected under `.temp/TASK-260719-cigkb7/apple-PowerManagement`.

- `pmset/pmset.m:5813-5836`: `ARG_DISABLESLEEP` writes `kIOPMSleepDisabledKey` into `local_system_power_settings` and marks `kModSystemSettings`; it does not call the AC/battery/UPS profile setter.
- `pmset/pmset.m:790-803`: system settings are persisted with `IOPMSetSystemPowerSetting`.
- `pmset/pmset.m:1184-1198`: `show_system_power_settings()` reads `IOPMCopySystemPowerSettings()` and prints the one `SleepDisabled` value.
- `pmset/pmset.m:1512-1521`: `show_custom_pm_settings()` separately reads `IOPMCopyPMPreferences()` and prints power-source profiles.
- `pmconfigd/PMSettings.m:1341-1347`: `pmconfigd` reads the one system `kIOPMSleepDisabledKey` and applies it to the root domain.

The `-a` flag in `/usr/bin/pmset -a disablesleep 1|0` does not turn this special system setting into separate AC and battery values.

## Failed Assumption

The task assumes `pmset -g custom` can expose an independently effective `disablesleep` value for AC and battery. Local behavior and Apple source both disprove that assumption. An `inconsistent` AC/battery `disablesleep` state is not representable by this API.

## Viable Options

1. **Recommended: revise the contract to system-wide sleep prevention.** Keep the fixed daemon commands `/usr/bin/pmset -a disablesleep 1` and `0`. Implement status with the system-wide `SleepDisabled` value from `/usr/bin/pmset -g`, reporting `enabled`, `disabled`, or `unavailable`. Remove AC/battery and inconsistent-state acceptance criteria.
2. Change per-source `sleep` timers. This can produce different AC/battery behavior, but it violates the explicit scope and overwrites the user's intentional `sleep=1` battery / `sleep=0` AC policy. Reject.
3. Print AC and battery as duplicated aliases of the global value. This is misleading, cannot produce a real inconsistent state, and would make tests validate invented behavior. Reject.

## Decision Needed

Authorize option 1 by revising the task/story acceptance criteria from per-source status to one system-wide status. No clean implementation can satisfy the current AC/battery/inconsistent-state contract.

## Worktree Safety

No product, test, documentation, setup, or audio-sweep files were modified while establishing this constraint.
