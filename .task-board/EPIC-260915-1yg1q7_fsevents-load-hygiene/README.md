# EPIC-260915-1yg1q7: fsevents-load-hygiene

## Description
Diagnose, restart, and watch fseventsd memory/CPU bloat caused by slow FSEvents consumers (Colima inotify) and high file-event volume (git-heavy test loops). Root cause session 2026-09-14: fseventsd reached 27-40 GB RSS and 100% CPU over 11 days.

## Scope
mac-load-profile fsevents diagnostics; mac-infra-core fseventsd-restart privileged action; mac-infra-core fseventsd-watchdog LaunchAgent; skill/README docs. Scratch-volume (no_log) is out of scope for this epic.

## Acceptance Criteria
fseventsd bloat is detectable without sudo, restartable through the root daemon, and a user LaunchAgent alerts before it degrades the machine.
