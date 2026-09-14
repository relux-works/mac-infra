# TASK-260915-2scia5: add-load-profile-fsevents-diagnostics

## Description
Add read-only mac-load-profile fsevents: fseventsd pid/RSS/CPU/uptime with thresholds, known FSEvents consumers (colima --inotify daemon, mds, Time Machine, iCloud, third-party sync/agent daemons), colima mountInotify detection in ~/.colima/*/colima.yaml, go-build leftover size in TMPDIR, verdict and recommendations. No sudo, no mutation.

## Scope
cmd/mac-load-profile, internal/loadprofile (or new internal/fsevents)

## Acceptance Criteria
Command runs without sudo; JSON and text output; unit tests with fake process/config inputs; negative tests: unreadable colima config, missing fseventsd, threshold boundary
