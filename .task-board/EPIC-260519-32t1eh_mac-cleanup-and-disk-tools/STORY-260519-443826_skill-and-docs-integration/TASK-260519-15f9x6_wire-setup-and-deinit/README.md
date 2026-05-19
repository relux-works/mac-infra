# TASK-260519-15f9x6: wire-setup-and-deinit

## Description
Build/install mac-cleanup and mac-disk-profile and remove their symlinks in deinit

## Scope
Wire mac-cleanup and mac-disk-profile into scripts/setup.sh and scripts/deinit.sh alongside existing mac-infra CLIs, without breaking mac-audio-reset, mac-infra-core, or mac-load-profile installs.

## Acceptance Criteria
setup builds and installs all CLIs to the expected global bin location. deinit removes installed symlinks/binaries owned by this repo. Logs are stored in .temp and existing installed tools still pass smoke checks.
