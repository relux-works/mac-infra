# STORY-260719-1a2lns: sleep-prevention-control

## Description
Provide explicit enable, disable, and status commands for persistent macOS sleep prevention through mac-infra-core.

## Scope
Use the dedicated pmset disablesleep setting for all power sources via the privileged daemon; do not rewrite sleep timers, standby, or hibernation policy.

## Acceptance Criteria
Users can enable or disable sleep prevention for both AC and battery and can query a clear non-mutating status.
