# TASK-261015-21d446: security-module-and-cli

## Description
Implement bounded read-only macOS exposure/posture/persistence/SSH/IOC audit with JSON and text, private no-overwrite baselines and coverage-aware drift. Use Go tests with planted IOC, wildcard listener, unavailable commands, secret suppression, and invalid baseline controls. No sudo, live configuration changes, a2a, unrelated work projects, or setup execution. Seed IOC markers from the authorized local-sysadmin brief.

## Scope
internal/security; cmd/mac-security; README; mac-infra skill/reference; setup/deinit integration

## Acceptance Criteria
Read-only checks; explicit partial coverage; Go tests/vet/build; independent security review; signed PR landing
