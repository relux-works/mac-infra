## Status
development

## Assigned To
codex

## Created
2026-06-10T12:48:55Z

## Last Update
2026-06-10T12:56:45Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Implemented mac-infra-core request-permissions sudo as an explicit permission kind. The command calls the Go core sudo credential path, reports helper status, and states that it does not grant Full Disk Access or broad launcher permissions. Updated README and mac-infra skill. Verification: go test ./cmd/mac-infra-core ./internal/maccore; go test ./...; git diff --check; ./scripts/setup.sh; mac-infra-core --help; mac-infra-core request-permissions usage smoke; mac-infra-core status.

## Precondition Resources
(none)

## Outcome Resources
(none)
