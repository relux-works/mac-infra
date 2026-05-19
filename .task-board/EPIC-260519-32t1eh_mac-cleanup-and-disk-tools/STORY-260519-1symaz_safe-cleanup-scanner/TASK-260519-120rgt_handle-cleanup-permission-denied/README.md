# handle-cleanup-permission-denied

## Description
Make mac-cleanup tolerate permission-denied paths and expose a user-facing Full Disk Access permission helper so scans produce partial plans instead of failing on protected macOS directories.

Scope:
- Continue cleanup planning when individual category roots or candidates hit macOS permission denial.
- Persist permission warnings into the Plan JSON artifact and print a concise remediation summary.
- Add mac-cleanup permissions --open using fixed /usr/bin/open arguments, with no shell evaluation.
- Document the workflow in README and the mac-infra skill.

Acceptance Criteria:
- mac-cleanup scan no longer fails on protected ~/Library/Caches entries.
- Permission-denied paths are reported as warnings and saved in JSON.
- The permissions command opens Full Disk Access settings on request.
- Tests cover planner continuation and permissions command behavior.

## Scope
(define task scope)

## Acceptance Criteria
(define acceptance criteria)
