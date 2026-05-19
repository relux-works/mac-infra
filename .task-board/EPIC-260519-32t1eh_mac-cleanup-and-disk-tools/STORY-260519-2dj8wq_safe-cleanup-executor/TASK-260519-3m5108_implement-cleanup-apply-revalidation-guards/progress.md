## Status
backlog

## Assigned To
(none)

## Created
2026-05-19T12:26:15Z

## Last Update
2026-05-19T12:26:55Z

## Blocked By
- TASK-260519-2cplpc
- TASK-260519-3ilnxy

## Blocks
- TASK-260519-1g0cy0

## Checklist
- [ ] Validate PlanHash, schemaVersion, category policy version, and stale-plan window before candidate actions
- [ ] Re-lstat every candidate and refuse changed type, size, ownership, or modtime according to the plan/apply contract
- [ ] Refuse symlink candidates, symlink swaps, out-of-root realpaths, dangerous roots, and path traversal
- [ ] Return structured per-candidate decisions for allowed, skipped, refused, and error states
- [ ] Add tests for stale plan, changed candidate, symlink swap, external-volume child path, and non-user-owned candidate behavior

## Notes

## Precondition Resources
(none)

## Outcome Resources
(none)
