## Status
backlog

## Assigned To
(none)

## Created
2026-05-19T11:54:59Z

## Last Update
2026-05-19T12:05:41Z

## Blocked By
- TASK-260519-3ilnxy

## Blocks
- TASK-260519-1g0cy0

## Checklist
- [ ] Test dangerous root refusal including /, $HOME, /System, /Library, /Applications, /private, /var, and /Volumes root
- [ ] Test symlink root, symlink candidate, path traversal, and symlink swap before apply
- [ ] Test external volume root refusal but allow explicit child paths when safe
- [ ] Test changed file, stale plan, and non-user-owned candidate refusal

## Notes

## Precondition Resources
(none)

## Outcome Resources
(none)
