## Status
to-review

## Review
required

## Task Class
code

## Estimate
estimated(fibonacci(3))

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Pin snapshot JavaScript to the agent-created Safari window
- [x] Close only the exact agent-created window after capture
- [x] Add regression coverage and run setup

## Notes
Fixed target loss by pinning JS to the exact window ID returned by OpenBackground. snapshot --url and fetch-file --page now close their exact agent-owned window on all exits; open-bg exposes window-id plus close-window. Full setup and two live authenticated HUB smokes passed with HRlink frontmost and no agent-created visible/tabbed window left behind.

## Precondition Resources
(none)

## Outcome Resources
- [BUG-260723-1vgmu0_safari-target-cleanup-fix.md](file://BUG-260723-1vgmu0/BUG-260723-1vgmu0_safari-target-cleanup-fix.md) — Root cause, implementation, unit tests, live Safari smoke, and setup evidence

## Created
2026-07-23T15:18:34Z

## Last Update
2026-07-23T15:30:12Z

## Assigned To
codex
