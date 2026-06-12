## Status
done

## Assigned To
codex

## Created
2026-05-21T08:10:13Z

## Last Update
2026-05-21T08:21:43Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Implemented mac-cleanup xcode-runtimes. Current Mac cleanup: removed unsupported iOS 13.5/14.2/14.5/15.0 CoreSimulator runtimes via simctl runtime delete; /Library/Developer/CoreSimulator/Profiles/Runtimes is now 0B; simctl unavailable devices lists no stale devices. Added internal/simcleanup parser/runner, dry-run default, --delete apply path, README/skill/logbook updates. Verified go test ./..., scripts/setup.sh, installed mac-cleanup xcode-runtimes smoke.

## Precondition Resources
(none)

## Outcome Resources
(none)
