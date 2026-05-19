## Status
done

## Assigned To
codex

## Created
2026-05-19T13:15:55Z

## Last Update
2026-05-19T13:50:03Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
(empty)

## Notes
Observed mac-cleanup scan failing on ~/Library/Caches/CloudKit with operation not permitted. Implement partial-plan permission warnings and a permission helper command before continuing cleanup.
Implemented permission-aware mac-cleanup scan handling. Permission-denied candidates are skipped with planner warnings, warnings are persisted into Plan JSON, CLI prints remediation guidance, and mac-cleanup permissions --open opens Full Disk Access settings via fixed /usr/bin/open URL. Verified with go test ./..., go vet ./..., git diff --check, task-board validate, setup.sh, and real scan artifact .temp/mac-cleanup/home-plan-after-permissions-v2.json.
Follow-up: permissions --open is now intentionally not implemented. The command returns an error explaining that granting Full Disk Access to Terminal/iTerm/Cursor/VS Code is too risky because child processes may inherit it. Cleanup proceeds with partial scans only.
Verified disabled permissions --open path and continued cleanup without Full Disk Access. Trashed only selected safe_generated rotated logs from the plan: 286 files, 86,775,471 bytes, recoverable under ~/.Trash/mac-cleanup-rotated-logs-20260519-163210. New scan shows no selected safe candidates remain; remaining 700.8GB are review_only.
Cleanup execution update: user requested moving junk to Trash while preserving possibly valuable Downloads items in ~/Downloads/.toReview. Initial review move placed 1,144 review-only candidates into ~/.Trash/mac-cleanup-review-20260519-163819. Then restored likely valuable Downloads media/docs/source/build artifacts to ~/Downloads/.toReview in two passes: 710 items total in .toReview, about 434GB. Final Trash cleanup roots: ~/.Trash/mac-cleanup-review-20260519-163819 about 247GB and ~/.Trash/mac-cleanup-rotated-logs-20260519-163210 about 83MB. Remaining Downloads root-owned squats_classifier.mlmodelc stayed in place due permission denial.
Final cleanup update: user explicitly requested emptying Trash. POSIX listing of ~/.Trash was blocked by macOS privacy, but Finder native empty trash succeeded via osascript. Finder now reports 0 trash items. Data volume is about 1.2Ti used / 6.0Ti available. ~/Downloads/.toReview was left intact for user review.

## Precondition Resources
(none)

## Outcome Resources
(none)
