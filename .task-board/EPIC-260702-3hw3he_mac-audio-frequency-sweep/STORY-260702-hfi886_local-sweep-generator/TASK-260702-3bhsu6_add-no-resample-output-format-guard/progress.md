## Status
to-review

## Assigned To
codex

## Created
2026-07-02T12:36:40Z

## Last Update
2026-07-02T12:42:41Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Add CoreAudio default-output sample-rate query and optional setter
- [x] Guard TUI playback against sample-rate mismatch by default
- [x] Add optional set-and-restore sample-rate mode for clean playback
- [x] Update tests, README, and skill workflow
- [x] Add deterministic WAV cache with explicit rerender flag

## Notes
Implemented CoreAudio output sample-rate guard/set/restore, read-only device inspection, cached WAV reuse, and --rerender. Verification: .temp/TASK-260702-3bhsu6-go-test-01.log, .temp/TASK-260702-3bhsu6-go-build-02.log, .temp/TASK-260702-3bhsu6-device-smoke-02.log, .temp/TASK-260702-3bhsu6-setup-01.log, .temp/TASK-260702-3bhsu6-installed-device-01.log, .temp/TASK-260702-3bhsu6-installed-generate-01.log, .temp/TASK-260702-3bhsu6-focused-cover-01.log. TA-22 currently reports 192000 Hz, settable yes, supports 96000 Hz yes.

## Precondition Resources
(none)

## Outcome Resources
(none)
