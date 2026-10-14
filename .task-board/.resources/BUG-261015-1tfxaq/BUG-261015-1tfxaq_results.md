# CORE Timeout-Test Supplemental Review

Tracking: BUG-261015-1tfxaq, child correction to TASK-261015-2ftdza.
Verdict: **ACCEPT** the test-only correction at `internal/maccore/service_install_test.go`, git blob `a8ea14b22b70c0d8dead3240104e32a7f26a996d`.

Delivery checkout: `/Users/alexis/src/mac-infra/.temp/TASK-261015-2ftdza/delivery`; source head before the test delta: `3330186354930a093b530d9c715fc1f8bc6f192b`.

## Scope and assessment

The aggregate suite exposed a fixture timing assumption: while a retained service always fails the bounded removal check without bootstrap, scheduler load can exhaust either the polling loop or an in-flight inspection. The old assertion accepted only the polling-loop message.

The correction changes one existing test, its explanatory comment, and its import list. It preserves all production code/timeouts and every other table-row expectation. The retained-service row now requires `errors.Is(err, context.DeadlineExceeded)` AND one of two exact complete messages, both bound to the expected service label and one-second budget: `did not leave the system domain within ...` or `removal verification exceeded ...`. It does not accept arbitrary errors, unrelated deadline failures, or matching text with a non-wrapping error. The existing command-log assertion still requires exactly zero bootstrap commands for this row.

The control is deterministic at the contract level: both permitted failure branches and every forbidden classification below were exercised through overlays without relying on the scheduler to choose a particular timeout branch. The real repeated fixture tests retain wall-clock scheduling, and passing repetitions alone would not prove timing determinism; they supplement those deterministic branch controls.

## Independent verification

All commands used source and isolated helper/overlay fixtures. No product edits, privilege, launchctl operations, installation, live configs/ACLs, keychain access or excluded projects were involved.

- PASS `go test -count=5 ./internal/maccore -run '^TestReplaceLaunchService(Admission|SlowInspection)$'` — `.temp/core-review/bug-focused-02.log` (7.136s).
- PASS `python3 .temp/core-review/deterministic-controls.py` — `.temp/core-review/deterministic-controls-03.log`. Overlay copies live only under `.temp/core-review/controls/`; the original test assertions are exercised unchanged:
  - Exact wrapped polling-loop deadline: accepted, exit 0.
  - Exact wrapped inspection deadline: accepted, exit 0.
  - Identical inspection text without wrapping DeadlineExceeded: intended assertion rejection, exit 1.
  - Unrelated error wrapping DeadlineExceeded: intended assertion rejection, exit 1.
  - Permission/verification failure: intended assertion rejection, exit 1.
  - Permitted deadline error accompanied by forbidden bootstrap: intended `bootstrap count=1, want0` rejection, exit 1.
- PASS `GORACE=atexit_sleep_ms=0 go test -race -count=1 ./internal/maccore -run '^TestReplaceLaunchService(Admission|SlowInspection)$'` — `.temp/core-review/bug-race-04.log` (3.389s), no race reports. The known cgo/race linker LC_DYSYMTAB warning was emitted; test compilation/execution succeeded.
- PASS `git diff --check -- internal/maccore/service_install_test.go`.
- Exact hash comparison: only the accepted test file differs from the original 14-code/test-file review freeze; all other 13 code/test hashes match. Updated freeze: `.temp/core-review/reviewed-code-hashes.json`. README/SKILL merge review belongs to the parent and is outside this supplement.

No blocking findings. The original source-review boundaries remain unchanged. Parent must still obtain a passing full aggregate suite for the final delivery head before publication/landing; this focused supplemental verdict does not waive that gate.
