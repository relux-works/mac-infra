# TASK-260519-3ilnxy Results

## Code

- Added `internal/cleanup/planner.go` for read-only cleanup planning.
- Added `cmd/mac-cleanup` with `scan`, `target`, `xcode`, `version`, and `help`.
- Updated `scripts/setup.sh` and `scripts/deinit.sh` for the `mac-cleanup` binary.
- Updated `README.md` tool documentation for the cleanup planner.
- Added planner and CLI tests in `internal/cleanup/planner_test.go` and `cmd/mac-cleanup/main_test.go`.

## Behavior

- `scan`, `target`, and `xcode` only build plans and print summaries; no delete, move, Trash, permanent delete, or `clean` command was added.
- Table output includes category, risk, default selection, bytes, candidate count, selected count, and reason.
- Optional `--json PATH` writes versioned cleanup `Plan` JSON through `cleanup.WritePlanArtifact`.
- `--json` without a path writes to `.temp/mac-cleanup/<command>-plan.json` with directory mode `0700` and file mode `0600`.
- `target` refuses dangerous roots through the existing cleanup safety policy.
- Safe generated candidates are selected by default; review-only candidates are reported but not selected.
- Symlink generated candidates are downgraded to review-only and unselected.

## Verification

- `go test ./internal/cleanup ./cmd/mac-cleanup -count=1`: passed. Log: `.temp/TASK-260519-3ilnxy/go-test-focused-03.log`.
- `go test ./... -count=1`: passed. Log: `.temp/TASK-260519-3ilnxy/go-test-01.log`.
- `go vet ./...`: passed. Log: `.temp/TASK-260519-3ilnxy/go-vet-01.log`.
- `gofmt -l cmd internal`: passed with no unformatted files. Log: `.temp/TASK-260519-3ilnxy/gofmt-01.log`.
- `go build ./cmd/...`: passed. Log: `.temp/TASK-260519-3ilnxy/go-build-01.log`.
- `git diff --check`: passed. Log: `.temp/TASK-260519-3ilnxy/git-diff-check-02.log`.

All Go commands used task-local `GOCACHE` and `GOMODCACHE` under `.temp/TASK-260519-3ilnxy/`.

## Notes

- Recorded a logbook entry: `1600 - Cleanup Planner Test Roots`.
- macOS `t.TempDir()` lives under `/var/folders`, which the cleanup safety policy correctly refuses; cleanup planner tests use repo-local temp directories instead.
