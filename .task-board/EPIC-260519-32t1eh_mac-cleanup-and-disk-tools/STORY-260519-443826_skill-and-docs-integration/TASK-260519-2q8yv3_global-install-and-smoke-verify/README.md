# TASK-260519-2q8yv3: global-install-and-smoke-verify

## Description
Run setup, verify global skill copy, dry-run cleanup scans, disk profile scans, and logs

## Scope
Run final setup, global command smoke checks, dry-run cleanup scans, disk profile scans, Go tests, board validation, and capture logs.

## Acceptance Criteria
All test and smoke logs are in .temp. Global commands resolve in PATH, read-only scans work, cleanup dry-runs do not mutate, setup/deinit paths are verified, and task-board validate passes.
