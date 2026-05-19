# TASK-260519-3m5108: implement-cleanup-apply-revalidation-guards

## Description
Implement the non-mutating guard layer that validates a saved cleanup Plan immediately before any executor move/delete work.

## Scope
Own internal/cleanup apply validation helpers and tests: plan hash/staleness checks, candidate lstat refresh, realpath containment, symlink refusal, ownership checks, and per-candidate refusal reasons. Do not implement Trash moves or permanent deletion in this task.

## Acceptance Criteria
Given a saved Plan, validation returns a per-candidate decision set and refuses stale plans, changed candidates, symlink swaps, out-of-root paths, dangerous roots, and non-user-owned candidates before any mutation path can run. Tests cover TOCTOU and refusal cases. The guard layer is reusable by the Trash executor and writes no files except test fixtures/logs.
