# TASK-260519-1g0cy0: implement-trash-first-executor

## Description
Implement cleanup clean --apply with Trash-first behavior and collision-safe destination layout

## Scope
Implement mac-cleanup clean --apply executor that applies a saved plan, revalidates every candidate, defaults to Trash-first moves, refuses unsafe changes, and records all outcomes in the manifest.

## Acceptance Criteria
Without --apply, clean exits without mutation. With --apply --plan PATH, executor validates plan hash/staleness, re-lstats candidates, refuses symlinks/out-of-root/non-user-owned changes, moves allowed candidates to Trash, and never uses mac-infra-core or sudo.
