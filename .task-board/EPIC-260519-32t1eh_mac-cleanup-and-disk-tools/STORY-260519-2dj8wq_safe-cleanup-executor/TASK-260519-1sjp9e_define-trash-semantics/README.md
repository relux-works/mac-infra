# TASK-260519-1sjp9e: define-trash-semantics

## Description
Define Trash-first destination layout, collision handling, cross-volume behavior, and restoration metadata for mac-cleanup

## Scope
Choose and document v1 Trash behavior: collision-safe move into ~/.Trash/mac-infra-<timestamp>/..., original-path restoration metadata, cross-volume fallback behavior, and failure modes.

## Acceptance Criteria
Trash behavior is deterministic and testable. Executor never silently permanently deletes when Trash move fails; manifest records original path, trash path, and error state for every candidate.
