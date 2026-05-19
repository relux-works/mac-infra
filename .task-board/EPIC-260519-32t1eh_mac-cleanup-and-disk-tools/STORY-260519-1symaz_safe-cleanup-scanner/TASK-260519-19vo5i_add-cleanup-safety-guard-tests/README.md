# TASK-260519-19vo5i: add-cleanup-safety-guard-tests

## Description
Test dangerous root refusal, symlink refusal, containment checks, and allowlist behavior

## Scope
Add safety guard tests for cleanup planning and execution boundaries: root refusal, containment, symlink refusal, TOCTOU, ownership, external volumes, and changed candidates.

## Acceptance Criteria
Tests fail if cleanup can delete outside an allowlisted root, follow symlinks, apply a stale/changed plan, delete a non-user-owned path, or treat review-only categories as default-selected.
