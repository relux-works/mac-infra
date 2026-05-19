# TASK-260519-4m0vph: define-cleanup-category-policy

## Description
Define safe/review-only/out-of-scope cleanup categories and default selection rules

## Scope
Define cleanup category policy for safe generated data, review-only user data, dangerous roots, default selection, ownership checks, external volumes, and out-of-scope categories.

## Acceptance Criteria
Policy explicitly separates safe, review-only, and out-of-scope categories. Defaults never select user data, Downloads, app caches, backups, Archives, DeviceSupport, simulators, or external volume roots for deletion.
