# TASK-260519-r7v7eg: implement-target-folder-build-log-categories

## Description
Scan target folder for known generated build/log dirs using allowlisted names and containment checks

## Scope
Implement target-folder generated-data categories for explicit project paths using allowlisted directory names and containment checks.

## Acceptance Criteria
Only known generated dirs inside the requested target are candidates. The scanner refuses dangerous target roots, does not follow symlinks, and reports skipped symlink/out-of-root cases.
