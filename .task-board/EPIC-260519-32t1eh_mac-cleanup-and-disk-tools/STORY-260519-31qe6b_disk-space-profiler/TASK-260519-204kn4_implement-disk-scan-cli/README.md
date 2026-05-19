# TASK-260519-204kn4: implement-disk-scan-cli

## Description
Implement mac-disk-profile scan/top/explain commands with text output

## Scope
Implement cmd/mac-disk-profile and internal/diskprofile for scan, top, and explain commands with plain text output and deterministic tests over fixtures.

## Acceptance Criteria
scan/top/explain run without mutating files. Tests cover directory aggregation, top files and dirs, excludes, symlink skipping, and permission-error recording where practical.
