# STORY-260519-31qe6b: disk-space-profiler

## Description
Read-only DaisyDisk/OmniDiskSweeper-style disk usage profiler with text and JSON outputs

## Scope
Implement DaisyDisk/OmniDiskSweeper-style read-only disk profiling for any target path with top dirs/files, excludes, errors, and JSON artifacts.

## Acceptance Criteria
Scanner does not mutate files; does not follow symlinks; reports permission-denied/skipped paths; supports text and JSON; tests cover traversal and size aggregation.
