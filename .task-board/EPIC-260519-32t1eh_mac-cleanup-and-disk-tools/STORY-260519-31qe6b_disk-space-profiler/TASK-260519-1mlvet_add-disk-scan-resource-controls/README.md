# TASK-260519-1mlvet: add-disk-scan-resource-controls

## Description
Define and implement disk scan resource controls for cancellation, retained-entry limits, default excludes, and benchmark fixtures

## Scope
Define and implement disk scan controls: context cancellation, max retained entries, default excludes, memory-safe aggregation, progress-friendly structure, and synthetic large-tree benchmark fixtures.

## Acceptance Criteria
Disk scans have explicit resource limits before live $HOME verification. Large fixtures do not cause unbounded memory retention, cancellation works in tests, and default excludes avoid noisy generated trees unless requested.
