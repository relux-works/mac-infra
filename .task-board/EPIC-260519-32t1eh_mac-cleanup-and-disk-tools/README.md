# EPIC-260519-32t1eh: mac-cleanup-and-disk-tools

## Description
Design and implement safe macOS cleanup and disk profiling tooling for mac-infra

## Scope
Read-only disk profiling, safe cleanup planning, guarded cleanup execution, Xcode/repo generated-data categories, README/setup/skill integration. Excludes malware scanning, RAM cleaning, forced purgeable-space deletion, binary/language stripping, and app uninstaller v1.

## Acceptance Criteria
Research and architecture are linked as precondition resources; disk profiler ships before cleanup executor; cleanup has scan-first behavior and --apply guard; deletion defaults to Trash; tests cover safety guards; setup installs all CLIs; skill documents workflows.
