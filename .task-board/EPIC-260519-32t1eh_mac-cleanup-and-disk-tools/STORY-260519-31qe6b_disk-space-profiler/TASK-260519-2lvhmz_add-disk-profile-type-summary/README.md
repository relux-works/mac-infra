# TASK-260519-2lvhmz: add-disk-profile-type-summary

## Description
Add extension and file-kind disk usage summaries to mac-disk-profile scan results without changing cleanup behavior.

## Scope
Own internal/diskprofile aggregation for by-extension and by-kind summaries plus mac-disk-profile text rendering hooks. Do not touch cleanup packages, setup/deinit, or global docs except task-scoped notes.

## Acceptance Criteria
Scan results include deterministic by-extension and by-kind totals using the same lstat, hard-link dedupe, exclude, and depth rules as the core scanner. No-extension and unknown kinds are bucketed explicitly. Text output can show a bounded summary. JSON artifact task can serialize the summaries without schema churn.
