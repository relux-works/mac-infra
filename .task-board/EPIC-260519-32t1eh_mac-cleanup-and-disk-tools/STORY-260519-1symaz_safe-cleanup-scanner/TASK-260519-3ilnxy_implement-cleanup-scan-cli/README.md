# TASK-260519-3ilnxy: implement-cleanup-scan-cli

## Description
Implement mac-cleanup scan with candidate planning and totals but no deletion

## Scope
Implement mac-cleanup scan, target, and xcode commands as read-only planners that emit candidate totals, risk labels, default selection, reasons, and optional versioned Plan JSON.

## Acceptance Criteria
No scan command deletes or moves files. Plans are deterministic over fixtures, refuse dangerous roots, mark review-only candidates correctly, and write JSON artifacts with 0600 file permissions under .temp by default.
