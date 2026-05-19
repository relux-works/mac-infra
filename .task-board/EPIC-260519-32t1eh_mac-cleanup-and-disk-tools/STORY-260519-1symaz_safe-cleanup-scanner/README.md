# STORY-260519-1symaz: safe-cleanup-scanner

## Description
CleanMyMac-style scan-first cleanup candidate planner using allowlisted categories and risk levels

## Scope
Implement CleanMyMac-style scan-first cleanup candidate planning with safe/review-only/out-of-scope category policy.

## Acceptance Criteria
scan never deletes; categories include reasons, bytes, risk, default selection; dangerous roots and symlinks are refused; large/old user files are review-only.
