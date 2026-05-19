# STORY-260519-yz0mqz: xcode-and-repo-cleanup-categories

## Description
High-value generated-data cleanup categories for Xcode, local repos, logs, and build outputs

## Scope
Implement high-value cleanup categories for Xcode generated data and target-folder build/log artifacts.

## Acceptance Criteria
DerivedData/build products are supported; Archives, DeviceSupport, simulators, large/old files are review-only by default; target cleanup is allowlist-based and path-contained.
