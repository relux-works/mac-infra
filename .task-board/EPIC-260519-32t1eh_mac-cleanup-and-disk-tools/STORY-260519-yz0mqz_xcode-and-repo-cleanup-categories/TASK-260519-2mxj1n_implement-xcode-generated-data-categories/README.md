# TASK-260519-2mxj1n: implement-xcode-generated-data-categories

## Description
Scan Xcode DerivedData and generated caches while keeping archives/device support/simulators review-only

## Scope
Implement Xcode generated-data cleanup categories for DerivedData while keeping Archives, DeviceSupport, simulators, docs, and backups review-only.

## Acceptance Criteria
DerivedData candidates are categorized as generated data with explicit paths under ~/Library/Developer/Xcode/DerivedData. Archives, DeviceSupport, simulators, and backups are reported review-only and never default-selected.
