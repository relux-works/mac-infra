# TASK-260519-3vfq4z: design-disk-scan-model

## Description
Define disk profile data model, traversal rules, size accounting, excludes, and error reporting

## Scope
Define filesystem traversal model, entry/result structs, size accounting, symlink handling, permission error reporting, excludes, depth limits, and APFS caveats for mac-disk-profile.

## Acceptance Criteria
Model contract is documented in the linked architecture resource. It separates logical and disk bytes, never follows symlinks, records unreadable paths, and supports future JSON visualization without cleanup coupling.
