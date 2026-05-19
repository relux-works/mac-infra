# TASK-260519-2mafct: classify-review-only-large-old-files

## Description
Report large/old files for review without auto-selection or deletion

## Scope
Classify large and old files as disk-inspection findings only, with no default selection and no deletion action in v1.

## Acceptance Criteria
Large/old findings appear in reports with path, size, age, and reason. They cannot be cleaned by category defaults and are clearly marked review-only in text and JSON output.
