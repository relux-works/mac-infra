# TASK-260519-1q0s32: add-permanent-delete-friction

## Description
Gate permanent deletion behind explicit high-friction flags and tests

## Scope
Add permanent delete support only behind explicit high-friction flags and tests; keep Trash as default and recommended path.

## Acceptance Criteria
Permanent deletion is impossible unless both --permanent and --yes-i-know are present with --apply --plan. Tests prove missing either flag refuses mutation and review-only candidates remain protected.
