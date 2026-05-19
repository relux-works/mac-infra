# STORY-260519-2dj8wq: safe-cleanup-executor

## Description
Trash-first cleanup execution with high-friction permanent deletion and manifest logging

## Scope
Implement guarded cleanup execution after scan output is proven, with Trash-first behavior and manifest logging.

## Acceptance Criteria
clean requires --apply; permanent delete requires explicit high-friction flags; every operation writes a manifest; errors are per-candidate; tests cover Trash destination and refusal paths.
