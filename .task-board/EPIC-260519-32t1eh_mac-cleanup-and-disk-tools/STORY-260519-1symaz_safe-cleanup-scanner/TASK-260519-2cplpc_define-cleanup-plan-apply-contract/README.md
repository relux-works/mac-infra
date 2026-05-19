# TASK-260519-2cplpc: define-cleanup-plan-apply-contract

## Description
Define versioned cleanup Plan schema, apply semantics, plan hash validation, stale-plan behavior, and candidate revalidation rules before any deletion code

## Scope
Define the destructive cleanup contract: versioned Plan JSON emitted by scan commands, clean --apply --plan PATH behavior, PlanHash validation, stale-plan handling, candidate re-lstat, TOCTOU refusal, and confirmation UX.

## Acceptance Criteria
Executor implementation has an unambiguous input contract. Saved plan schema includes schemaVersion, category policy version, candidate identity, risk/default flags, sizes, root realpath, plan hash, and generated timestamp. Apply refuses stale or changed unsafe candidates before any deletion.
