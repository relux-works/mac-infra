# TASK-260724-31wqd5: add-window-targeted-run-js

## Description
Expose the existing session window targeting through mac-safari-session run-js and redact sensitive OAuth query parameters in surfaced page statuses.

## Scope
CLI parser/output, safarictl status sanitization, tests, README, and skill instructions.

## Acceptance Criteria
Positive --window-id directs run-js to that exact window; invalid values fail; status output never exposes OAuth code/state; relevant tests pass; documentation covers lifecycle and close-window cleanup.
