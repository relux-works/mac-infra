# Add mac-infra-core AnyConnect cleanup action

## Description
Implement allowlisted privileged action(s) in mac-infra-core for the approved AnyConnect cleanup plan.

## Scope
mac-infra-core protocol/service/CLI tests only; no generic command runner and no broad shell execution.

## Acceptance Criteria
Cleanup apply goes through mac-infra-core allowlisted actions; unsupported actions remain rejected; unit tests cover success/failure/refusal paths.
