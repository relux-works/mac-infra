# STORY-260724-2mj7n7: safari-window-targeted-javascript

## Description
Enable guarded JavaScript execution against a specific agent-created background Safari window so browser automation stays no-focus and does not touch user-owned tabs.

## Scope
mac-safari-session CLI, its tests, README, and mac-infra skill guidance only.

## Acceptance Criteria
run-js accepts a validated window ID; execution is addressed to that Safari window; sensitive auth-query parameters are redacted from status output; tests pass; docs explain use only with open-bg-owned windows.
