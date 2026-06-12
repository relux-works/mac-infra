# Design AnyConnect cleanup plan and safety contract

## Description
Specify dry-run/apply behavior for cleaning disconnected AnyConnect socket-filter resource leaks safely.

## Scope
Action ordering, refusal conditions, side effects, user-visible dry-run output, and verification commands.

## Acceptance Criteria
Plan refuses cleanup when VPN is connected by default, names exact commands/actions, documents expected side effects, and defines post-cleanup verification with mac-load-profile.
