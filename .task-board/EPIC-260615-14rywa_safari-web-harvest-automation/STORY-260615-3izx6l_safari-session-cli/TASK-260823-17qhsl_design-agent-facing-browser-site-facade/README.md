# TASK-260823-17qhsl: design-agent-facing-browser-site-facade

## Description
Design and implement a token-efficient agent-facing-api facade over browser-session site adapters and marketplace workflows.

## Scope
Define q/grep/m contracts with projection, batching, bounded pagination, scoped cache search, mutation safety metadata, and adapters that use mac-chrome-session or mac-safari-session as transport without exposing browser secrets.

## Acceptance Criteria
Facade follows agent-facing-api q/grep/m separation; structured reads support field projection and batching; marketplace list operations are paginated and compact; full-text search is cache-scoped; mutations are explicit and guarded; adapters never expose cookies, storage, authorization headers, or tokens; output-size/token comparisons are recorded.
