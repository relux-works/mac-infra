# TASK-260826-10ftog: add-guarded-chrome-file-upload

## Description
Add an explicitly authorized exact-target Chrome file-upload command for authenticated forms without exposing browser secrets or local file contents.

## Scope
cmd/mac-chrome-session, internal/chromectl, focused tests, setup/install, README, and the mac-infra Chrome-session skill contract. Preserve unrelated dirty checkout state and do not touch live browser sessions during development.

## Acceptance Criteria
A caller can upload a bounded explicit list of validated regular local files to one declared visible file input in an exact window/tab and expected origin; stale target or origin, hidden/ambiguous/non-file inputs, invalid files, count/size/extension violations, or mismatched DOM acceptance fail closed; the CLI never falls back to the active tab and normal output exposes only safe count/name verification, not file bytes, browser secrets, or full local paths; help/docs/install contract and focused positive and negative tests are updated and green.
