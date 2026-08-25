# Build unified guarded browser session runtime

## Description
Orchestrate a coherent mac-infra browser-session toolset over the existing Safari implementation and the current uncommitted Chrome draft. Cover exact window/tab targeting, silent background operation, explicit visible/handoff semantics, named persistent heartbeats, browser-secret guards, private evidence, setup/deinit, tests, README, skill installation, and migration of current ad hoc Chrome/FNS/T-Bank heartbeat fragments into the supported tool.

## Scope
Existing cmd/mac-safari-session and internal/safarictl; current uncommitted cmd/mac-chrome-session and internal/chromectl drafts; lifecycle/setup/deinit scripts; README, chrome/safari skill references, LOGBOOK, and task-board delivery evidence. Preserve unrelated dirty checkout changes. The future dumb repeated-element extractor is separate TASK-260823-17qhsl and must not be implemented in this scope.

## Acceptance Criteria
Chrome and Safari exact-target workflows have a coherent documented contract; named heartbeat start/status/stop can keep multiple exact sessions alive concurrently without focusing browsers; origin/tab drift fails closed; browser secrets cannot be exported; current ad hoc heartbeat use cases migrate to supported commands; setup/deinit install and clean managed artifacts safely; tests include negative focus/secret/retargeting cases; installed live smokes pass; skill/docs match implementation; producer-reviewer workflow reaches an accepted deliverable without overwriting unrelated work.
