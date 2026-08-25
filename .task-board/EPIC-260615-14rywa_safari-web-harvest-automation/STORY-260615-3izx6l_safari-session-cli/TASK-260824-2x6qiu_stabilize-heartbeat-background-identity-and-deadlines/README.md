# TASK-260824-2x6qiu: stabilize-heartbeat-background-identity-and-deadlines

## Description
Stop macOS from treating each heartbeat build as a new background application and require every managed heartbeat to expire automatically.

## Scope
mac-chrome-session heartbeat installation/runtime identity, LaunchAgent rendering, CLI start/status/list/stop/run semantics, setup/deinit, tests, README, and mac-infra skill documentation.

## Acceptance Criteria
All heartbeat LaunchAgents execute one stable installed launcher identity across tool rebuilds; ordinary rebuilds do not create a new App Background Activity identity; heartbeat start requires a finite deadline/TTL; expired heartbeats boot out and remove managed state/plist without browser focus; status/list expose deadline and expiry; existing heartbeats can be migrated or restarted safely; tests and installed smoke pass.
