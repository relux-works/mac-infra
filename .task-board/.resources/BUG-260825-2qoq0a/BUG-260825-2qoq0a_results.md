# Outcome

Root cause: each rebuilt CLI was copied to a new content-addressed LaunchAgent path, while setup supplied only an ad-hoc identifier whose actual designated requirement fell back to a build-specific cdhash. TCC therefore prompted for the new managed path; the three bounded retries also serialized unrelated Chrome Apple Events.

Fix: reuse an executable already referenced by a configured heartbeat before pinning a rebuild, and embed the explicit designated requirement designated => identifier works.relux.mac-infra.browser-session for the first managed runtime.

Changed source worktree: .temp/BUG-260825-2qoq0a/worktree. Files: internal/browsersession/heartbeat.go, internal/browsersession/heartbeat_test.go, scripts/setup.sh, scripts/deinit_test.go, README.md, agents/skills/mac-infra/references/chrome-session.md, LOGBOOK.md.

Validation: focused browser-session/setup tests pass; go test ./... passed through scripts/setup.sh; go vet ./... and git diff --check pass; installed codesign requirement is explicit. Source install command: ./scripts/setup.sh.

Live evidence: gosuslugi-egrn-260825 exact Chrome tab 704793865/704793877 at https://lk.gosuslugi.ru runs every 10m with lastOutcome ok; launchctl state is running. Concurrent sanitized list took 0.47s and guarded run-js on another exact tab took 0.16s. No browser focus or secret/page-content capture. No files staged or committed.