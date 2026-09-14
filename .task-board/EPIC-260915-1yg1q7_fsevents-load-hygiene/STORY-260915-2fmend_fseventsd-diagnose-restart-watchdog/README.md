# STORY-260915-2fmend: fseventsd-diagnose-restart-watchdog

## Description
First slice: read-only fsevents diagnostics in mac-load-profile, allowlisted fseventsd restart in mac-infra-core, a user LaunchAgent watchdog with notification and opt-in auto-restart, and skill/README documentation.

## Scope
cmd/mac-load-profile, cmd/mac-infra-core, internal/*, agents/skills/mac-infra/SKILL.md, README.md

## Acceptance Criteria
All four tasks done; go test/vet/build green; negative tests cover threshold refusal, missing snapshot, and non-root paths.
