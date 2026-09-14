# TASK-260915-19m7ql: lower-fsevents-default-thresholds

## Description
Change DefaultRSSWarnBytes to 256 MB and DefaultRSSCriticalBytes to 512 MB; update SKILL.md/README/RELEASE_NOTES text; keep tests green.

## Scope
internal/fsevents/diagnose.go, docs

## Acceptance Criteria
constants and docs updated; go test ./internal/fsevents ./internal/maccore ./cmd/mac-infra-core green
