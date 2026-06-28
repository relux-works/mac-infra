# Implement video smoothness diagnostics

## Description
Add a read-only macOS video/display smoothness diagnostic workflow for subtle slideshow/stutter symptoms. The workflow should answer what is likely wrong when UI/video smoothness becomes discrete, including WindowServer/GPU/display pressure, Docker or virtualization load, thermal throttling, memory pressure, and suspicious processes.

## Scope
Create a new mac-video-profile CLI backed by internal videoprofile planning/model code. Add summary and capture modes, optional recent log capture, setup/deinit integration, README docs, and mac-infra skill instructions. Do not add mutation/reset behavior.

## Acceptance Criteria
1. internal/videoprofile planner tests cover default capture commands, optional log commands, process query categories, and artifact naming. 2. cmd/mac-video-profile supports snapshot, capture, version, and help. 3. capture writes summary.txt and command artifacts under .temp/mac-video-profile/capture-*. 4. snapshot prints concise process/display-stutter triage using existing process collection patterns. 5. scripts/setup.sh and scripts/deinit.sh install/remove the new binary. 6. README.md and agents/skills/mac-infra/SKILL.md document the workflow. 7. gofmt and go test ./... pass.
