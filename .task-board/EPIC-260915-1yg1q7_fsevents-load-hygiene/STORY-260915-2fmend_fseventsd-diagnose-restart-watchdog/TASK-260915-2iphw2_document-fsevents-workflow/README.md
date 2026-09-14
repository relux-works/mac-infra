# TASK-260915-2iphw2: document-fsevents-workflow

## Description
Document FSEvents Bloat workflow in agents/skills/mac-infra/SKILL.md and README tools section: diagnose -> restart -> watchdog, Colima mountInotify guidance, heavy git/go test loop hygiene, when NOT to throttle fseventsd (dropped events cause full rescans).

## Scope
agents/skills/mac-infra/SKILL.md, README.md, RELEASE_NOTES.md

## Acceptance Criteria
Skill section exists with exact commands; README tools table lists new commands; release notes entry
