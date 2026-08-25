# TASK-260822-1db1bg: document-chrome-authenticated-session-automation

## Description
Document verified no-focus Chrome Apple Events automation for authenticated tabs, including the required user toggle, exact window/tab targeting, safe DOM smoke tests, and secret-handling boundaries.

## Scope
agents/skills/mac-infra/SKILL.md; agents/skills/mac-infra/references/chrome-session.md; README.md

## Acceptance Criteria
The mac-infra skill triggers for Chrome automation; the workflow explains enabling View > Developer > Allow JavaScript from Apple Events; examples target exact Chrome window and tab IDs without activation; secret storage/cookies are prohibited; documentation is installed and verified against a live authenticated Chrome tab.
