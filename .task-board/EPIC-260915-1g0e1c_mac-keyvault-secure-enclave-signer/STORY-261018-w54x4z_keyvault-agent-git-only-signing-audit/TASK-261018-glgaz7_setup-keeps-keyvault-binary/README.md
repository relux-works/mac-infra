# TASK-261018-glgaz7: setup-keeps-keyvault-binary

## Description
Meta-keeper request 2026-10-18: setup.sh must not rebuild bin/mac-keyvault (keys trust its cdhash; a rebuild stops unattended signing until an owner keychain prompt). Keep an existing binary unless --rebuild-keyvault; refuse that while a process runs it.

## Scope
(define task scope)

## Acceptance Criteria
(define acceptance criteria)
