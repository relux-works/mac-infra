# Add Safari browser automation workflow

## Description
Add reusable mac-infra support for reading and harvesting authenticated Safari browser pages through Apple Events without exporting cookies. Capture the MTS harvest lessons in source skill docs, README tooling docs, and a CLI module that can open pages in background mode, run JavaScript in Safari page context, snapshot page state, and fetch authenticated resources via Safari session.

## Scope
Source repo changes only. Add documented Safari Apple Events/browser-harvest workflow and a mac-infra CLI surface. Do not dump cookies, tokens, or Authorization headers. Do not add broad Full Disk Access requirements. Persist usage notes and tests/logs under the task.

## Acceptance Criteria
mac-infra source skill documents Safari/browser automation workflow, README lists the new tool and commands, a reusable CLI exists for background open/snapshot/run-js/fetch-file flows, tests/build pass or failures are recorded, setup/install refreshes the installed skill/CLI, and task resources/notes link the MTS source case.
