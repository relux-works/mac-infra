# TASK-260519-i018bt: add-disk-profile-json-artifacts

## Description
Add JSON output and saved scan artifacts for later visualization/TUI use

## Scope
Add JSON output for disk profile scans and saved artifacts under .temp/mac-disk-profile by default for later TUI or visualization work.

## Acceptance Criteria
JSON output is stable, includes scan metadata, totals, top dirs, top files, errors, and skipped categories. Default artifact paths are under .temp and are documented.
