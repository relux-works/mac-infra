# STORY-260915-fqzt34: fsevents-default-thresholds-512mb

## Description
Lower fseventsd default thresholds: critical 512 MB, warn 256 MB (owner: 4 GB is far too lax; healthy fseventsd sits at 10-20 MB). Watchdog default follows the critical constant.

## Scope
internal/fsevents constants, docs mentioning the defaults

## Acceptance Criteria
defaults 512/256 MB in code, skill, README, release notes; tests green
