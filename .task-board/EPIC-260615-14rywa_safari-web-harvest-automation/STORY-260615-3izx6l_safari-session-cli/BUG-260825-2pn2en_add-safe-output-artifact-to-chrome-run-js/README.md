# BUG-260825-2pn2en: add-safe-output-artifact-to-chrome-run-js

## Description
mac-chrome-session run-js rejects --out while the sibling Safari command supports controlled output artifacts; authenticated Chrome workflows must fall back to shell redirection for privacy-sensitive page results.

## Scope
cmd/mac-chrome-session and internal Chrome session helpers, run-js argument and artifact behavior, tests, README, mac-infra Chrome skill reference, setup/install verification, and source-to-installed-artifact parity. Preserve exact window/tab/origin guards and browser-secret refusal.

## Acceptance Criteria
mac-chrome-session run-js accepts optional --out PATH with --script and --file; output artifacts are written atomically with mode 0600 and page content is not duplicated to stdout; exact target/origin and secret guards remain unchanged; missing/invalid/unwritable paths fail closed; source, installed CLI help, README, and skill docs agree; targeted tests plus installed-artifact smoke pass.
