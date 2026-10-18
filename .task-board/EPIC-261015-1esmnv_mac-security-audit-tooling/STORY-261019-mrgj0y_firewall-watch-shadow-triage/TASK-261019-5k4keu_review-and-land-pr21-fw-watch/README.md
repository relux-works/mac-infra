# TASK-261019-5k4keu: review-and-land-pr21-fw-watch

## Description
Review and land relux-works/mac-infra PR #21 (head e4f2311 on c4459c3, author local-sysadmin keeper): mac-firewall watch + internal/security/firewallwatch + skill docs + docs-only LaunchAgent plist. Exact-head signed landing, no rewrite (meta-keeper). LaunchAgent install after landing is the sysadmin keeper host step.

## Scope
(define task scope)

## Acceptance Criteria
1) Keeper review plus an independent Codex review swept per surface (process exec, loopback client, state files, parsing, rules/kNN, never-blocks claim, tests, docs); verdict posted on the PR as a comment review. 2) Findings routed to the author and fixed or explicitly accepted. 3) The exact accepted head lands by plain fast-forward with every commit signature verified. 4) skill-mac-infra mirror updated (signed commit, new tag, README row, diff -rq) because agents/skills/mac-infra changes.
