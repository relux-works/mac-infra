## Status
done

## Review
light

## Task Class
docs

## Estimate
estimated(fibonacci(2))

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Document the Chrome Apple Events prerequisite and exact window/tab no-focus workflow
- [x] Prohibit browser secret export and document consequential-action guards
- [x] Verify source and installed documentation with bounded live evidence
- [x] Implementation matches AC
- [x] Solution fits project architecture
- [x] Tests green
- [x] Gate, refusal, validation, authorization, and attestation behavior attacked, not read — positive-path-only evidence is not accepted
- [x] If review does not accept the work — verdict evidence added and status routed by the explicit verdict branches

## Notes
Implemented a dedicated Chrome authenticated-session workflow in the mac-infra source skill and README. Documented the required View > Developer > Allow JavaScript from Apple Events toggle, no-focus enumeration, exact window/tab ID pinning, bounded title/origin smoke, consequential-action guards, and prohibition on exporting browser secrets. Verified against live Chrome 151 tab business.tbank.ru without activation. Validation: git diff --check passed; ./scripts/setup.sh passed all Go tests/builds and installed the skill; installed SKILL.md/reference match source; task-board validate passed. The project-local skill-creator validate-skill.sh is currently unusable due to its own line-123 unexpected-EOF syntax error; evidence is in .temp/chrome-external-scripting/skill-validate-01.log.
Follow-up: documented the live-verified no-focus Chrome pattern explicitly. Exact window/tab resolution followed by execute targetTab javascript keeps DOM reads, form events, and element clicks in page context without selecting the tab or raising Chrome; activate, active-tab assignment, window-index changes, and System Events UI scripting are prohibited. Updated source reference and README, ran scripts/setup.sh successfully (all Go tests/builds passed), verified the installed reference matches source, git diff --check passed, and task-board validate passed. Evidence: .temp/TASK-260822-1db1bg/setup-02.log, install-verify-02.log, task-board-validate-03.log.
Clarified the browser focus contract into two explicit modes. Silent mode is the default exact-ID Apple Events workflow and never surfaces Chrome. Visible/handoff mode is allowed when the user explicitly asks to open/show/foreground their tab or prepare it for manual interaction; human-only prompts remain silent until the user asks for focus. Updated SKILL.md, chrome-session.md, and README; setup passed, installed skill matches source, git diff --check passed, and board validation passed.
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-e92178, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-e92178)
Reviewer verdict: ACCEPTED (RUN-260825-e92178). All five AC verified against the committed HEAD state, not just the dirty worktree. Gates attacked rather than read: 14 negative probes against a live authenticated Chrome tab (app.slack.com, window 704793865/tab 704793878) - origin-mismatch payload suppression, localStorage/document.cookie blocklist incl. case evasion, nonexistent tab (no active-tab fallback), real tab under wrong window id, focus and trusted-input without --human-authorized, unguarded --origin-omitted path still enforcing the blocklist, --out 0600 with no stdout fallback on unwritable dir, --script+--file conflict, close arg validation. All refused correctly. No-focus attestation: frontmost stayed Terminal before/after the whole battery. Structural checks: activation exists on exactly one line gated by selectTab reachable only from focus/trusted-input; zero System Events UI scripting in production code; extract caps 100/4000 and the attribute allowlist and the seven Slack methods match the docs. Installed ~/.agents/skills/mac-infra is byte-identical to worktree source. go build+go test ./... exit 0. Non-blocking findings: (1) producer cited .temp evidence logs that were never attached to the board - review re-derived everything independently instead of trusting the summary; (2) skill-creator validate-skill.sh is genuinely broken (line 123 unexpected EOF, reproduced) and needs a fix in its own source repo, not here; (3) three sibling runs are editing chrome-session.md and README concurrently, one edited mid-review - re-diff rather than trust a snapshot. Evidence: TASK-260822-1db1bg_review-verdict.md, TASK-260822-1db1bg_review-go-test.log.
agent completed: [reviewer] reviewer (claude) (exit=0)
spawn run completed: claude (run=RUN-260825-e92178, pid=40974, exit=0)

## Precondition Resources
(none)

## Outcome Resources
- [TASK-260822-1db1bg_spawn-log_-reviewer--reviewer--claude-_RUN-260825-e92178.log](file://TASK-260822-1db1bg/TASK-260822-1db1bg_spawn-log_-reviewer--reviewer--claude-_RUN-260825-e92178.log) — System spawn log captured by task-board
- [TASK-260822-1db1bg_review-verdict.md](file://TASK-260822-1db1bg/TASK-260822-1db1bg_review-verdict.md) — Reviewer verdict: accepted. AC matrix, 14 attacked gates with live no-focus evidence, test run, findings.
- [TASK-260822-1db1bg_review-go-test.log](file://TASK-260822-1db1bg/TASK-260822-1db1bg_review-go-test.log) — go build ./... && go test ./... exit 0 during review

## Created
2026-08-22T19:40:47Z

## Last Update
2026-08-25T20:10:10Z

## Assigned To
[reviewer] reviewer (claude)
