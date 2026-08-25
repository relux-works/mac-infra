## Status
done

## Review
required

## Task Class
code

## Estimate
estimated(fibonacci(8))

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Use one stable installed launcher identity across Chrome and Safari heartbeat rebuilds
- [x] Require a finite heartbeat deadline and clean expired LaunchAgent state without browser focus
- [x] Expose deadline and expiry state and provide a safe migration or restart path
- [x] Add negative lifecycle tests and verify source, install, and bounded runtime behavior
- [x] Code written per task description and AC
- [x] Relevant tests written for new or changed behavior and passing
- [x] Gating, refusing, validating, authorizing, or attesting behavior covered by negative tests that fail when the gate admits what it must reject, with the production call site named
- [x] Lint clean
- [x] Relevant build/validation commands run after changes and build not broken
- [x] New outcome artifact attached on the board with a task-scoped name when the work produces notes, logs, screenshots, or other deliverables
- [x] Important findings, decisions, anomalies, or regressions recorded in logbook when relevant
- [x] Implementation matches AC
- [x] Solution fits project architecture
- [x] Tests green
- [x] Gate, refusal, validation, authorization, and attestation behavior attacked, not read — positive-path-only evidence is not accepted
- [x] If review does not accept the work — verdict evidence added and status routed by the explicit verdict branches

## Notes
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260825-db66cb, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260825-db66cb)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260825-db66cb, pid=8850, exit=0)
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-b9688a, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-b9688a)
Reviewer RUN-260825-b9688a verdict on CR-TASK-260824-2x6qiu-1 rev1: CHANGES REQUESTED -> to-dev. Evidence: TASK-260824-2x6qiu_review-verdict.md, TASK-260824-2x6qiu_review-mutants.log. Suites green (go vet ./... exit 0; go test -count=1 ./... exit 0), and four narrowing mutants on the render/start/ResolveDeadline/Inspect gates were killed. Two blocking findings. (1) Both in-flight expiry arms in HeartbeatManager.Run - the mid-probe runCtx deadline plus post-probe check, and the sleep-window case <-time.After(deadline.Sub(m.now())) - can be deleted outright with the whole suite still green. Every existing expiry test freezes m.Now, while both arms use real wall-clock timers, so a frozen clock can never reach them. With --interval 20m --ttl 5m (accepted today; nothing relates interval to TTL) the sleep-window arm is the only thing stopping a heartbeat from holding its LaunchAgent, state, plist and log for a full interval past its deadline, contradicting the AC clause on booting out expired heartbeats. A real-clock probe test written during review returns in 532ms against production code and FAILS at a 5s bound with the arm deleted, so the gap is cheap to close. (2) heartbeat start budget was cut from 11min to 90s in both CLIs with no rationale in AC, task, evidence artifact or LOGBOOK, while the comment directly above it still argues for a long budget because Chrome serializes Apple Events behind an existing long-running monitor; worst-case direct plus background preflight is already ~62s inside that 90s ceiling. Non-blocking: the launcher regular-file/exec-mode clause and the cfg.Deadline=="" migration clause each survive narrowing untested. Structural note for the orchestrator: this candidate tree also bundles unaccepted sibling work - BUG-260825-1wsh7n (to-dev), BUG-260825-2s6iw4 (to-dev), TASK-260822-3dshyo (blocked); integrating this revision is not acceptance of those.
agent completed: [reviewer] reviewer (claude) (exit=0)
spawn run completed: claude (run=RUN-260825-b9688a, pid=63751, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260825-e05214, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260825-e05214)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260825-e05214, pid=15743, exit=0)
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-1027f1, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-1027f1)
Reviewer RUN-260825-1027f1 verdict on CR-TASK-260824-2x6qiu-2 rev2: ACCEPTED. Evidence: TASK-260824-2x6qiu_review-verdict.md, TASK-260824-2x6qiu_review-mutants.log. Both rev1 blockers are closed: the wall-clock expiry arms in Run are now pinned by real-clock tests (deleting the interval-sleep arm fails TestRunExpiresDuringIntervalSleepAtRealDeadlineAndCleansManagedState), and the 11min heartbeat lifecycle budget is restored and pinned. Candidate tree: gofmt/vet/build clean, go test -count=1 ./... green on a non-symlinked path (the 6 internal/cleanup + cmd/mac-cleanup failures seen under /tmp are the macOS /tmp->/private/tmp realpath artifact; same code passes in the worktree). Ten narrowing/deleting gate mutants killed: ResolveDeadline exclusivity, render stable-launcher path, launcher regular-file/exec-mode, Run pre-probe and sleep-window expiry, Inspect expiry cleanup, deadline-free migration trigger, strict Load, and an 8h --ttl default in BOTH CLIs. The AC that macOS must stop seeing a new background identity was measured, not read: base ad-hoc signing yields cdhash-bound designated requirements that differ per build (1312eeb1 vs 51893f84); candidate signing yields the identical identifier-only requirement across two binaries with different content hashes, and setup.sh DR guard fires on the base-style signature. Installed smoke against the real installed CLI in a sandboxed HOME: all three deadline refusals exit 2 with no browser contact, heartbeat run on expired state exits 0 and removes state/plist/log tolerating the absent launchd service, status on expired reports expired/deadline-expired and cleans without a probe, status/list on legacy state report migration-required/missing-deadline. Non-blocking: NewConfig past-deadline clause, Run post-probe expiry re-check and Start validateConfig each survive narrowing untested but are redundant second layers with no reachable bypass; isMissingLaunchAgent matches the bare substring 113 anywhere in the launchctl error text, which includes the service label, so a legal heartbeat name like hb113 misclassifies a genuine bootout failure (pre-existing at base, but expire() removes plist/state before bootout so a swallowed failure strands a throttled respawn job - suggest a follow-up bug); Safari heartbeat restart on an expired heartbeat reports a raw ENOENT because requireSafariHeartbeat Inspect deletes the state first, while Chrome restart renews cleanly. STRUCTURAL NOTE FOR ORCHESTRATOR: this candidate tree is a shared-worktree snapshot and bundles unaccepted sibling work - fetch_file.* (BUG-260825-2s6iw4, to-dev), trusted_input.*/ax_darwin.*/focus rework (BUG-260825-1wsh7n, to-dev) and the RedactSensitiveURL rewrite. None of that was reviewed here. This acceptance covers only internal/browsersession/heartbeat.go+test, the heartbeat subcommands in both CLIs and their tests, scripts/setup.sh, scripts/deinit.sh, scripts/deinit_test.go and the heartbeat docs. Do not integrate the whole tree as this task scope.
agent completed: [reviewer] reviewer (claude) (exit=143)
spawn run completed: claude (run=RUN-260825-1027f1, pid=30297, exit=143)
spawn run RUN-260825-1027f1 cancelled by operator; operator action required; reason: no operator reason supplied
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260826-2ee573, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260826-2ee573)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260826-2ee573, pid=88739, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (codex) (run=RUN-260826-deaa15, max_parallel=20)
spawn run started: [reviewer] reviewer (codex) (run=RUN-260826-deaa15)
agent completed: [reviewer] reviewer (codex) (exit=0)
spawn run completed: codex (run=RUN-260826-deaa15, pid=92908, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260826-1c657f, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260826-1c657f)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260826-1c657f, pid=11104, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (codex) (run=RUN-260826-d73d45, max_parallel=20)
spawn run started: [reviewer] reviewer (codex) (run=RUN-260826-d73d45)
agent completed: [reviewer] reviewer (codex) (exit=0)
spawn run completed: codex (run=RUN-260826-d73d45, pid=26866, exit=0)

## Precondition Resources
(none)

## Outcome Resources
- [TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260825-db66cb.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260825-db66cb.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_results.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_results.md) — Developer implementation, validation, mutation, install, and migration evidence
- [TASK-260824-2x6qiu_change-request_rev1.patch](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_change-request_rev1.patch) — Change Request CR-TASK-260824-2x6qiu-1 revision 1 candidate patch (repository_delta=present, 25 changed paths)
- [TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--claude-_RUN-260825-b9688a.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--claude-_RUN-260825-b9688a.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_review-verdict.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_review-verdict.md) — Revision 4 reviewer verdict: accepted after exact-tree gates and production-path bootout classifier attacks
- [TASK-260824-2x6qiu_review-mutants.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_review-mutants.log) — Mutation log for the rev2 review: 10 gate mutants killed, 3 redundant-layer survivors, plus the isMissingLaunchAgent substring-113 probe
- [TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260825-e05214.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260825-e05214.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_rework-results.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_rework-results.md) — Developer rework, negative mutants, validation, install, and runtime evidence
- [TASK-260824-2x6qiu_change-request_rev2.patch](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_change-request_rev2.patch) — Change Request CR-TASK-260824-2x6qiu-2 revision 2 candidate patch (repository_delta=present, 29 changed paths)
- [TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--claude-_RUN-260825-1027f1.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--claude-_RUN-260825-1027f1.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_review-verdict-rev2.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_review-verdict-rev2.md) — Reviewer verdict for CR-TASK-260824-2x6qiu-2 rev2 (RUN-260825-1027f1): ACCEPTED, with AC-by-AC evidence, installed smoke, codesign identity measurement and non-blocking findings
- [TASK-260824-2x6qiu_review-mutants-rev2.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_review-mutants-rev2.log) — Mutation log for the rev2 review: 10 gate mutants killed, 3 redundant-layer survivors, plus the isMissingLaunchAgent substring-113 probe
- [TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260826-2ee573.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260826-2ee573.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_recovery-validation.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_recovery-validation.md) — Recovery-only current-candidate validation and empty-delta evidence
- [TASK-260824-2x6qiu_change-request_rev3.patch](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_change-request_rev3.patch) — Change Request CR-TASK-260824-2x6qiu-3 revision 3 candidate patch (repository_delta=empty, 0 changed paths)
- [TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--codex-_RUN-260826-deaa15.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--codex-_RUN-260826-deaa15.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_review-bypass-probe-rev3.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_review-bypass-probe-rev3.log) — Revision 3 production-path expiry bootout bypass reproduction
- [TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260826-1c657f.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-implementer--developer--codex-_RUN-260826-1c657f.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_bootout-classification-rework.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_bootout-classification-rework.md) — Revision 3 bootout-classification rework, negative mutant, and exact-source validation evidence
- [TASK-260824-2x6qiu_change-request_rev4.patch](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_change-request_rev4.patch) — Change Request CR-TASK-260824-2x6qiu-4 revision 4 candidate patch (repository_delta=present, 3 changed paths)
- [TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--codex-_RUN-260826-d73d45.log](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_spawn-log_-reviewer--reviewer--codex-_RUN-260826-d73d45.log) — System spawn log captured by task-board
- [TASK-260824-2x6qiu_review-verdict-rev4.md](file://TASK-260824-2x6qiu/TASK-260824-2x6qiu_review-verdict-rev4.md) — Revision 4 reviewer verdict: accepted after exact-tree gates and production-path bootout classifier attacks

## Created
2026-08-23T22:00:25Z

## Last Update
2026-08-26T01:55:27Z

## Assigned To
[reviewer] reviewer (codex)
