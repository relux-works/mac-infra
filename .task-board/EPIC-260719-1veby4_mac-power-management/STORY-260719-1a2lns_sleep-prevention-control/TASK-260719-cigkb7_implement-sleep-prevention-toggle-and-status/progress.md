## Status
done

## Review
required

## Task Class
code

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Add fixed daemon protocol actions and absolute /usr/bin/pmset command plans for all-source enable and disable
- [x] Implement deterministic sleep-prevention status parsing and CLI output for AC and battery profiles
- [x] Add focused protocol, service, parser, and CLI tests including command failures and inconsistent status
- [x] Update README, mac-infra skill, setup/install guidance, and LOGBOOK without overwriting existing audio-sweep work
- [x] Run gofmt, go test ./..., build/setup checks, installed command smokes, git diff review, and task-board validate
- [x] Code written per task description and AC
- [x] Relevant tests written for new or changed behavior and passing
- [x] Lint clean
- [x] Relevant build/validation commands run after changes and build not broken
- [x] New outcome artifact attached on the board with a task-scoped name when the work produces notes, logs, screenshots, or other deliverables
- [x] Important findings, decisions, anomalies, or regressions recorded in logbook when relevant
- [x] Treat checklist item 2 as global SleepDisabled status plus applies_to AC,battery per revised task details; no per-profile disablesleep values
- [x] Implementation matches AC
- [x] Solution fits project architecture
- [x] Tests green
- [ ] If review does not accept the work — verdict evidence added and status routed by the explicit verdict branches

## Notes
spawn agent resolution: Agent selection: codex via runtime_affinity
spawn queued: [implementer] developer (codex) (run=RUN-260719-256a43, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260719-256a43)
2026-07-19 evidence correction: /usr/bin/pmset -g reports system-wide SleepDisabled=1 on this Mac, while pmset -g custom omits disablesleep. Interpret checklist item 2 as parsing the global value and reporting applies_to AC,battery; do not invent per-profile disablesleep fields.
STOP-THE-LINE: local macOS 26.5.1 evidence shows /usr/bin/pmset -g exposes one system-wide SleepDisabled=1, while /usr/bin/pmset -g custom exposes AC/Battery profiles with no disablesleep key. Apple PowerManagement source confirms ARG_DISABLESLEEP writes kIOPMSleepDisabledKey via IOPMSetSystemPowerSetting, outside per-source preferences. The assumption that AC and battery can differ is false; parsing sleep timers would violate scope, and duplicating the global value under two labels would make inconsistent state unreachable and misleading. Recommended option: revise AC to one system-wide enabled/disabled/unavailable status parsed from pmset -g; retain fixed daemon commands /usr/bin/pmset -a disablesleep 1|0. Exact decision needed: authorize that contract revision. Evidence and alternatives: TASK-260719-cigkb7_platform-constraint.md.
RESOLVED 2026-07-19: the user requested one enable/disable/status control that covers battery as well as AC. The orchestrator authorized the recommended system-wide contract and revised description/AC/precondition accordingly. No human decision remains; continue implementation. Amend the provisional LOGBOOK BLOCKED line to the resolved decision.
spawn agent resolution: Agent selection: codex via runtime_affinity
spawn queued: [implementer] developer (codex) (run=RUN-260719-aa2335, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260719-aa2335)
Implementation checkpoint: added typed fixed sleep_prevention_enable/disable protocol actions, daemon-only /usr/bin/pmset -a disablesleep 1|0 plans, direct read-only /usr/bin/pmset -g inspection, strict global SleepDisabled parser, CLI output with applies_to AC,battery, and focused protocol/service/parser/CLI tests. First focused go test exited 1 because two Darwin test socket paths exceeded the Unix-socket length limit; shortened fixture prefixes only. Exact rerun go test ./internal/maccore ./cmd/mac-infra-core exited 0. Existing audio-sweep changes remain preserved.
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260719-aa2335, pid=49631, exit=0)
spawn agent resolution: Agent selection: codex via runtime_affinity
spawn queued: [reviewer] reviewer (codex) (run=RUN-260719-2a9276, max_parallel=20)
spawn run started: [reviewer] reviewer (codex) (run=RUN-260719-2a9276)
Reviewer verdict: accepted. Independent AC mapping and validation evidence are attached as TASK-260719-cigkb7_review-verdict.md; no rework findings.
agent completed: [reviewer] reviewer (codex) (exit=0)
spawn run completed: codex (run=RUN-260719-2a9276, pid=58197, exit=0)

## Precondition Resources
- [TASK-260719-cigkb7_sleep-prevention-context.md](file://TASK-260719-cigkb7/TASK-260719-cigkb7_sleep-prevention-context.md) — Recovered power-policy evidence and worktree constraints

## Outcome Resources
- [TASK-260719-cigkb7_spawn-log_-implementer--developer--codex-_RUN-260719-256a43.log](file://TASK-260719-cigkb7/TASK-260719-cigkb7_spawn-log_-implementer--developer--codex-_RUN-260719-256a43.log) — System spawn log captured by task-board
- [TASK-260719-cigkb7_platform-constraint.md](file://TASK-260719-cigkb7/TASK-260719-cigkb7_platform-constraint.md) — Evidence-backed pmset system-wide state constraint, options, and required decision
- [TASK-260719-cigkb7_spawn-log_-implementer--developer--codex-_RUN-260719-aa2335.log](file://TASK-260719-cigkb7/TASK-260719-cigkb7_spawn-log_-implementer--developer--codex-_RUN-260719-aa2335.log) — System spawn log captured by task-board
- [TASK-260719-cigkb7_results.md](file://TASK-260719-cigkb7/TASK-260719-cigkb7_results.md) — Implementation summary, validation exit codes, coverage, worktree preservation, and live-mutation boundary
- [TASK-260719-cigkb7_spawn-log_-reviewer--reviewer--codex-_RUN-260719-2a9276.log](file://TASK-260719-cigkb7/TASK-260719-cigkb7_spawn-log_-reviewer--reviewer--codex-_RUN-260719-2a9276.log) — System spawn log captured by task-board
- [TASK-260719-cigkb7_review-verdict.md](file://TASK-260719-cigkb7/TASK-260719-cigkb7_review-verdict.md) — Independent accepted reviewer verdict, AC mapping, validation, and worktree-safety evidence

## Created
2026-07-19T14:17:32Z

## Last Update
2026-07-19T14:54:24Z

## Assigned To
[reviewer] reviewer (codex)
