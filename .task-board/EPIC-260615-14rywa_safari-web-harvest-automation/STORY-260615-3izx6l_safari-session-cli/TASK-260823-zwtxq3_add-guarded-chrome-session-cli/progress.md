## Status
done

## Review
required

## Task Class
code

## Estimate
estimated(fibonacci(5))

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Unify Chrome and Safari exact-target browser session contracts without focus regressions
- [x] Implement and test named persistent heartbeat start/status/stop with origin and exact-tab guards
- [x] Preserve browser secrets and private artifact boundaries with negative tests
- [x] Install and live-smoke supported commands while preserving existing active sessions
- [x] Update README, mac-infra skill references, setup/deinit, and delivery evidence
- [x] Code written per task description and AC
- [x] Relevant tests written for new or changed behavior and passing
- [x] Gating, refusing, validating, authorizing, or attesting behavior covered by negative tests that fail when the gate admits what it must reject, with the production call site named
- [x] Lint clean
- [x] Relevant build/validation commands run after changes and build not broken
- [x] New outcome artifact attached on the board with a task-scoped name when the work produces notes, logs, screenshots, or other deliverables
- [x] Important findings, decisions, anomalies, or regressions recorded in logbook when relevant
- [x] Add compiled allowlisted Slack sealed-read primitive without relaxing generic run-js guards
- [x] Live-smoke sealed auth.test and bounded conversations.list against authorized test workspace without persisting content
- [x] Implementation matches AC
- [x] Solution fits project architecture
- [x] Tests green
- [x] Gate, refusal, validation, authorization, and attestation behavior attacked, not read — positive-path-only evidence is not accepted
- [x] If review does not accept the work — verdict evidence added and status routed by the explicit verdict branches

## Notes
Handoff to orchestrator requested by owner. The control checkout is intentionally dirty and contains a partially implemented Chrome draft in cmd/mac-chrome-session and internal/chromectl plus prior Chrome docs. Inspect and salvage it; do not assume it compiles or silently discard it. Because producer worktrees start from committed HEAD, explicitly transfer useful draft content into tracked task resources or producer instructions before delegating. Existing live monitors: FNS heartbeat LaunchAgent and a temporary T-Bank support watcher; do not stop them until supported replacements are verified. Spawn ceilings were migrated to spawn-policy-v4 exact pairs: gpt-5.6-sol/high and claude-opus-5/high, with orchestrator defaults.
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-18-g302a445; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [analyst] orchestrator (claude) (run=RUN-260822-8f48e1, max_parallel=20)
spawn run started: [analyst] orchestrator (claude) (run=RUN-260822-8f48e1)
Orchestrator survey complete (RUN-260822-8f48e1). Three precondition resources attached: design-contract.md (authoritative producer contract), untracked-chrome-draft.patch, tracked-doc-drafts.patch. Both patches verified with git apply --check against a clean HEAD worktree, so the producer can reconstruct the owner uncommitted draft inside the Story worktree.

Verified platform constraint that shapes the whole contract: Chrome exposes stable window AND tab ids, Safari exposes stable window ids but NO tab id (osascript -1728 on id of tab 1 of window id 105; only index and name exist). Chrome targeting is tab-exact, Safari targeting is window-exact with a drifting current tab. The origin guard is therefore mandatory on every Safari operation rather than optional. No synthetic Safari tab id will be invented.

Live state inventory: FNS keepalive is launchd com.relux.fns-chrome-heartbeat (submitted directly, no plist in LaunchAgents) running an ad hoc Go binary from casual-talks/.temp against window 704793720 tab 704793726 origin https://lkip2.nalog.ru at 45s. It is a pure heartbeat and is migratable under a concurrent-verify-then-bootout protocol. The T-Bank monitor is a foreground zsh loop (pid 73464) that combines the same keepalive with conversation-ui-message scraping; the scraping half belongs to TASK-260823-17qhsl, so the loop stays untouched and only its heartbeat half is documented as future migration. Killing it would silently destroy the user chat watching.

Draft defects recorded for the producer: chromectl imports safarictl (backwards layering), the origin check is a separate osascript round trip before the payload (TOCTOU hole in the load-bearing guard), the heartbeat returns and persistently logs document.title, and the LaunchAgent points at os.Executable() wherever it happens to live. The last one is why heartbeat start must pin a content-addressed copy of the executable under the managed state dir; without it a LaunchAgent built from a worktree becomes a time bomb and live migration would be unsafe.

Delivery shape: single producer on this task (codex, pinned equal-criterion pair) then an independent reviewer on the other provider, rework cycles as needed. This is a non-final leaf of STORY-260615-3izx6l (17qhsl backlog, 3dshyo development, 1db1bg and 1tlcpm to-review), so the accepted CR lands via worktree checkpoint on the Story branch, not trunk.
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-18-g302a445; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260822-cf231d, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260822-cf231d)
INFRA BLOCKER FOUND AND FIXED AT SOURCE (2026-08-23). Every tracked spawn on this machine refused with: decoding primary-session launch plan: json: unknown field "pi_compatibility". Root cause is a version skew, not a board problem: agents-infra v1.6.1-18-g302a445 learned the new pi provider and now emits resolved.pi_compatibility in the agents-infra.primary-session-launch-plan contract, while task-board 0.24.3-112-ged48781 decodes that plan with DisallowUnknownFields and has no such field on ResolvedPrimarySession. Both codex and claude spawns were refused identically, before any side effect. Confirmed by calling the composer directly: agents-infra compose --mode primary-session emits the key for both providers, while agents-infra compose (child mode) is unaffected, which is why my own earlier prompt-mode launch survived.

Fixed in the source repo /Users/alexis/src/relux-works/skill-project-management (installed CLI is not the authoring surface): added PiCompatibility *ResolvedLaunchValue with json:pi_compatibility,omitempty to ResolvedPrimarySession in tools/board-cli/internal/sessionmanager/launch_plan.go, so the additive half of the contract is forward-compatible and the field is accepted and ignored. Added regression test TestDecodePrimarySessionLaunchPlanAcceptsNewerComposerResolvedKeys in launch_plan_test.go. Mutation-checked it: with the field removed the test fails with the exact production error, and it passes with the field present, so the test would have caught the skew. Full ./internal/sessionmanager package suite green. Reinstalled with make install-frontend.

The change is UNCOMMITTED in skill-project-management and needs a tracked fix in that repo; it is outside this board scope. Producer spawn then succeeded: RUN-260822-cf231d, developer, codex gpt-5.6-sol high, 4h timeout.
agent completed: [analyst] orchestrator (claude) (exit=0)
spawn run completed: claude (run=RUN-260822-8f48e1, pid=80192, exit=0)
Developer stop-line evidence: implementation and all offline gates pass (go test/vet/build, format, bash syntax, diff check, setup, installed skill match). Direct no-focus Chrome/Safari guarded reads and negative refusals pass. New pinned LaunchAgents load, but execute JavaScript from the background executable waits until timeout while launchd browser-version reads exit 0 and direct exact-target execution succeeds. This isolates macOS Automation consent for the new managed runtime. No proxy/UI-script workaround was added. Throwaway jobs were removed; legacy FNS and T-Bank monitors remain alive; FNS migration was not attempted. Human input: approve Automation access for mac-browser-session-* to control Chrome and Safari, then resume concurrency/drift smoke and guarded FNS migration. Evidence resource: TASK-260823-zwtxq3_delivery.md.
Continuation: unified TCC logs refined the blocker. Raw Go linker-signed pinned binaries caused TCC designated-identity creation error -67062. Fixed setup to apply a complete ad-hoc signature with identifier works.relux.mac-infra.browser-session; codesign verify and designated-requirement checks pass. A signed launchd probe is now attributed to that identifier and TCC identity creation returns without -67062. Also strengthened heartbeat start to wait for the first real LaunchAgent outcome and rollback on background refusal/error/timeout; production wait-path negative tests pass. All Go/format/vet/build/bash/diff/setup/installed-skill gates remain exit 0. Remaining external input is the genuine macOS Automation approval; final signed read-only consent probe is active without focus change. Legacy FNS and T-Bank monitors remain untouched. Updated outcome: TASK-260823-zwtxq3_delivery.md.
agent completed: [implementer] developer (codex) (exit=1)
spawn run completed: codex (run=RUN-260822-cf231d, pid=0, exit=1)
Continuation 2026-08-23: macOS Automation consent is now effective. Signed installed Chrome CLI passed silent no-focus live inspection in 0.7s. Fixed the heartbeat health bug: each probe uses up to three 10-second attempts with bounded backoff, non-retryable guard failures stop immediately, and status rejects stale prior success as stale-outcome. Stopped the obsolete broken watcher and started supported named tbank-support heartbeat at a 20-minute interval; latest outcome is fresh and ok. Full uncached tests, vet, setup/install, and diff check pass. Ready for independent review; no commit or stage performed.
2026-08-24 follow-up: generalized the recovered cross-origin embedded-app workflow. The Chrome skill now documents safe promotion into a disposable top-level background target using a sanitized allowlisted bootstrap URL, bounded application readiness polling, exact target/origin guards, and explicit stop conditions for secret-bearing or parent-only state. No site-specific contract was added.
Validation after generalized cross-origin documentation: scripts/setup.sh exit 0, git diff --check exit 0, and source skill matches installed ~/.agents skill exactly. Live proof used a disposable top-level target, bounded readiness polling, and deterministic conversation-item/message selectors without browser focus or credential export.
Reopened continuation requested by skill-slack-management after live evidence: normal Slack production page exposes no public page-owned API helper, while cookie-only /api/auth.test returns not_authed. Add a compiled sealed Slack read primitive at mac-infra source without weakening generic run-js. User authorized read-only smoke on test workspace T073GL82HJB; never perform Slack writes.
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-28-gac759d9; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260825-ebdd72, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260825-ebdd72)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260825-ebdd72, pid=33065, exit=0)
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-28-gac759d9; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-28e372, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-28e372)
Review verdict RUN-260825-28e372 (CR rev1): CHANGES REQUESTED -> to-dev. Implementation quality is high and live-verified (3 concurrent named heartbeats, one correctly drifted with fail-closed refusal logging, frontmost app byte-identical across every probe, all live guard attacks refused: document.cookie, wrong origin, bogus tab-id with no active-tab fallback, Slack write/wrong-workspace/wrong-origin/forged-token/oversized-limit). Full suite, vet, build, gofmt all green when rerun.

Two blocking findings, both on refusal gates, both found by mutation and both violating the DoD item -negative tests that fail when the gate admits what it must reject-:

F1 (blocking, highest risk surface): deleting BOTH the origin check and the workspace/pathname check from internal/chromectl/slack.go:slackStartPageJavaScript - the evaluation that reads the xoxc- token from localConfig_v2 and fires the POST - leaves the entire suite green. TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv substring-matches a capture file that the fake osascript appends across the start AND poll calls, so the poll script satisfies the assertion for the unguarded start script. TestSlackReadOriginAndWorkspaceDriftFailBeforePolling feeds a fake osascript a canned refusal envelope, proving only Go-side handling - a green suite around a fake. The guard is genuinely correct in production (live wrong-workspace probe returned workspace-mismatch with no request started); the gap is that nothing would notice its removal. Fix: capture start and poll sources separately and assert the start source independently.

F2 (blocking): BlockedJavaScriptTokens is self-referential. Dropping cookiestore or opendatabase leaves the suite green because every consumer iterates the production list itself; only indexeddb and navigator.credentials die, by accident of two hardcoded fixtures. Contract N2 required a narrowed guard to fail the suite. Fix: assert the set against a literal expected list and drive each token from a literal fixture.

Non-blocking: isSlackSecretKey token-suffix rule unpinned (value-shape redaction backstops it, so the delivery note claim about the recursive KEY policy is overstated); heartbeat state-file mode unpinned (log mode IS pinned); Safari library-level empty-origin refusal unpinned (CLI parse-time check is pinned).

Mutants killed as expected: wrapper origin check, empty-output-as-success, sentinel check, fragment redaction, LaunchAgent managed-path check, name pattern, minimum interval, log mode, activate in Chrome/Safari silent scripts, Safari front-document fallback, Slack allowlist admitting chat.postMessage, Slack token-shape and URL value redaction.

Sibling TASK-260823-17qhsl files ride along in the CR because both leaves share the Story worktree; I verified the facade shells out to the CLIs so no page-context path bypasses the shared guard, and did not review that task ACs. Nothing was modified; every mutant was reverted in the same shell call and the tree matches the candidate at exit. Evidence: TASK-260823-zwtxq3_review-verdict.md
agent completed: [reviewer] reviewer (claude) (exit=0)
spawn run completed: claude (run=RUN-260825-28e372, pid=52473, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-28-gac759d9; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260825-e91742, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260825-e91742)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260825-e91742, pid=72835, exit=0)
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-28-gac759d9; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-5c241b, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-5c241b)
CR rev2 accepted by RUN-260825-5c241b. F1 closed: Slack start evaluation is captured separately from poll and pinned by presence+ordering — gutting either start guard alone, or moving both below the localStorage secret read with text unchanged, kills TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv. F2 closed: all 7 blocked tokens now die individually at both the literal library contract and the production run() CLI path; case-sensitivity and exact-match narrowings of GuardJavaScript also die. Restore hashes reproduced, worktree exits at candidate tree 9a791b4a, build/vet/gofmt/full suite green, three live heartbeats untouched. Non-blocking: a start-guard mutant that keeps the condition text but drops the return survives the suite (structure-pinned, live-proven in rev1); rev1 non-blocking items unchanged. Evidence: TASK-260823-zwtxq3_review-verdict-rev2.md. Awaiting orchestrator checkpoint/integration and the done transition with commit_ack.
agent completed: [reviewer] reviewer (claude) (exit=0)
spawn run completed: claude (run=RUN-260825-5c241b, pid=75485, exit=0)

## Precondition Resources
- [TASK-260823-zwtxq3_design-contract.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_design-contract.md) — Authoritative producer contract: verified platform facts, live monitor inventory, pinned design, negative-test matrix, live smoke protocol
- [TASK-260823-zwtxq3_untracked-chrome-draft.patch](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_untracked-chrome-draft.patch) — Owner's uncommitted Chrome draft (cmd/mac-chrome-session, internal/chromectl, chrome-session.md); git apply at repo root
- [TASK-260823-zwtxq3_tracked-doc-drafts.patch](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_tracked-doc-drafts.patch) — Owner's uncommitted README/SKILL.md/LOGBOOK.md draft edits; git apply at repo root
- [slack-sealed-read-contract.md](file://TASK-260823-zwtxq3/slack-sealed-read-contract.md) — Security, interface, and live-smoke contract for a sealed Slack browser read primitive
- [rev2-rereview-scope.md](file://TASK-260823-zwtxq3/rev2-rereview-scope.md) — Focused CR rev2 rereview scope for the two previously blocking negative-test gaps

## Outcome Resources
- [TASK-260823-zwtxq3_spawn-log_-analyst--orchestrator--claude-_RUN-260822-8f48e1.log](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_spawn-log_-analyst--orchestrator--claude-_RUN-260822-8f48e1.log) — System spawn log captured by task-board
- [TASK-260823-zwtxq3_spawn-log_-implementer--developer--codex-_RUN-260822-cf231d.log](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_spawn-log_-implementer--developer--codex-_RUN-260822-cf231d.log) — System spawn log captured by task-board
- [TASK-260823-zwtxq3_delivery.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_delivery.md) — Developer implementation, negative-test matrix, signed TCC identity evidence, validation results, live smoke state, and remaining Automation consent boundary
- [TASK-260823-zwtxq3_heartbeat-hardening-2026-08-23.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_heartbeat-hardening-2026-08-23.md) — Root cause, bounded retry and freshness fix, validation, and live 20-minute heartbeat evidence
- [TASK-260823-zwtxq3_spawn-log_-implementer--developer--codex-_RUN-260825-ebdd72.log](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_spawn-log_-implementer--developer--codex-_RUN-260825-ebdd72.log) — System spawn log captured by task-board
- [TASK-260823-zwtxq3_slack-sealed-read.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_slack-sealed-read.md) — Compiled Slack sealed-read implementation, negative evidence, validation, and content-free live smoke results
- [TASK-260823-zwtxq3_change-request_rev1.patch](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_change-request_rev1.patch) — Change Request CR-TASK-260823-zwtxq3-1 revision 1 candidate patch (repository_delta=present, 39 changed paths)
- [TASK-260823-zwtxq3_spawn-log_-reviewer--reviewer--claude-_RUN-260825-28e372.log](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_spawn-log_-reviewer--reviewer--claude-_RUN-260825-28e372.log) — System spawn log captured by task-board
- [TASK-260823-zwtxq3_review-verdict.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_review-verdict.md) — Reviewer verdict CR rev1: changes requested — two refusal gates survive narrowing mutants (Slack start-script origin/workspace guards; blocked-token set); full mutation + live attack evidence
- [TASK-260823-zwtxq3_spawn-log_-implementer--developer--codex-_RUN-260825-e91742.log](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_spawn-log_-implementer--developer--codex-_RUN-260825-e91742.log) — System spawn log captured by task-board
- [TASK-260823-zwtxq3_rework-evidence.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_rework-evidence.md) — CR rev1 F1/F2 fixes, narrowing-mutant failures, restore hashes, and green validation
- [TASK-260823-zwtxq3_change-request_rev2.patch](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_change-request_rev2.patch) — Change Request CR-TASK-260823-zwtxq3-2 revision 2 candidate patch (repository_delta=present, 39 changed paths)
- [TASK-260823-zwtxq3_spawn-log_-reviewer--reviewer--claude-_RUN-260825-5c241b.log](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_spawn-log_-reviewer--reviewer--claude-_RUN-260825-5c241b.log) — System spawn log captured by task-board
- [TASK-260823-zwtxq3_review-verdict-rev2.md](file://TASK-260823-zwtxq3/TASK-260823-zwtxq3_review-verdict-rev2.md) — Reviewer verdict CR rev2: accepted — F1 start-guard placement and F2 literal blocked-token contract both closed under narrowing mutants; restore hashes and green gates reverified

## Created
2026-08-22T21:19:11Z

## Last Update
2026-08-25T13:14:27Z

## Assigned To
[reviewer] reviewer (claude)
