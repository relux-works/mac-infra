# 7. Seeing and limiting the network

A quiet network digest can mean few noteworthy events or missing collection.
How does mac-infra distinguish evidence from enforcement, and make missing coverage visible?
This chapter follows local security collection, application-firewall management, shadow classification and netfilter control.
Chapter 6 covers installation of the privileged helper.
The distinction starts with recorded collection spans rather than an assumption that retained events cover the requested interval.
(*source*: `internal/security/firewallwatch/split.go`, `Store.coverageGaps`.)

## Collect evidence without changing policy

`mac-security` reads SIP, Gatekeeper and FileVault state and explicit update preferences.
Persistence collection fingerprints system and current-user launchd files, periodic/cron sources and privileged helpers.
Exposure collection reads visible TCP listeners, firewall state and sharing overrides.
Its indicator sweep examines fixed temporary and launchd names, fixed shell files and visible numeric network endpoints.
SSH collection reads fixed configuration sources, checks authorized-key presence without opening their contents, and counts agent identities without reporting comments or fingerprints.
These collectors change no host settings or services.
Their runner permits a fixed read-only command vocabulary without sudo or a shell; this is a tool restriction.
Commands belong in the [security runbook](../../../agents/skills/mac-infra/references/security.md).
(*source*: `internal/security/{posture,persistence,exposure,ioc,ssh}.go`, `Posture`, `Persistence`, `Exposure`, `IOC`, `scanSSH`; *tested*: `TestRunnerClosedVocabularyAndOutputBound`.)

An inaccessible source leaves missing evidence, not a clean result.
Listener coverage remains partial and excludes UDP; SSH declarations do not establish target-specific effective settings.
An XProtect version establishes neither freshness nor activation.
Login-item, profile and system-extension inventories remain partial and excluded from stable drift.
Explicit baseline capture writes a new `0600` artifact containing persistence paths, modes and fingerprints, rather than source contents.
It refuses overwrite.
Diff reports deletion only when both snapshots completely cover that source; the lost-coverage fixture suppresses deletion and marks the source unknown.
(*source*: `internal/security/{exposure,ssh,posture,persistence}.go`, `listenerExposure`, `scanSSH`, `xprotectPosture`, `Persistence`, `SaveBaseline`, `Compare`; *tested*: `TestPersistenceDriftAndLostCoverage`, `TestBaselinePrivateNoOverwriteAndValidation`.)

## Keep ALF on, recover failed changes

`mac-firewall` sends application-firewall (ALF) management requests to the `mac-infra-core` root helper, which revalidates configuration.
Planning is the default; mutation requires `apply --apply`.
The planner labels loosening steps and requires an Apple-anchored signature for newly allowing an application.
The execution vocabulary refuses global firewall-off even if a planner requests it.
Other loosening remains possible, including disabling stealth or block-all.
“Never off” therefore describes this tool's commands, not an operating-system prohibition on other actors.
Use the [firewall runbook](../../../agents/skills/mac-infra/references/firewall.md) for commands.
(*source*: `cmd/mac-firewall/main.go`, `run`; `internal/maccore/firewall_service.go`, `handle`; `internal/security/firewall/plan.go`, `BuildPlan`, `SystemResolver.VerifySigned`; *tested*: `TestAllowedArgv` for the execution vocabulary.)

An apply validates the complete plan before mutation and requires the intent audit write to succeed.
It runs the steps, reads back state and requires an empty residual plan.
Failure triggers reverse-order compensating undo on an independent two-minute budget.
Rollback deliberately leaves the firewall on if this apply enabled it.
The injected mid-apply failure restores the fixture's other state and removes its half-added application entry.
A failed restoration reports `rollback_failed` with drift; the operation is not atomic.
(*source*: `internal/security/firewall/engine.go`, `Engine.Apply`; `internal/maccore/firewall_service.go`, `handle`; *tested*: `TestFirewallApplyFailsClosedWithoutAudit`, `TestMidApplyFailureRollsBack`.)

Keep-on enforcement requires a managed marker written after an `applied` or `no_change` result.
The helper checks at startup and every five minutes, so this is periodic repair rather than continuous prevention.
A busy operation or unreadable marker can postpone repair.
Unlike apply, turning ALF back on does not wait for a successful audit write; audit failure is logged afterward.
This favors restoring protection when audit storage fails.
(*source*: `internal/maccore/firewall_service.go`, `handle`, `enforce`, `runEnforcement`; `internal/security/firewall/engine.go`, `EnforceOn`.)

## Read proposals with their missing coverage

Firewall watch observes ALF logs and sampled nettop traffic, writes observation state and proposes `noise`, `digest` or `decide`.
It changes no firewall rules and never initiates kills.
Deterministic rules precede weighted nearest-neighbour classification; unavailable classification returns `decide`, increasing review work instead of suppressing unmatched events.
ALF parsing recognizes verdict `1` as allow and preserves other codes without guessing deny.
ALF and nettop observations remain separate; sampling does not establish complete flow visibility.
(*source*: `internal/security/firewallwatch/{run,parse,classifier}.go`, `Run`, `ALFParser.Parse`, `ParseNettop`, `Classifier.Classify`; *tested*: `TestClassifierFailures`.)

`digest --json --split` separates retained events into at most one bucket each, with `real_deny` taking precedence over `known_fp`, then `needs_review`.
`real_deny` requires an explicit non-nettop blocking verdict, regardless of proposed label.
The named false-positive groups cover raw-IP nettop decisions, unknown/allow ALF decisions and kNN loopback decisions for SSH or limactl.
Other `decide` events need review; ordinary noise and digest events enter no bucket.
These are triage categories, not proof that a grouped event is harmless.
The output also includes saved health and window metadata.
(*source*: `internal/security/firewallwatch/split.go`, `Store.Split`; *tested*: `TestSplitBuckets`.)

A stopped collector, restart or full line queue can leave a coverage gap.
The split window reports gaps and eviction through a timestamp; either a gap or eviction within the window sets `truncated`.
Its gaps cover ALF spans only, although netfilter records separate spans.
A tail within `nettop_interval + save_interval` receives grace after a span reaches the window, so a recent death can remain undetected.
Saved health is not a live probe.
Inspect these limits before interpreting an empty bucket.
(*source*: `internal/security/firewallwatch/{split,store}.go`, `coverageGaps`, `Split`, `Status`; *tested*: `TestCoverageStallIsGap`, `TestSplitCoverageTruncation`, `TestSplitEvictionTruncation`.)

## Attribute flows before operator enforcement

Netfilter adds per-flow application and destination metadata through a content-filter system extension.
Identity resolution tries the source application's audit token, then a PID/path fallback guarded by process start times.
Failed resolution remains explicit.
Signing labels describe retrieved signing metadata, not an independent signature-validity verdict.
Without a decoded protect-list, new flows are allowed immediately and kill/block requests refuse.
With a list, protected flows remain allowed; other flows can stay watched for a later kill or be dropped by an active block.
Observe-only is the default, not the only implemented behavior.
(*source*: `apps/netfilter/Shared/AppIdentity.swift`, `resolve`, `signingFacts`; `apps/netfilter/Shared/Enforcement.swift`, `Engine.decideNewFlow`, `handle`; *tested*: Swift `noProtectListMeansNoEnforcement` for the absent-list engine case.)

The operator contract calls for an owner-installed, root-owned protect-list before enforcement.
Both loaders now check that contract before decoding any bytes.
They walk from `/` one directory descriptor at a time without following symlinks, and require each ancestor to be a root-owned directory without group or world write.
The file itself must be a regular file with a single link, owned by root, without group or world write or set-ID and sticky bits.
The bytes are read only from that checked descriptor, and any refusal leaves enforcement off with a specific reason.
The tests cover each refusal with the current user standing in for root; a file owned by another user cannot be created without root, so the file-owner branch is checked by inspection rather than a dedicated case.
The CLI also accepts an explicit list path while the extension reads its fixed path.
These paths need not identify the same bytes.
Blocks expire within 24 hours and live only in memory, so extension restart clears them.
(*source*: `agents/skills/mac-infra/references/firewall.md`, “Netfilter kill path”; `internal/security/netfilterctl/protect_file.go`, `readProtectList`; `internal/security/netfilterctl/ctl.go`, `LoadProtectList`; `apps/netfilter/Shared/ProtectListFile.swift`, `ProtectList.load`; `apps/netfilter/Extension/Control.swift`, `reloadProtectList`; `apps/netfilter/Shared/Enforcement.swift`, `RuleSet.add`, `Engine`; *tested*: `TestProtectListFileTrust` and Swift `protectListFileTrust`, the same case table.)

The operator CLI checks its list, then journals and syncs an intent before invoking the app; afterward it journals the result.
A journal failure prevents sending the request in the corrupt-journal fixture.
Successful kill/block replies trigger a pending-report append and report text, but the CLI does not post it.
Later journal failures do not undo enforcement.
With netfilter collection enabled, watch reconciles observed successful kill/block/unblock actions against matching actor, operation and target intents within two minutes, allowing two seconds of timestamp slack.
Unmatched actions append `reconcile_mismatch`; refusals do not alarm.
This detects observed discrepancies after the action rather than enforcing journaling inside the extension.
(*source*: `internal/security/netfilterctl/ctl.go`, `Execute`; `internal/security/journal/journal.go`, `Append`; `internal/security/firewallwatch/reconcile.go`, `ReconcileAction`; *tested*: `TestNoKillWithoutJournal`, `TestReconcileAction`.)

## What this does not protect against

Same-user processes are not isolated: root-helper admission identifies a UID, not an individual agent.
The journal's hash chain supplies consistency within its retained window, not protection against its owner's rewrite.
The signed NetFilter app can send control requests directly, bypassing the Go journal workflow.
Its actor label is caller-supplied, not an authenticated agent identity.
Local evidence does not establish absence of compromise.
Treat missing coverage and rollback drift as unresolved operator work before relying on the resulting report.
(*source*: `internal/maccore/service_peer_darwin.go`, `requireSocketPeer`; `internal/security/journal/journal.go`, `Verify`; `apps/netfilter/App/main.swift`, `control`, `controlRequest`; `internal/security/security.go`, `Summary`.)

**Status.** *Source* checked at `4394da05a3ee918581f5389d44527370bfeb6fa3`; the protect-list paragraph at `3e49742093a0fc2b0b5bd569a41cbb27f538bb60`, the only code change since.
*Tested* means assertions read, not fresh execution.
Live-host netfilter kill behavior is *unknown*: the admitted evidence does not include a live kill-path measurement.
No installed-state claim is made.
Installed builds may lag source.

## Sources

| Paragraph | Repository-relative path and function or symbol | Test asserting the cited case |
| --- | --- | --- |
| Quiet digest | `internal/security/firewallwatch/split.go`: `coverageGaps` | Source only |
| Collector inputs | `internal/security/{posture,persistence,exposure,ioc,ssh,security}.go`: `Posture`, `Persistence`, `Exposure`, `IOC`, `scanSSH`, `CommandRunner.Run` | `internal/security/security_test.go`: `TestRunnerClosedVocabularyAndOutputBound` |
| Missing evidence and baseline | `internal/security/{exposure,ssh,posture,persistence}.go`: `listenerExposure`, `scanSSH`, `xprotectPosture`, `Persistence`, `SaveBaseline`, `Compare` | `internal/security/persistence_test.go`: `TestPersistenceDriftAndLostCoverage`, `TestBaselinePrivateNoOverwriteAndValidation` |
| ALF admission | `cmd/mac-firewall/main.go`: `run`; `internal/maccore/firewall_service.go`: `handle`; `internal/security/firewall/{plan,runner}.go`: `BuildPlan`, `SystemResolver.VerifySigned`, `allowedArgv` | `internal/security/firewall/firewall_test.go`: `TestAllowedArgv` |
| Apply and rollback | `internal/security/firewall/engine.go`: `Apply`; `internal/maccore/firewall_service.go`: `handle` | `internal/maccore/firewall_service_test.go`: `TestFirewallApplyFailsClosedWithoutAudit`; `internal/security/firewall/firewall_test.go`: `TestMidApplyFailureRollsBack` |
| Periodic repair | `internal/maccore/firewall_service.go`: `handle`, `enforce`, `runEnforcement` | Source only |
| Shadow proposals | `internal/security/firewallwatch/{run,parse,classifier}.go`: `Run`, `Parse`, `ParseNettop`, `Classify` | `internal/security/firewallwatch/classifier_test.go`: `TestClassifierFailures` |
| Split buckets | `internal/security/firewallwatch/split.go`: `Split` | `internal/security/firewallwatch/split_test.go`: `TestSplitBuckets` |
| Coverage limits | `internal/security/firewallwatch/{split,store}.go`: `coverageGaps`, `Split`, `Status`; `cmd/mac-firewall/watch.go`: `runWatch` | `internal/security/firewallwatch/split_test.go`: `TestCoverageStallIsGap`, `TestSplitCoverageTruncation`, `TestSplitEvictionTruncation` |
| Attribution and default | `apps/netfilter/Shared/{AppIdentity,Enforcement}.swift`: `resolve`, `signingFacts`, `Engine` | `apps/netfilter/Tests/NetFilterIdentityTests/EnforcementTests.swift`: `noProtectListMeansNoEnforcement` (pure engine) |
| Protect-list checks | `agents/skills/mac-infra/references/firewall.md`: kill-path contract; `internal/security/netfilterctl/protect_file.go`: `readProtectList`; `internal/security/netfilterctl/ctl.go`: `LoadProtectList`; `apps/netfilter/Shared/ProtectListFile.swift`: `ProtectList.load`; `apps/netfilter/Extension/Control.swift`: `reloadProtectList`; `apps/netfilter/Shared/Enforcement.swift`: `RuleSet`, `Engine` | `internal/security/netfilterctl/ctl_test.go`: `TestProtectListFileTrust`; `apps/netfilter/Tests/NetFilterIdentityTests/ProtectListFileTests.swift`: `protectListFileTrust` |
| Journal and reconciliation | `internal/security/netfilterctl/ctl.go`: `Execute`; `internal/security/journal/journal.go`: `Append`; `internal/security/firewallwatch/reconcile.go`: `ReconcileAction` | `internal/security/netfilterctl/ctl_test.go`: `TestNoKillWithoutJournal`; `internal/security/firewallwatch/reconcile_test.go`: `TestReconcileAction` |
| Protection limits | `internal/maccore/service_peer_darwin.go`: `requireSocketPeer`; `internal/security/journal/journal.go`: `Verify`; `apps/netfilter/App/main.swift`: `control`, `controlRequest`; `internal/security/security.go`: `Summary` | Source and architectural inference |
| Status | Job pin and admitted evidence boundary | No execution or live-host claim |
