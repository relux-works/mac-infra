## Status
done

## Assigned To
[reviewer] reviewer (codex)

## Created
2026-06-15T10:57:55Z

## Last Update
2026-08-26T00:50:05Z

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [x] Document Safari Apple Events background mode and permission preflight
- [x] Design no-cookie-export authenticated harvest flow
- [x] Design page-context fetch plus base64/chunk transfer fallback
- [x] Decide CLI surface and skill trigger additions
- [x] Link MTS regulations project notes as source artifact
- [x] Implement reusable Safari browser automation CLI
- [x] Update README tools documentation
- [x] Update source mac-infra skill and install artifacts
- [x] Run tests/build/setup verification
- [x] Implementation matches AC
- [x] Solution fits project architecture
- [x] Tests green
- [x] Gate, refusal, validation, authorization, and attestation behavior attacked, not read — positive-path-only evidence is not accepted
- [x] If review does not accept the work — verdict evidence added and status routed by the explicit verdict branches
- [x] Code written per task description and AC
- [x] Relevant tests written for new or changed behavior and passing
- [x] Gating, refusing, validating, authorizing, or attesting behavior covered by negative tests that fail when the gate admits what it must reject, with the production call site named
- [x] Lint clean
- [x] Relevant build/validation commands run after changes and build not broken
- [x] New outcome artifact attached on the board with a task-scoped name when the work produces notes, logs, screenshots, or other deliverables
- [x] Important findings, decisions, anomalies, or regressions recorded in logbook when relevant

## Notes
Source case: /Users/alexis/src/mts/mts-pjsc-regulations. Key artifacts: AGENTS.md, documents/harvesting-notes.md, .scripts/safari-session.zsh, .scripts/harvest-receiver.py. Direct curl to hello.mts.ru static document endpoint returns 401; successful path is Safari authenticated fetch -> base64 via AppleScript -> local decode. Localhost receiver POST was blocked by Safari with Load failed.
Added LOGBOOK.md entry for Safari browser-session harvest workflow and verification.
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-a03e26, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-a03e26)
agent completed: [reviewer] reviewer (claude) (exit=1)
spawn run completed: claude (run=RUN-260825-a03e26, pid=39869, exit=1)
spawn autonomous recovery: run RUN-260825-a03e26 queued successor RUN-260825-fb1f13 (attempt 1/3, model=claude-opus-5): spawned agent exited with code 1
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-fb1f13)
REVIEW VERDICT (RUN-260825-fb1f13): changes requested -> to-dev. Evidence: TASK-260615-1tlcpm_review-verdict.md.

BLOCKING F1 - cmd/mac-safari-session/main.go:377-395 fetch-file never compares the browser-reported blob size (meta.Bytes) against the decoded/written length. ActualBytesWritten is assigned and serialized but compared to nothing (2 grep hits repo-wide). ReadFetchChunkJavaScript returns "" whenever window.__macSafariSessionFetchJob is gone, and with the default 250000 chunk size a dropped middle chunk stays base64 4-aligned, so decode succeeds. Reproduced through the production run() entry with a fake osascript: browser reported 400000 bytes, 212500 bytes written to disk, exit 0, stdout printed "saved:" and "bytes: 212500", and the meta artifact recorded 400000 next to 212500 without flagging. Origin guard does not cover it - a same-origin nav or tab switch wipes page globals with location.origin unchanged. Fix: verify decoded length against meta.Bytes before publishing the file and fail on mismatch; treat an unexpected empty chunk as a read failure, not an absence.

BLOCKING F2 - fetch-file has no behavioral test. main_test.go:99 asserts flag validation only; no positive reassembly test and no negative truncation/empty-chunk/size-mismatch test. The newSafariSession injection seam is already used by the heartbeat tests in the same file, so there is no harness gap.

NON-BLOCKING F3 - deleting the ok-branch origin re-check in internal/browsersession/session.go:156-160 leaves browsersession, safarictl and mac-safari-session all green under go test -count=1. Only the origin-mismatch branch is covered. Add a sentinel-valid outcome:ok envelope with a mismatched origin asserting ErrOriginMismatch.

ATTACKS THAT HELD (do not redo): cookie/storage blocklist bypassed by 6 of 7 respellings (document["cookie"], spaced, concat, prototype descriptor, window[local+Storage], self[sessionSt+orage]) - NOT a defect, references/safari-session.md states it is not a sandbox and constructed property access can bypass it, so the claim matches behavior. Guard is reached from every production JS path via WrapJavaScript. Narrowing GuardJavaScript to equality is caught by existing tests. run-js fails closed on missing window id and missing origin with no front-document fallback. snapshot --url / fetch-file --page cannot be widened by redirect. Forged/empty/malformed envelopes refused. Header/URL redaction negatives are real. No silent focus theft.

Reviewer verification: go build ./... clean; go test ./... exit 0 across 28 packages. Scope note: heartbeat surfaces in the worktree belong to TASK-260822-3dshyo / TASK-260824-2x6qiu and chromectl/chrome-session to the Chrome items; they were excluded from this verdict. No repository file was modified by this review.
agent completed: [reviewer] reviewer (claude) (exit=0)
spawn run completed: claude (run=RUN-260825-fb1f13, pid=81916, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260825-d8bf2d, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260825-d8bf2d)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260825-d8bf2d, pid=23779, exit=0)
spawn agent resolution: Agent selection: claude via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=claude; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (claude) (run=RUN-260825-d88f74, max_parallel=20)
spawn run started: [reviewer] reviewer (claude) (run=RUN-260825-d88f74)
REVIEW VERDICT (RUN-260825-d88f74): ACCEPTED for CR-TASK-260615-1tlcpm-1 rev1. Evidence: TASK-260615-1tlcpm_review-verdict.md, TASK-260615-1tlcpm_review-rev1-go-test-uncached.log.

F1 CLOSED - cmd/mac-safari-session/main.go:381-395 refuses an empty page-context chunk and refuses publication when decoded length != Safari blob.size. Five mutants killed, three of them NARROWING not delete: != -> > on the byte attestation, drop-equality-keep-negative, and empty-chunk-refusal restricted to i==0. The two chunk mutants still die on the byte attestation, so the layers are independent.

F2 CLOSED - main_test.go:112-217 drives the production run() entry via a fake osascript replaying guarded envelopes. Positive asserts byte-exact reassembly and meta.Bytes == ActualBytesWritten; negatives assert exit 1, named stderr refusal, no saved: on stdout, pre-existing destination byte-preserved, no metadata artifact.

F3 CLOSED - browsersession/session.go:161-163 ok-branch origin re-check now dies under both delete and a HasPrefix narrowing; previously deleting it left the whole suite green.

ALSO ATTACKED: six Safari heartbeat gate mutants all killed (window-id <=0 -> <0, drop https requirement, drop OriginOf canonicality, interval floor 15s -> 10s, drop Chrome-namespace refusal, drop list filter). Live CLI negative smoke: run-js/snapshot/fetch-file fail closed without --origin, no front-document fallback; ttl+deadline together, past deadline, userinfo origin, trailing-slash origin, uppercase name all exit 2. No browser state created. chromectl fetch_file.go/trusted_input.go/ax_darwin.m carry no cookie/storage/authorization handling and no print or log statements.

VERIFIED: go build, go vet, go test ./... (28 pkgs), go test -count=1 over the six touched packages, gofmt -l empty, git diff --check clean. Install refresh checked against the live install without re-running setup.sh: skill files byte-identical to ~/.agents/skills/mac-infra, installed CLI exposes heartbeat, installed binary carries both new refusal strings, codesign designated => identifier works.relux.mac-infra.safari-session, stable launcher present 0700.

NON-BLOCKING N1 - internal/safarictl/session.go:124-129 refuses TargetWindowID <= 0 and empty ExpectedOrigin, but deleting either leaves safarictl and mac-safari-session green. Not exploitable today (all four production callers set both from a validated --origin; OpenBackground inferred origin is overwritten by the flag). Same shape as F3; wants a table test on RunJavaScriptResult.

NON-BLOCKING N2 - README:68 documents mac-safari-session fetch-file without --origin; running it verbatim gives exit 2. Pre-existing at base fa43cb3, contradicts README:278.

NON-BLOCKING N3 - --origin https://host:443 passes OriginOf canonicality but never matches the browser port-normalized location.origin, so such a heartbeat reports drifted forever. Fails safe.

SCOPE NOTE - the candidate is a snapshot of the shared story worktree and carries sibling work not handed to this reviewer: chromectl ax_darwin/trusted_input -> BUG-260825-1wsh7n (to-dev), chromectl fetch_file -> BUG-260825-2s6iw4 (to-dev), heartbeat deadlines/stable launcher + setup.sh codesign -> TASK-260824-2x6qiu (to-review). Those were checked for build/vet/test/format/secret-boundary regressions only, not line-by-line. Accepting this CR does not close them; a story-branch checkpoint is not review of their content.
agent completed: [reviewer] reviewer (claude) (exit=0)
spawn run completed: claude (run=RUN-260825-d88f74, pid=42104, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [implementer] developer (codex) (run=RUN-260826-8ce41e, max_parallel=20)
spawn run started: [implementer] developer (codex) (run=RUN-260826-8ce41e)
agent completed: [implementer] developer (codex) (exit=0)
spawn run completed: codex (run=RUN-260826-8ce41e, pid=81532, exit=0)
spawn agent resolution: Agent selection: codex via explicit_override (preferred_agentic_system: mixed[claude,codex], config: spawn.preferred_agentic_system)
spawn launch composition: empty; contract=agents-infra.child-launch-composition; provider=codex; schema=1; producer=v1.6.1-31-ge70f953; diagnostic=launch_composition_empty; no project MCP servers enabled
spawn queued: [reviewer] reviewer (codex) (run=RUN-260826-862d81, max_parallel=20)
spawn run started: [reviewer] reviewer (codex) (run=RUN-260826-862d81)
agent completed: [reviewer] reviewer (codex) (exit=0)
spawn run completed: codex (run=RUN-260826-862d81, pid=86447, exit=0)

## Precondition Resources
- [mts-harvesting-notes.md](file://TASK-260615-1tlcpm/mts-harvesting-notes.md) — MTS regulations Safari harvest notes

## Outcome Resources
- [mac-safari-session-results.md](file://TASK-260615-1tlcpm/mac-safari-session-results.md) — Safari browser-session CLI implementation results
- [TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--claude-_RUN-260825-a03e26.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--claude-_RUN-260825-a03e26.log) — System spawn log captured by task-board
- [TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--claude-_RUN-260825-fb1f13.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--claude-_RUN-260825-fb1f13.log) — System spawn log captured by task-board
- [TASK-260615-1tlcpm_review-verdict.md](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-verdict.md) — Reviewer verdict for CR revision 2 with exact-tree verification and evidence provenance
- [TASK-260615-1tlcpm_probe-fetch-file-truncation_test.go.txt](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_probe-fetch-file-truncation_test.go.txt) — Probe reproducing F1: fetch-file writes 212500 of 400000 bytes and exits 0 with 'saved:'
- [TASK-260615-1tlcpm_probe-cookie-guard-spellings_test.go.txt](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_probe-cookie-guard-spellings_test.go.txt) — Probe for the documented blocklist limit: 6 of 7 respellings reach dispatch (matches documented non-sandbox claim)
- [TASK-260615-1tlcpm_review-go-test-01.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-go-test-01.log) — Reviewer go test ./... run, exit 0, 28 packages
- [TASK-260615-1tlcpm_spawn-log_-implementer--developer--codex-_RUN-260825-d8bf2d.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_spawn-log_-implementer--developer--codex-_RUN-260825-d8bf2d.log) — System spawn log captured by task-board
- [TASK-260615-1tlcpm_rework-results.md](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_rework-results.md) — Developer rework evidence for Safari fetch byte attestation, negative production-entry tests, full verification, and install refresh
- [TASK-260615-1tlcpm_change-request_rev1.patch](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_change-request_rev1.patch) — Change Request CR-TASK-260615-1tlcpm-1 revision 1 candidate patch (repository_delta=present, 29 changed paths)
- [TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--claude-_RUN-260825-d88f74.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--claude-_RUN-260825-d88f74.log) — System spawn log captured by task-board
- [TASK-260615-1tlcpm_review-rev1-go-test-uncached.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-rev1-go-test-uncached.log) — Reviewer RUN-260825-d88f74 uncached go test -count=1 over the six packages touched by CR rev1, exit 0
- [TASK-260615-1tlcpm_review-verdict-rev1.md](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-verdict-rev1.md) — Reviewer verdict RUN-260825-d88f74 for CR-TASK-260615-1tlcpm-1 rev1: ACCEPTED; F1/F2/F3 closed under delete+narrow mutants; 3 non-blocking findings and a scope note
- [TASK-260615-1tlcpm_spawn-log_-implementer--developer--codex-_RUN-260826-8ce41e.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_spawn-log_-implementer--developer--codex-_RUN-260826-8ce41e.log) — System spawn log captured by task-board
- [TASK-260615-1tlcpm_recovery-results-rev2.md](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_recovery-results-rev2.md) — Recovery producer evidence: README origin correction, current candidate scope, gates, install refresh, and negative coverage
- [TASK-260615-1tlcpm_recovery-go-test-narrow-01.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_recovery-go-test-narrow-01.log) — Uncached Safari production-entry, transport, and shared guard regression suite; exit 0
- [TASK-260615-1tlcpm_recovery-go-test-all-01.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_recovery-go-test-all-01.log) — Full uncached Go test suite; exit 0
- [TASK-260615-1tlcpm_recovery-setup-install-01.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_recovery-setup-install-01.log) — Source setup/install refresh with tests, builds, codesign, CLI symlinks, and skill installation; exit 0
- [TASK-260615-1tlcpm_change-request_rev2.patch](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_change-request_rev2.patch) — Change Request CR-TASK-260615-1tlcpm-2 revision 2 candidate patch (repository_delta=present, 1 changed paths)
- [TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--codex-_RUN-260826-862d81.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_spawn-log_-reviewer--reviewer--codex-_RUN-260826-862d81.log) — System spawn log captured by task-board
- [TASK-260615-1tlcpm_review-r2-go-test-uncached.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-r2-go-test-uncached.log) — Uncached exact-candidate Safari package tests
- [TASK-260615-1tlcpm_review-r2-go-test-fetch-entry.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-r2-go-test-fetch-entry.log) — Verbose production fetch-file positive and negative entry-point tests
- [TASK-260615-1tlcpm_review-r2-readme-tree.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-r2-readme-tree.log) — Candidate tree identity, README mandatory flags, and diff verification
- [TASK-260615-1tlcpm_review-r2-go-build-safari.log](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-r2-go-build-safari.log) — Exact-candidate mac-safari-session build result
- [TASK-260615-1tlcpm_review-verdict-r2.md](file://TASK-260615-1tlcpm/TASK-260615-1tlcpm_review-verdict-r2.md) — Revision-scoped reviewer acceptance verdict produced by RUN-260826-862d81
