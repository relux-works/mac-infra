## Status
integrating

## Review
required

## Task Class
code

## Blocked By
- (none)

## Blocks
- (none)

## Checklist
- [ ] task-board worktree integrate STORY-260915-3r0ys5 succeeded: one signed squash commit on main whose tree equals the T3 checkpoint 6c25ca3
- [ ] board-only commit recorded; Story and all three leaves are done
- [ ] go vet ./... && go build ./... && go test -count=1 ./... green on landed main
- [ ] mac-keyvault --json list shows no works.relux.mac-keyvault.*.test.* items
- [ ] origin/main fast-forwarded to the landed commits

## Notes
LANDED EXTERNALLY 2026-09-15: PR https://github.com/relux-works/mac-infra/pull/6 fast-forwarded main to 594f748 (three signed commits = accepted trees of T1 rev7 / T2 rev2 / T3 rev9 rebased onto e326b5f, LOGBOOK.md merged additively). Board transition to done is blocked by task-board itself (skill-project-management BUG-260915-2pbrvf); managed branch left at its recorded checkpoint 6c25ca3 so the fix can replay/recognise it. Do not re-land.

## Precondition Resources
- [STORY-260915-3r0ys5_key-record-model-v2.md](file://STORY-260915-3r0ys5/STORY-260915-3r0ys5_key-record-model-v2.md) — Key record model v2, consolidated: identity, record, split rule, access policy, registry, operations, generation, import with detection, CLI + error contract, negatives, fingerprint-vs-checksum (owner 2026-09-15)

## Outcome Resources
(none)

## Created
2026-09-15T09:12:24Z

## Last Update
2026-09-15T19:58:43Z
