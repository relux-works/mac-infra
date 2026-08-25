# TASK-260823-17qhsl Review Verdict — CR Revision 2

Date: 2026-08-24 MSK

## Verdict

- **Changes requested**; route `TASK-260823-17qhsl` to `to-dev`.
- This is ordinary implementation rework, not a Stop-The-Line boundary and not a human-only decision.

## Authoritative Review Scope

- Reviewer goal checkpoint: `GOAL-260823-15c4f1` revision 1.
- Resolved scope: `TASK-260823-17qhsl`.
- Change Request: `CR-TASK-260823-17qhsl-2` revision 2, observed `ready` in the managed Story workspace.
- Exact diff: base `85ce82c27b25a22c6124a30614c6e7b3bed9b8a0` to candidate tree `9ef113c03aad4de199d49aa506710a490c37626c`.
- Patch SHA-256 independently reproduced as `75f413f643507aaf792481d73de567abefffac405ef37c687d7c52c506dca332`.
- All 35 working-tree path contents matched the candidate tree; mismatch count was zero.
- No operator directive was present at the review checkpoint.

## F1 — High: secret-output policy remains bypassable

Negative shapes: **bypass path around the check** and **narrowed gate survives**.

The revision fixes the exact lowercase URL keys and GitHub-token fixtures from cycle 1, but the composed production artifact still emits synthetic authorization/token material through three adjacent forms:

1. `internal/browserfacade.sanitizeText` uses a case-sensitive `https?://` recognizer. An uppercase valid HTTP(S) URL containing a sensitive query key passed `cmd/mac-browser-site.runQuery -> Facade.Query -> sanitizeItems -> sanitizeText`, exited 0, reached stdout, and was cached without redaction.
2. `Cache.readBoundedLines` decodes a JSONL record into `map[string]string` for validation, but `Cache.Grep` returns the original raw line. A record with duplicate JSON keys can place authorization material in the earlier value and a safe value in the later key; Go's decoder validates only the later value while `RenderGrep` emits the sensitive original bytes. The installed `runGrep -> Cache.Grep -> readBoundedLines -> RenderGrep` path exited 0 and exposed the earlier value.
3. The opaque-token allowlist remains narrower than the stated no-token boundary. A common GitLab personal-access-token form passed the installed `runQuery` path, exited 0, reached stdout, and was cached.

Raw synthetic values are intentionally omitted here. Task-scoped evidence:

- `.temp/TASK-260823-17qhsl/review2/installed-attack-summary-01.log`
- `.temp/TASK-260823-17qhsl/review2/installed-uppercase.stdout`
- `.temp/TASK-260823-17qhsl/review2/installed-gitlab.stdout`
- `.temp/TASK-260823-17qhsl/review2/installed-duplicate.stdout`
- `.temp/TASK-260823-17qhsl/review2/home/Library/Application Support/mac-infra/browser-site-cache/review-two/`

Required rework:

- Recognize HTTP(S) URL schemes case-insensitively and add a production CLI negative test proving the sensitive value is absent from stdout, stderr, and cache.
- Never render unvalidated raw JSONL bytes. Reject duplicate keys during cache decoding or render a canonical re-encoding of the exact validated record; add a production `grep` negative test for duplicate-key shadowing.
- Cover the common GitLab opaque-token family, or replace the expanding per-family list with one enforceable policy consistent with the documented no-token guarantee. Add a production CLI negative test and assert no cache creation.

## Cycle-1 F2 Resolution

The pagination rework is correct for the requested negative shapes:

- duplicate/stale pages, caller bounds, adapter bounds, and the global scan bound report `hasMore:"unknown"`;
- partial/malformed extractor or advance envelopes return `TRANSPORT_RESPONSE_INVALID` rather than false exhaustion;
- explicit `advanced:false` and complete non-paginated reads remain the proven false cases;
- an observed record beyond the requested window remains the proven true case.

Production-entry tests cover duplicate, caller-bound, adapter-bound, partial-advance, explicit-exhaustion, and partial-extractor cases. The full uncached suite passed.

## Acceptance Audit

- Deterministic extractor/template/predicate contract: preserved; revision 2 does not alter `internal/browserquery`, and full tests pass.
- `q` projection, schema, compact output, and batching: implemented and production-tested.
- Bounded pagination and explicit adapter kinds: implemented; cycle-1 unknown/absence defect resolved.
- Cache-scoped `grep`: browser-free and path-bounded, but its secret revalidation/output boundary is bypassable through duplicate keys.
- Explicit guarded `m`: preview/refusal/confirmation and batch prevalidation are implemented and production-tested.
- Browser secret boundary: **not satisfied**, as reproduced above on the installed artifact.
- Output-size/token comparison: recorded as 1,789 bytes / about 448 tokens versus 288 bytes / about 72 tokens, an 83.9% reduction.
- README, skill reference, setup/deinit, installation: present; installed skill and facade reference byte-match the candidate.

## Validation

| Command / check | Result |
| --- | --- |
| `go test -count=1 ./...` | pass |
| `go vet ./...` | pass |
| `go build ./...` | pass |
| `gofmt -l cmd internal scripts` | empty |
| exact CR `git diff --check` | pass |
| candidate-path blob comparison | 0 mismatches |
| installed binary/version and skill/reference comparison | available; skill/reference match |
| installed uppercase-URL attack | exit 0; secret escaped |
| installed GitLab-token attack | exit 0; token escaped |
| installed duplicate-key cache grep attack | exit 0; authorization material escaped |

The green suite therefore does not establish the mandatory no-secret-escape acceptance criterion.
