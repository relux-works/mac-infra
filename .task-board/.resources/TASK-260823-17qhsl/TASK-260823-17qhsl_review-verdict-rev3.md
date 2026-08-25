# TASK-260823-17qhsl Review Verdict — CR Revision 3

Date: 2026-08-24 MSK

## Verdict

- **Changes requested**; route `TASK-260823-17qhsl` to `to-dev`.
- This is ordinary implementation rework. There is no external blocker, human-only decision, or Stop-The-Line boundary.

## Authoritative Review Scope

- Reviewer goal checkpoint: `GOAL-260823-3405d9` revision 1.
- Resolved scope: `TASK-260823-17qhsl`.
- Change Request: `CR-TASK-260823-17qhsl-3` revision 3, supplied as `ready` in the managed Story workspace.
- Exact diff: base `85ce82c27b25a22c6124a30614c6e7b3bed9b8a0` to candidate tree `00ebbf409cbae48474c75c2c14588602a80f3aa8`.
- Patch SHA-256 independently reproduced as `56f0dcc1ce9b346e6ff176a086280b39ab44fe8caa31823154b47b71408ed143`; the materialized patch byte-matched a fresh exact-diff export.
- All 37 candidate path blobs matched the current managed worktree; mismatch count was zero.
- No operator directive was present at the review checkpoint.

## F1 — High: nested secret-bearing URL keys bypass the canonical scanner

Negative shapes: **bypass path around the check** and **narrowed gate survives**.

`internal/browserfacade/outbound.go:140` recognizes a sensitive query key and redacts only that key's associated values while retaining the key itself. Nested scanning at lines 152-160 runs only over values. A percent-encoded secret-bearing URL placed in the outer URL's query-key therefore retains the nested sensitive value inside the key. The transformed URL is returned without a second central scan.

Both the source-built candidate and installed `mac-browser-site q` production entry exited 0 and emitted the synthetic nested value to stdout and the query cache. This contradicts the revision directive and documentation that nested/encoded secret-bearing URLs are refused.

Required rework:

- Inspect decoded query names as well as values; never retain a secret-bearing key.
- Re-run the canonical decision over the fully transformed URL/output, with bounded recursion and an explicit unknown state where classification is ambiguous.
- Add production-entry narrowing tests for a nested URL in a query key, asserting non-zero refusal/unknown and absence from stdout, stderr, and cache for both compact and JSON render paths.

## F2 — High: a common opaque token family still escapes stdout and cache

Negative shape: **narrowed gate survives**.

The single regex in `internal/browserfacade/outbound.go:34` recognizes Stripe-style `sk_live`/`sk_test` forms but not the common OpenAI-style `sk-proj-*`/`sk-*` family. A synthetic `sk-proj-*` value in an otherwise public `title` field passed `runQuery -> Facade.Query -> sanitizeItems -> EnforceOutbound -> RenderQuery`, exited 0, and was persisted unchanged in the cache by both the source-built candidate and installed binary.

This violates the task acceptance criterion that tokens cannot escape and the documented promise to refuse common opaque credential families.

Required rework:

- Extend the one canonical scanner rather than adding a per-surface filter.
- Add a production-entry narrowing test for the missing family with stdout/stderr/cache non-disclosure assertions and a rejected-read cache-absence assertion.
- Reassess the documented absolute no-token wording against the enforceable scanner policy; either make the policy enforce the promise or narrow the public contract truthfully without weakening the explicit task acceptance criterion.

## F3 — High: duplicate-key extractor envelopes are accepted after lossy decoding

Negative shapes: **check present but uncalled from production** and **failure to read treated as valid evidence**.

`CLITransport.Extract` decodes `items` through `json.Unmarshal` into `[]map[string]any` at `internal/browserfacade/facade.go:125-129`. Duplicate object keys are collapsed before the eventual outbound enforcement sees the value. A real q invocation with a duplicate `title` key, where the earlier value was authorization-shaped and the later value was safe, exited 0, returned the safe value, and created a cache record instead of reporting an ambiguous/malformed transport response.

The cache duplicate-key path is now guarded, but the successful extractor path bypasses that same normalized decision. This contradicts the revision requirement that ambiguous/malformed inputs fail closed or report unknown.

Required rework:

- Perform duplicate-key-aware validation on the successful extractor envelope and every item before lossy map decoding, using the same normalized boundary decision.
- Add a production `q` test whose fake exact-target transport returns duplicate item keys; require `SENSITIVE_RESPONSE_UNKNOWN` or `TRANSPORT_RESPONSE_INVALID`, no output record, and no cache creation.
- Cover the mutation/advance response decoders with the same single-value/duplicate-key discipline where their response shape can become evidence.

## F4 — Medium: cache-scoped grep follows a symlinked ancestor outside its physical root

Negative shape: **bypass path around the check**.

`Cache.siteDirectory` checks only the final cache root and site directory with `Lstat` (`internal/browserfacade/cache.go:166-199`). If the `mac-infra` ancestor below `~/Library/Application Support` is a symlink, both checked descendants are ordinary directories after path resolution. A production `grep` invocation followed that ancestor and returned a record stored in an external physical directory, exiting 0.

This violates the scoped-cache/no-filesystem-overreach contract even though direct symlink roots and files are covered.

Required rework:

- Anchor cache access to a canonical trusted root and reject symlinks in every attacker-controllable path component, or use descriptor-relative no-follow traversal.
- Add a production grep negative test for an ancestor-symlink scope escape; require `CACHE_SCOPE_REFUSED` and no external record output.

## Acceptance Audit

- Deterministic extractor/template/predicate contract: preserved; extractor tests and the full suite pass.
- q/grep/m separation, projection, batching, schema, compact output, pagination kinds/bounds, and guarded mutation preview/confirmation: implemented and covered.
- Pagination evidence: duplicate/caller/adapter/global bounds remain `unknown`; partial extractor/advance reads are typed failures; explicit exhaustion remains proven `false`.
- Cache grep browser isolation and direct root/file symlink checks: implemented, but physical cache scope is bypassable through an ancestor symlink (F4).
- Central secret boundary: one state type and call exist, but nested query-key and opaque-token variants still escape (F1/F2), and successful extractor ambiguity bypasses raw validation (F3).
- Output-size/token comparison: independently confirmed as 1,789 bytes / about 448 tokens versus 288 bytes / about 72 tokens, an 83.9% reduction.
- README, mac-infra skill/reference, setup/deinit, and logbook updates are present; installed skill/reference byte-match source.
- Therefore the mandatory no-secret-escape, fail-closed ambiguity, and cache-scope acceptance criteria are not satisfied.

## Validation

| Command / check | Result |
| --- | --- |
| `go test -count=1 ./...` | pass |
| `go vet ./...` | pass |
| `go build ./...` | pass |
| `gofmt -l cmd internal scripts` | empty |
| exact CR `git diff --check` | pass |
| candidate-path blob comparison | 0 mismatches |
| patch SHA-256 / byte comparison | exact match |
| installed skill/reference comparison | exact match |
| source-built + installed nested query-key attack | exit 0; synthetic nested value reached stdout and cache |
| source-built + installed common opaque-token attack | exit 0; synthetic token reached stdout and cache |
| source-built + installed duplicate extractor-key attack | exit 0; ambiguous read accepted and cached |
| ancestor-symlink cache grep attack | exit 0; external physical cache record rendered |

The green suite demonstrates that the missing negative shapes are not currently covered; it does not establish the security acceptance criteria.
