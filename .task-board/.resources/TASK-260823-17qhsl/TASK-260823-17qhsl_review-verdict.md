# TASK-260823-17qhsl Review Verdict

Date: 2026-08-24 MSK

## Reviewed candidate

- Verdict: **changes requested**; route to `to-dev`.
- Change Request: `CR-TASK-260823-17qhsl-1`, revision `1`, state observed as `ready` immediately before verdict.
- Goal binding: `GOAL-260823-a87f0b` revision `1`, resolved scope `TASK-260823-17qhsl`.
- Exact diff: base `85ce82c27b25a22c6124a30614c6e7b3bed9b8a0` to candidate tree `566a08bd50d025052a3a7d656311ad851e87089b`, 35 changed paths.
- Patch SHA-256 independently verified as `3887597f29ad6142d550ecd27a161953aa5d44c7a37c674ce3b1fb91a15ef68b`.

## Findings

### F1 — High: production secret boundary is bypassable

Negative shapes: **bypass path around the check** and **narrowed gate survives**.

The candidate claims that tokens and secret-bearing URLs cannot leave the facade, but two production output surfaces admit them:

1. `Adapter.Validate` only bounds mutation-description length (`internal/browserfacade/config.go`), while `schemaResult` emits `Mutation.Description` verbatim (`internal/browserfacade/facade.go`). The built production `mac-browser-site q ... 'schema()'` returned a synthetic `Bearer ...` string and an `api_key` URL from adapter metadata with exit 0.
2. `Facade.Query -> sanitizeItems -> sanitizeText` rejects a small set of header-shaped values and JWTs, then delegates URL handling to `browsersession.RedactSensitiveURL`. That URL helper recognizes `code`, `token`, and a few exact keys but not common sensitive keys such as `api_key` or `signature`; `sanitizeText` also admits a common `ghp_...` credential shape. The production `Facade.Query` call returned those synthetic values and wrote them unchanged to the scoped JSONL cache.

Evidence:

- `.temp/TASK-260823-17qhsl-review/schema-leak-01.log`
- `.temp/TASK-260823-17qhsl-review/facade-attack-01.log`
- `.temp/TASK-260823-17qhsl-review/cache/marketplace/query-e3c685caea111fa2.jsonl`

Required rework:

- Put every public schema/result/cache/error surface behind one enforceable secret-output policy; adapter descriptions must be refused or sanitized before `schema()` renders them.
- Expand sensitive URL-key classification to cover credential/key/signature variants, and refuse well-known opaque credential formats rather than relying only on JWT/header syntax.
- Add negative tests through the real `mac-browser-site q` entry point that assert the synthetic values are absent from stdout, stderr, and cache. Narrow the existing gate with an unlisted sensitive query-key/token variant; do not prove it only by deleting the sanitizer.

### F2 — High: pagination reports guessed facts instead of `unknown`

Negative shape: **absence vs failure/unknown** (proxy signal reported as a fact).

`Facade.list` treats a duplicate page digest as proof of exhaustion and sets `hasMore=false`. But `advance()` proves only that the declared control accepted a click/scroll dispatch; an asynchronous page that has not settled, a stale DOM, or a control that did not change results is not proof that no later records exist. The adversarial production-logic call returned the same page twice after `advanced=true` and emitted `hasMore=false`.

The opposite inference is also unsupported: reaching caller `max_pages` or the scan cap sets `hasMore=true`, although a bound being reached proves only that the facade stopped, not that another record exists. `TestListNarrowsPaginationAtRequestedMaxPages` currently cements that proxy inference. This contradicts the README/reference/LOGBOOK contract that unprovable exhaustion is `unknown`.

Evidence:

- `.temp/TASK-260823-17qhsl-review/facade-attack-01.log`
- `internal/browserfacade/facade.go` duplicate-page and bound branches around `seenPages` / `maxPages`
- `internal/browserfacade/facade_test.go` current max-pages expectation

Required rework:

- Return `unknown` whenever exhaustion or additional data is not proven.
- Reserve `false` for a declared adapter outcome that proves no advance/no remaining records, and `true` for an observed additional record beyond the requested window.
- Add negative tests for unchanged/stale pages, caller-narrowed `max_pages`, adapter-cap exhaustion, and scan-cap exhaustion. Drive the production facade/CLI path and assert tri-state semantics.

## What passed

- `go test -count=1 ./...`: exit 0.
- `go vet ./...`: exit 0.
- `go build ./...`: exit 0.
- `gofmt -l cmd internal scripts`: empty output.
- Exact CR `git diff --check`: exit 0.
- The installed binary exists, source and installed skill/reference bytes match, q projection/batching, cache-only grep, mutation preview/confirmation, lifecycle wiring, and the 1,789-byte versus 288-byte representative comparison are present.

Those positive gates do not override F1/F2: both defects reproduced through production code paths that the green suite does not cover.

## Acceptance criteria assessment

- q/grep/m separation, projection, batching, schema, compact output, bounded cache grep, explicit mutation preview/confirmation, documentation, installation, and output-size evidence are implemented.
- The task is not acceptable because the mandatory no-secret-escape invariant and the explicit `unknown` pagination predicate are contradicted by current production behavior.
- This is ordinary autonomous implementation rework, not a Stop-The-Line boundary and not a human-only decision.
