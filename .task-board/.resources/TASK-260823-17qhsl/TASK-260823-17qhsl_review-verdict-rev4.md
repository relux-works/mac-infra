# TASK-260823-17qhsl Review Verdict — CR Revision 4

Date: 2026-08-24 MSK

## Verdict

- **Changes requested**; route `TASK-260823-17qhsl` to `to-dev`.
- This is ordinary implementation rework. There is no external blocker,
  human-only decision, or Stop-The-Line boundary.

## Authoritative Review Scope

- Reviewer goal checkpoint: `GOAL-260823-98348b` revision 1.
- Resolved scope: `TASK-260823-17qhsl`.
- Change Request: `CR-TASK-260823-17qhsl-4` revision 4, supplied as `ready` in
  the managed Story workspace.
- Exact diff: base `85ce82c27b25a22c6124a30614c6e7b3bed9b8a0` to candidate tree
  `2682c91d7ef26c14de4dfebcdbd0be02c9ee0c3e`.
- Patch SHA-256 independently reproduced as
  `13bf0f7fac8c2006064cc36ecbb19867f5e33796ea65189cd71278127388bd5d`;
  the materialized board patch byte-matched a fresh exact-diff export.
- All 37 candidate path blobs and modes matched the managed worktree; mismatch
  count was zero.
- No operator directive was present at either reviewer checkpoint.

## F1 — High: cookie/session/storage URL keys escape the canonical boundary

Negative shapes: **narrowed gate survives** and **bypass path around the
check**.

`internal/browserfacade/outbound.go:332-359` has separate normalized-name
policies. `safePublicField` rejects cookie, session, and storage field names,
but `sensitiveOutboundName`, which owns URL query-name decisions, omits those
families. The central regex at line 34 recognizes cookie header syntax with a
colon, not cookie/session/storage query assignments. The result contradicts
the README and facade-reference promise that cookies, storage, and opaque
session state remain inside the browser.

Both source-built and freshly installed production entries reproduced the
failure:

- `runQuery -> Facade.Query -> list -> CLITransport.Extract -> sanitizeItems ->
  sanitizeText -> EnforceOutbound` exited 0 for synthetic `cookie` and
  `session_id` query parameters in a returned URL, emitted the complete value
  in JSON and compact output, and persisted it in the site cache.
- `runQuery -> loadAdapter -> Adapter.Validate -> EnforceOutbound ->
  schemaResult -> RenderQuery -> WriteOutbound` exited 0 and emitted a mutation
  description containing a synthetic cookie-bearing URL.

Required rework:

- Extend the one canonical normalized policy, not a q/schema/cache-specific
  filter, so browser-cookie, storage, and session-state query/assignment names
  cannot be released.
- Add source-built and installed production-entry narrowing tests for at least
  cookie, session-id/state, and storage-shaped URL keys in both compact and
  JSON modes. Require refusal or safe redaction, absence from stdout/stderr,
  and rejected-read cache absence.
- Keep the public contract truthful for every class the scanner claims.

## F2 — High: escaped secret-bearing URLs leak through transport errors

Negative shape: **bypass path around the check**.

`outboundURLPattern` at `internal/browserfacade/outbound.go:33` recognizes only
literal `http://` and `https://`; `inspectEncodedVariants` handles percent
encoding but not JSON/backslash slash encodings. `inspectJSONShape` validates
shape and duplicate keys but does not recursively classify scalar strings.

A synthetic transport failure containing a backslash-escaped HTTPS URL with a
secret callback-code query parameter drove the real
`runQuery -> ExecRunner.Run -> safeErrorDetail -> EnforceOutbound -> fail ->
WriteOutbound` path. Source-built and freshly installed commands correctly
returned nonzero, but stderr still contained the complete secret-bearing URL.
Nonzero exit is not non-disclosure.

Required rework:

- Normalize or boundedly rescan common escaped URL spellings in the single
  `EnforceOutbound` owner and fail closed when decoding is ambiguous.
- Add production-entry tests over transport errors and schema metadata, with
  absence assertions on stdout, stderr, cache, and both render formats.
- Do not add an error-only or schema-only sanitizer.

## Revision-3 Finding Reproduction

The requested revision-3 shapes are closed in revision 4:

- nested secret URL in a percent-encoded query name: source/installed JSON and
  compact paths refused with no output or cache disclosure;
- common project and opaque `sk-` credential forms: source/installed JSON and
  compact paths refused with no output or cache disclosure;
- duplicate extractor item, pagination `advanced`, and mutation `applied`
  evidence: source/installed paths returned explicit refusal/unknown and did
  not create success/cache evidence;
- symlinked `mac-infra` cache ancestor: source/installed grep returned
  `CACHE_SCOPE_REFUSED`, produced no external record, and did not traverse the
  physical boundary.

Pagination evidence also remained correct: duplicate pages reported
`hasMore:"unknown"`, explicit `advanced:false` reported `false`, and a partial
extractor envelope returned `TRANSPORT_RESPONSE_INVALID` rather than absence.

## Gate Strength And Architecture

- Grep found one exported decision owner, `EnforceOutbound`, with q, cache,
  transport error, schema metadata, and buffered compact/JSON render paths
  calling it. No competing per-surface secret regex was found.
- A narrowed project-token regex mutant made the central unit test and real q
  JSON/compact production-entry tests fail.
- A duplicate-key mutant narrowed to `title` only made the pagination and
  mutation production-entry tests fail by admitting ambiguous evidence.
- Descriptor-rooted cache access and the explicit ancestor-symlink production
  test resisted the reviewed escape.
- The deterministic extractor/template/predicate contract, q/grep/m
  separation, projection, batching, bounds, mutation preview/confirm, and
  cache-only grep remain present and green.

The new findings are missing-class/bypass variants inside the single owner,
not evidence that ownership should be split again.

## Validation

| Command / check | Result |
| --- | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` | pass |
| `go test -count=1 ./...` | pass |
| `go vet ./...` | pass |
| `go build ./...` | pass |
| `gofmt -l cmd internal scripts` | empty |
| exact CR `git diff --check` | pass |
| `task-board validate` | pass |
| `./scripts/setup.sh` | pass; installed binary refreshed from the managed worktree |
| coverage | `internal/browserfacade` 80.5%; `cmd/mac-browser-site` 88.7% |
| candidate-path comparison | 37/37 blobs and modes match; zero mismatches |
| patch SHA-256 / byte comparison | exact match |
| installed skill/reference comparison | exact match |
| rev3 source-built + installed attacks | refused/unknown; no disclosure |
| new cookie/session list attacks, JSON / compact | exit 0; stdout and cache disclosure |
| new cookie-bearing schema attack | exit 0; stdout disclosure |
| new escaped-URL transport-error attack | exit 1; stderr disclosure |

The green suite demonstrates missing negative coverage for F1/F2; it does not
establish the no-secret-escape acceptance criterion.

## Remaining Acceptance Audit

- Output-size evidence independently matches the producer record: 1,789-byte
  raw fixture versus 288-byte compact projection, an 83.9% reduction (about
  448 versus 72 output tokens by the documented estimate).
- README, mac-infra skill/reference, setup/deinit, and logbook changes are
  present; installed skill/reference bytes match source.
- Full build/lint/test gates pass, but the explicit acceptance criteria that
  cookies, storage/session material, and secret-bearing URLs cannot escape are
  contradicted by F1/F2.

Therefore CR revision 4 is not acceptable and must return to implementation.
