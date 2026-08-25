# TASK-260823-17qhsl — Browser Site Facade Outcome

Date: 2026-08-24 MSK

## Current Story Checkpoint Recovery — 2026-08-26

Revision 8 became stale as a Change Request snapshot after later sibling Story
checkpoints, so `RUN-260826-42e886` revalidated the current managed tree without
redesigning or broadening the facade. No current defect reproduced and no new
task-owned source edit was required.

- The explicit named final-cache-symlink production path still returns nonzero
  `CACHE_SCOPE_REFUSED` in compact and JSON modes for both source-built and
  freshly installed CLIs; no external marker/path escapes and the external file
  plus symlink remain unchanged.
- Narrowing only that refusal back to `continue` makes
  `TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats`
  fail with `-count=1`; restoration is byte-exact.
- The full uncached suite, vet, build, formatting, all diff-check layers,
  coverage, setup/install, source/install parity, board validation, the
  rev1-rev7 installed regression matrix, and 22 hostname/path attacks pass.
- Fresh output comparison remains 893-byte raw extraction versus 132-byte
  compact projection, an 85.2% reduction (estimated 223 versus 33 tokens).
- Task-owned facade paths are clean relative to current `HEAD` and index.
  Existing staged/unstaged Chrome, Safari, browser-session, setup/deinit,
  README, skill, and LOGBOOK changes remain preserved sibling scope.

Exact commands, real exits, the uncounted first full-suite attempt, installed
attack evidence, parity hashes, and provenance are recorded in
`TASK-260823-17qhsl_current-checkpoint-validation-2026-08-26.md`.

## Change Request Revision 8 Final-Cache-Symlink Rework

This run closes the sole revision-7 review finding at the existing
descriptor-rooted cache owner:

- An explicitly named final `.jsonl` symlink now returns the typed nonzero
  `CACHE_SCOPE_REFUSED` result instead of being skipped into an empty match set.
  Unrequested symlink entries remain ignored during bounded scans, and the
  external target is never followed or modified.
- `TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats`
  drives the real `runGrep` entry in compact and JSON modes and asserts typed
  refusal, no external marker/path in stdout or stderr, byte-preservation of the
  external file, and preservation of the symlink itself.
- Narrowing only the new refusal back to `continue` makes that named production
  test fail with `-count=1`; the production source was then restored byte-exact.
- Full uncached tests, vet, build, formatting, diff, coverage, setup/install,
  source/install parity, source-built and installed final-symlink attacks, the
  22-case hostname/path matrix, the rev1-rev7 regression matrix, board
  validation, and the output-size comparison all pass.

Exact commands, exits, installed attack results, parity, and revision-7 path
provenance are recorded in
`TASK-260823-17qhsl_rework-cycle6-validation-2026-08-24.md`.

## Change Request Revision 7 Hostname/Path Rework

This run closes the single revision-6 review finding without weakening the
architecture decision or adding a per-surface filter:

- `EnforceOutbound` remains the sole outbound decision owner.
- The parsed decoded hostname and every bounded-decoded path component now
  cross the same recognized/opaque credential scanner and normalized
  sensitive-name policy used by JSON keys, fields, assignments, and query
  names. Malformed or exhausted component decoding reports `unknown`.
- New source production tests cover JSON/compact q, credential/opaque hosts,
  cookie/session/storage hosts and paths, mixed case/separators, encoded forms,
  and stdout/stderr/cache absence.
- Removing only the production hostname/path classifier call makes the named
  production test fail with `-count=1`; restoration is byte-exact.
- Full uncached tests, vet, build, formatting, diff, setup/install, parity,
  board validation, installed host/path attacks, the prior architecture
  regression matrix, and a fresh output-size comparison all pass.

Exact commands, real exits, installed attack results, source/install SHA, and
revision-6 path provenance are recorded in
`TASK-260823-17qhsl_rework-cycle5-validation-2026-08-24.md`.

## Architecture-Driven Boundary Migration Candidate

This run implements
`TASK-260823-17qhsl_boundary-architecture-decision.md` as the real candidate
following the architecture-only revision-5 snapshot:

- `EnforceOutbound` remains the one exported outbound decision owner and now
  runs one bounded normalization queue over literal, percent, nested,
  JSON/backslash-escaped, case-varied, and malformed representations.
- One normalized sensitive-name policy now serves adapter fields, JSON keys,
  assignments, and URL query names. Cookie, local/session storage, session
  id/state, authorization, credential, key, secret, and token families no
  longer diverge across surfaces.
- Adapter JSON, extractor items, advance/mutation evidence, cache records, and
  renderer buffers are duplicate-aware and scalar-inspected before lossy
  decode or output. Refused/unknown states retain no inspected value.
- Browser process stdout/stderr is never projected, even when apparently clean;
  `TransportFailure` exposes only stable generic typed metadata.
- Descriptor-rooted no-follow cache access, canonical cache rendering, final
  buffered `WriteOutbound`, pagination unknown semantics, deterministic
  extraction, exact target/origin guards, q/grep/m separation, and mutation
  preview/confirm behavior remain intact.
- New production tests cover cookie/session/storage URL names, escaped schema
  metadata and transport errors, ambiguous opaque credentials, duplicate
  adapter/evidence/cache keys, compact/JSON output, cache/external-path absence,
  canonical redacted cache reuse, and narrowing mutants of the central policy.

Final source gates, final installed attacks, exact exits, source/install SHA,
narrowing-mutant results, the recovered canonical-cache regression, and shared
lane provenance are recorded in
`TASK-260823-17qhsl_rework-cycle4-validation-2026-08-24.md`.

## Change Request Revision 4 Rework

Revision 4 closes all four reproduced findings from
`TASK-260823-17qhsl_review-verdict-rev3.md` while preserving the accepted
centralized boundary, pagination semantics, q/grep/m contracts, and deterministic
extractor:

- The canonical scanner now inspects decoded URL query names and values,
  boundedly rescans transformed URLs, and refuses common `sk-proj-*` / `sk-*`
  opaque credential forms. No per-surface filter was added.
- Extractor items, pagination advance evidence, and mutation evidence cross the
  canonical boundary before lossy JSON decode, so duplicate keys become typed
  refusal/unknown and cannot create cache or success evidence.
- Cache traversal is physically anchored through `os.Root`; every facade-owned
  directory component is checked with `Lstat`, symlinks are refused, and file
  creation/open/rename/read stays descriptor-relative.
- New production-entry tests cover compact and JSON secret attacks, duplicate
  extractor/advance/mutation keys, exact ancestor-symlink cache escape, rejected
  cache absence, and external-output absence. These tests reproduced the old
  behavior with focused exit 1 before the fix and pass after it.
- README, the installed facade reference, and LOGBOOK now document the bounded
  recognizable-token contract, decoded-name/rescan policy, pre-decode evidence
  gate, and descriptor-rooted cache decision.

Revision-4 gates and installed attack-smoke exits are attached separately as
`TASK-260823-17qhsl_rework-cycle3-validation-2026-08-24.md`.

## Change Request Revision 3 Rework

Revision 3 addresses the repeated secret-boundary variants from
`TASK-260823-17qhsl_review-verdict-rev2.md` without changing the accepted
pagination semantics or deterministic extractor/template/predicate contract:

- `internal/browserfacade/outbound.go` is now the sole owner of the facade's
  canonical secret scanner, normalized `clean` / `redacted` / `refused` /
  `unknown` decision, and `EnforceOutbound` production enforcement call.
- q schema/list results, cache records before and after persistence, grep
  matches, adapter metadata, transport/CLI errors, and every compact/JSON
  renderer pass through that same decision point. Renderers buffer before
  enforcing, so refusals cannot leave partial output.
- URL parsing is case-insensitive for HTTP(S) schemes, hosts, and query keys;
  every duplicate sensitive query value is redacted. Nested/repeatedly encoded
  secret-bearing URLs, Bearer/JWT, GitHub/GitLab and other common opaque token
  families are refused. Malformed/ambiguous URL or JSON-shaped material reports
  `SENSITIVE_RESPONSE_UNKNOWN` rather than passing.
- Cache reads reject duplicate JSON keys before lossy map decoding and grep
  renders a canonical re-encoding of the exact validated record, never the raw
  JSONL source line. This closes the revision-2 duplicate-key shadowing bypass.
- Production-entry narrowing tests cover uppercase URLs, duplicate sensitive
  query keys, GitLab tokens, nested encoding, malformed URLs, duplicate JSONL
  keys, direct renderer bypasses, schema metadata, and CLI/transport error
  paths. The pre-fix focused command exited 1 on those variants; the same suite
  exits 0 after the centralized boundary.

Revision-3 validation and installed attack-smoke exits are attached separately
as `TASK-260823-17qhsl_rework-cycle2-validation-2026-08-24.md`.

## Change Request Revision 2 Rework

Revision 2 addresses both findings from
`TASK-260823-17qhsl_review-verdict.md` without changing the deterministic
template/predicate extractor contract:

- F1: the production output policy now covers adapter mutation descriptions,
  projected and unprojected DOM fields, direct cache writes, cache reads/grep,
  and transport error details. Bearer/JWT/common opaque credential forms,
  including GitHub token prefixes, are refused. URL user info, fragments, and
  sensitive query-key variants including `api_key` and `signature` are
  redacted. Invalid schema metadata is refused before `schema()` renders it.
- F2: pagination now reserves `true` for an observed extra record and `false`
  for a complete `none` page or explicit adapter `advanced:false`. Duplicate or
  stale pages, caller/adapter page bounds, and the 1,000-record scan bound emit
  `unknown`. Extractor and advance envelopes require every field and exactly one
  JSON value; partial/malformed reads return `TRANSPORT_RESPONSE_INVALID`
  instead of becoming false exhaustion.
- Production call-site coverage drives `cmd/mac-browser-site.runQuery` and
  `runGrep`, including narrowed `api_key`, `signature`, and GitHub-token cases,
  stdout/stderr/cache assertions, duplicate/caller-bound/adapter-bound/scan-bound
  cases, explicit exhaustion, and partial extractor/advance reads.

## Delivered Scope

- Added `mac-browser-site`, a separate agent-facing CLI with `q`, `grep`, and
  `m` entry points.
- Added `internal/browserfacade` with strict site-adapter decoding, field
  projection, schema introspection, semicolon-separated batches, compact/JSON
  output, bounded multi-page list collection, private cache search, mutation
  preview/confirmation, and response sanitization.
- Preserved the installed extractor contract. Chrome reads invoke
  `mac-chrome-session extract`; Safari reads generate the same
  `browserquery.BuildJavaScript` template/predicate/skip/take program and invoke
  `mac-safari-session run-js`. The facade does not implement a second DOM
  extractor.
- Added explicit pagination adapter kinds: `none`, `next-page`, page-owned
  `cursor`, and `infinite-scroll`. Adapter `maxPages` is 1..20; a query may only
  narrow it. `take <= 100`, `skip+take <= 1000`, each extraction chunk retains
  the foundation's `take <= 100`, unchanged pages stop, and uncertain
  exhaustion is reported as `unknown`.
- Cursor state remains owned by the site's declared click handler. It is never
  read, returned, cached, passed as a CLI argument, or placed in a URL.
- Successful projected records are sanitized and atomically cached as `0600`
  JSONL below the fixed per-site root
  `~/Library/Application Support/mac-infra/browser-site-cache/<site>/`.
  `grep` accepts no root/path override, ignores symlink files, refuses symlink
  scope roots, accepts only one JSONL basename, and enforces file/record/context/
  match bounds.
- Every mutation must exist in adapter metadata. The entire batch is validated
  before dispatch. `--dry-run` performs no transport call; all live mutations,
  including non-destructive ones, require `--confirm`. A click reports
  verification `unknown` rather than inventing an attestation.

## Safety Evidence

Production entry points and gates:

- `cmd/mac-browser-site.runQuery` -> `browserfacade.Facade.Query` ->
  `CLITransport.Extract`.
- `cmd/mac-browser-site.runGrep` -> `browserfacade.Cache.Grep`; no transport is
  constructed or invoked.
- `cmd/mac-browser-site.runMutation` -> `browserfacade.Facade.Mutate` ->
  `CLITransport.Evaluate` only after adapter allowlist and `--confirm`.
- `Adapter.Validate`, `sanitizeItems`, `sanitizeText`, `safeErrorDetail`, and
  `Cache.readBoundedLines` are on those production paths.

Negative tests drive or narrow the production gates:

- `TestRunQProductionEntryRefusesSecretResponseWithoutOutputOrCacheLeak`
  drives `runQuery` and proves authorization material and an unexpected secret
  field cannot reach output/cache.
- `TestRunMProductionEntryRefusesAndPreviewsWithoutDispatchThenRequiresConfirm`
  drives `runMutation`, proves both absent confirmation and preview dispatch
  nothing, then proves the confirmed path is reachable.
- `TestRunGrepProductionEntryUsesOnlyCacheAndNeverBrowserTransport` drives
  `runGrep` with a browser executable that would leave a marker; no marker is
  created.
- `TestAdapterRejectsSecretBearingURLsFieldsAndSelectors` covers query/
  fragment origins, cookies, authorization, storage, API-key, CSRF/token, opaque state,
  and secret-bearing selector shapes.
- `TestQueryRefusesAuthorizationOpaqueStateAndTokensBeforeCacheWrite` covers
  authorization values, unexpected session-state fields, and JWT-like values.
- `TestQueryRedactsSecretBearingURLBeforeOutputAndCache` proves sensitive query
  values and fragments are absent from both output and cache.
- `TestGrepIsBoundedToNamedSiteCacheAndIgnoresSymlinks` covers traversal and
  symlink bypass shapes.
- `TestGrepRefusesUnsanitizedCacheInsteadOfTreatingReadFailureAsAbsence`
  proves malformed/unsafe reads are refusals, not empty-search fallbacks.
- `TestListNarrowsPaginationAtRequestedMaxPages` proves the bound by narrowing
  an adapter from three pages to two; exactly two extracts and one advance run.
- `TestCursorAndInfiniteScrollAdvanceContractsDoNotExposeCursorState` proves
  cursor pagination does not read or transport a cursor and infinite-scroll is
  a separate explicit contract.
- `TestMutationPreviewAndRefusalDoNotDispatchAndConfirmedBatchPrevalidates`
  proves a later unknown mutation prevents the first statement from writing.
- `TestCLITransportUsesSafariExactWindowOriginWithoutInventedTabOrSecretSource`
  and the Chrome counterpart prove both site transports retain exact-target and
  mandatory-origin behavior without browser-secret tokens.
- `TestExecRunnerRedactsAuthorizationAndSecretURLFromFailure` proves transport
  error text cannot export authorization material or secret-bearing URLs.
- `TestRunQProductionEntryGuardsSchemaListAndCacheSecretSurfaces` narrows the
  schema/list/cache/grep policy to Bearer, GitHub-token, `api_key`, and
  `signature` variants and asserts the synthetic values cannot escape.
- `TestRunQProductionEntrySanitizesTransportErrors` drives the real CLI error
  surface for Bearer, GitHub-token, and secret-URL failures.
- `TestRunQProductionEntryReportsUnknownForIndeterminatePagination` proves
  duplicate, caller-bound, and adapter-bound continuation is `unknown` while
  explicit `advanced:false` remains proven `false`.
- `TestRunQProductionEntryRefusesPartialExtractorEnvelope` and the partial
  advance subtest prove failed reads cannot take the absence fallback.
- `TestListReportsUnknownAtGlobalScanBound` reaches the real 1,000-record
  production list loop and keeps the unprovable continuation state `unknown`.
- `TestCacheWriteRefusesUnsanitizedRecordsBeforeCreatingSiteCache` proves the
  public cache writer cannot bypass facade sanitization.

## Representative Output / Token Comparison

Evidence files:

- `.temp/TASK-260823-17qhsl/smoke/raw-dom.txt`
- `.temp/TASK-260823-17qhsl/smoke/q-compact.txt`

The raw fixture is representative marketplace DOM text for the same five items;
it is synthetic, not a claim about a live authenticated page. Token estimates
use `ceil(bytes / 4)` for output only and exclude equal shell/tool framing.

| Output | Bytes | Estimated tokens | Delta vs raw |
| --- | ---: | ---: | ---: |
| Raw DOM text | 1,789 | 448 | baseline |
| Projected q compact | 288 | 72 | -376 tokens (-83.9%) |

Byte reduction: 1,501 bytes (-83.9%). The compact result retains one schema
header plus `id`, `price`, and `title` for all five items; descriptions,
ratings, developer metadata, buttons, navigation, and footer noise are absent.

## Validation Evidence

Each gate ran as a standalone process; no gate was piped through `tee`.

### Revision 2 gates

| Command | Exit | Result |
| --- | ---: | --- |
| `go test -count=1 ./internal/browsersession ./internal/browserfacade ./cmd/mac-browser-site` before production fix | 1 | Expected red: every new F1/F2 regression test reproduced the reviewer findings. |
| `go test -count=1 ./internal/browsersession ./internal/browserfacade ./cmd/mac-browser-site` after fix | 0 | Focused production paths and negative tests pass. |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `go test -count=1 ./...` | 0 | Full module passes. |
| `go vet ./...` | 0 | Vet/lint gate clean. |
| `go build ./...` | 0 | All commands compile. |
| `go test -count=1 -cover ./internal/browsersession ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 69.5% / 80.7% / 88.9% statement coverage. |
| `git diff --check` | 0 | No whitespace errors. |
| `task-board validate` | 0 | Board valid. |
| `./scripts/setup.sh` | 0 | Full tests, build, signing, binary symlinks, and runtime skill install succeeded; privileged daemon untouched. |
| installed `mac-browser-site q` schema + projected list smoke | 0 | Compact batch rendered; `api_key`, `signature`, and fragment values were redacted in output/cache. |
| installed `mac-browser-site q` pagination adapter-bound smoke | 0 | Two distinct pages; bounded continuation reported `hasMore:"unknown"`. |
| installed `mac-browser-site grep` cache-only smoke | 0 | Found the sanitized cached record without browser access. |
| installed `mac-browser-site m --dry-run` | 0 | Preview only; no transport dispatch. |
| installed `mac-browser-site m` without authorization | 1 | Expected refusal: `CONFIRM_REQUIRED`; no write. |
| installed secret list smoke | 1 | Expected refusal: `SENSITIVE_RESPONSE_REFUSED`; no secret output/cache. |
| installed secret schema smoke | 2 | Expected adapter refusal: `SENSITIVE_RESPONSE_REFUSED`; schema not rendered. |
| source/runtime facade-reference `cmp` | 0 | Installed skill bytes match source. |

The concise revision-2 command/output record is attached separately as
`TASK-260823-17qhsl_rework-cycle1-validation-2026-08-24.md`.

| Command | Exit | Result |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` (first development run) | 1 | Unexpected red: fake envelopes claimed `take=1` while production requested bounded `take=100`; strict validator correctly refused. Fixture and one JS assertion were corrected. |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site ./scripts` | 0 | Focused facade, production CLI, and lifecycle tests pass. |
| `go test -count=1 ./...` | 0 | Full module passes. |
| `go test -count=1 -cover ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 80.2% / 87.8% statement coverage. |
| `go vet ./...` | 0 | Vet clean. |
| `go build ./...` | 0 | All commands compile. |
| `gofmt -l cmd internal scripts` | 0 | Empty output; formatting clean. |
| `git diff --check` | 0 | No whitespace errors. |
| `./scripts/setup.sh` | 0 | Tests, builds, signs Chrome transport, installs `mac-browser-site`, and installs the mac-infra skill. Privileged daemon intentionally untouched. |
| installed `/Users/alexis/.local/bin/mac-browser-site q ...` against task fake transport | 0 | Five projected rows; proven `hasMore=false`; private cache emitted. |
| installed binary version plus source/runtime `cmp` for `SKILL.md` and facade reference | 0 | Binary available; installed skill bytes match source. |
| real binary `grep` against named task cache | 0 | Two scoped matches; no browser access. |
| real binary `m --dry-run` | 0 | Preview; `applied=false`, `verification=not-run`. |
| real binary `m` without confirmation | 1 | Expected-red `CONFIRM_REQUIRED`; no write. |
| real binary `m --confirm` against task fake transport | 0 | Declared action dispatched; verification honestly `unknown`. |

Development red-gate details are preserved in
`.temp/TASK-260823-17qhsl/focused-test-01.log`; tool readiness is in
`.temp/TASK-260823-17qhsl/tool-readiness-01.log`.

## Documentation And Installation

- README tools inventory and guarded browser workflow document q/grep/m,
  artifacts, pagination, cache, mutation, and secret boundaries.
- `agents/skills/mac-infra/references/browser-site-facade.md` contains the full
  adapter contract and examples; Chrome and Safari references link to it.
- The main `SKILL.md` routes facade work lazily and remains 499 lines.
- `scripts/setup.sh` builds/installs `mac-browser-site`; `scripts/deinit.sh`
  removes it. Lifecycle tests cover setup registration.
- LOGBOOK entries `2026-08-24 / 0055` and `/ 0110` record the architectural,
  safety, secret-boundary, and pagination-evidence decisions.

## Shared-Lane Provenance

The Story worktree already contained uncommitted extractor/browser-session work
before this implementation. Existing files/directories included Safari and
Chrome session CLIs, `internal/browserquery`, `internal/browsersession`,
`internal/chromectl`, README, skill docs, setup/deinit, and LOGBOOK. No reset,
checkout, staging, commit, or discard was performed.

Task-owned additions are `cmd/mac-browser-site`, `internal/browserfacade`, and
`agents/skills/mac-infra/references/browser-site-facade.md`. Required integration
caused explicit overlaps in README, LOGBOOK, main skill, Chrome/Safari
references, `scripts/setup.sh`, `scripts/deinit.sh`, and `scripts/deinit_test.go`.
The earlier extractor/session implementation remains shared-lane scope and is
not claimed as newly authored by this outcome.
