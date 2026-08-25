# TASK-260823-17qhsl — CR Revision 6 Hostname/Path Rework Validation

Date: 2026-08-24 MSK  
Run: `RUN-260824-be972c`  
Goal checkpoint: `GOAL-260824-716ce8` revision 1  
Resolved scope: `TASK-260823-17qhsl`  
Review policy: `required`

## Reproduced Finding And Central Fix

Revision 6 removed recognized URLs from the general scanner remainder before
the decoded hostname and individual path components crossed the canonical name
and credential policy. Source production tests added before the fix reproduced
the reviewer finding with exit 1: credential/opaque hostnames and cookie,
session, and storage host/path forms reached stdout and cache.

`internal/browserfacade.EnforceOutbound` remains the sole exported decision
owner. `sanitizeOutboundURL` now structurally classifies `URL.Hostname()` and
every non-empty `URL.EscapedPath()` component after bounded `PathUnescape`.
Each decoded component passes the existing recognized/opaque credential scanner
and the same `outboundNameState` policy used by adapter fields, JSON keys,
assignments, and query names. Malformed percent components and values that still
contain encoded work after four rounds return `unknown`. No q, cache, renderer,
or transport-specific filter was added.

The accepted revision-6 architecture remains unchanged: one
`clean | redacted | refused | unknown` vocabulary, duplicate-aware pre-lossy
evidence checks, typed generic transport failures, descriptor-rooted cache,
canonical cache rendering, final buffered enforcement, exact target/origin
transport, pagination evidence, q/grep/m separation, and mutation preview/
confirmation.

## Red-To-Green And Narrowing Evidence

Every command ran directly as a standalone process without `tee`.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site -run 'TestCentralOutboundBoundaryNormalizesCleanRedactedRefusedAndUnknown|TestRunQProductionEntryRefusesSensitiveURLHostnameAndPathComponentsAcrossFormats'` before production change | 1 | Expected red: hostname/path attacks were admitted and cached. |
| Same focused production command after the central change | 0 | Unit and compact/JSON q production paths refuse or report unknown. |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` | 0 | Full facade and CLI packages pass. |
| Narrowing mutant removing only the `inspectOutboundURLHostAndPath` production call, then `go test -count=1 ./cmd/mac-browser-site -run '^TestRunQProductionEntryRefusesSensitiveURLHostnameAndPathComponentsAcrossFormats$'` | 1 | Named production test fails across host and path variants. |
| `cmp -s internal/browserfacade/outbound.go .temp/TASK-260823-17qhsl/outbound.go.before-host-path-mutant` after restoring | 0 | Mutant restoration is byte-exact. |
| Same named production test after restoration | 0 | Restored production call is active. |

The production test covers JSON and compact output for `sk-proj-*` and opaque
credential hostnames; cookie, session, and storage hostnames; credential and
browser-session path components; mixed case/separators; percent encoding; and
normalization-budget exhaustion. Every rejected case asserts nonzero typed
refusal/unknown plus absence from stdout, stderr, and cache.

## Source Gates

| Command | Exit | Result |
| --- | ---: | --- |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `go test -count=1 ./...` | 0 | Full uncached module passes. |
| `go vet ./...` | 0 | Empty output. |
| `go build ./...` | 0 | All commands compile. |
| `go test -count=1 -cover ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 81.4% / 88.7% statement coverage. |
| `git diff --check` | 0 | Empty output. |
| `task-board validate` | 0 | Board valid. |
| `./scripts/setup.sh` | 0 | Tests/build/sign/install and skill sync passed; privileged daemon untouched. |

The full suite includes the deterministic extractor/template/predicate tests,
Chrome/Safari exact target/origin tests, pagination tri-state and partial-read
tests, q projection/batching/schema tests, grep cache/no-follow tests, mutation
preview/confirm tests, and the complete revision-1-through-revision-4 central
boundary attack matrix.

## Freshly Installed Production Evidence

Installed binary:
`/Users/alexis/.local/bin/mac-browser-site`.

`installed-host-path-smoke.sh` ran 22 production q cases (11 attack classes x
compact/JSON) after the final install. Every CLI invocation exited 1 with
`SENSITIVE_RESPONSE_REFUSED` or `SENSITIVE_RESPONSE_UNKNOWN`; every raw value
was absent from stdout/stderr and no cache file was created. Covered classes:

- project-token and opaque credential hostnames;
- cookie, encoded-cookie, session, and storage hostnames;
- project-token, mixed-case cookie, encoded session/storage, and exhausted
  percent-decoding path components.

`installed-regression-smoke.sh` independently reran unaffected production
boundaries:

| Installed entry | Exit | Result |
| --- | ---: | --- |
| q redacted URL -> grep canonical cache, compact / JSON | 0 / 0 | Protected query/fragment values absent from q, grep, and cache. |
| Exact Chrome extract target/origin capture | 0 | `window-id=11`, `tab-id=22`, and `origin=https://shop.example` present. |
| Nested encoded query-name URL, compact / JSON | 1 / 1 | Typed refusal; disclosure/cache absent. |
| Duplicate extractor key, compact / JSON | 1 / 1 | Typed refusal; shadow value/cache absent. |
| Raw escaped transport error, compact / JSON | 1 / 1 | `TRANSPORT_FAILED`; raw stderr absent. |
| Duplicate-key cache grep, JSON | 1 | Sensitive shadow value absent. |
| Symlinked cache ancestor grep, compact | 1 | `CACHE_SCOPE_REFUSED`; external file preserved and not rendered. |
| m without confirm / dry-run / confirmed | 1 / 0 / 0 | Refusal and preview dispatch nothing; confirmed declared mutation dispatches. |
| Pagination at adapter bound, compact / JSON | 0 / 0 | `hasMore=unknown`. |

The installed comparison used a fresh safe raw extractor fixture and the same
installed q projection:

| Output | Bytes | Estimated tokens (`bytes / 4`) | Delta |
| --- | ---: | ---: | ---: |
| Raw extractor response | 893 | 223 | baseline |
| Projected compact q | 132 | 33 | -761 bytes / -190 tokens (-85.2%) |

The earlier representative 1,789-byte raw / 288-byte compact result remains
attached and was independently matched by revision-6 review; this fresh run
confirms the reduction after the hostname/path change.

## Source / Install And Revision Provenance

- Source and installed binary SHA-256:
  `f9ca7163ac176e25690dc144804751a49668463737f7664ce8f14876c4bfa507`.
- Binary `cmp`: exit 0.
- Source/installed `SKILL.md` `cmp`: exit 0.
- Source/installed `browser-site-facade.md` `cmp`: exit 0.
- Installed symlink targets this managed Story worktree's
  `bin/mac-browser-site`.
- All 37 revision-6 candidate paths were compared by blob. Exactly six changed:
  `internal/browserfacade/outbound.go`, its unit test,
  `cmd/mac-browser-site/main_test.go`, README, the facade skill reference, and
  LOGBOOK. The other 31 path blobs remain byte-identical to revision 6.
- No reset, checkout, stage, commit, rebase, merge, or discard was performed.
  Existing Safari/Chrome session, extractor, lifecycle, and other shared-lane
  work remains preserved and is not claimed as new scope.

No directive was present at checkpoints. No human-only decision or external
blocker remains. This candidate is ready for independent review under the
Task's required review policy.
