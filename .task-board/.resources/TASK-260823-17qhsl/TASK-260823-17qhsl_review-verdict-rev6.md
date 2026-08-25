# TASK-260823-17qhsl Review Verdict — CR Revision 6

Date: 2026-08-24 MSK

## Verdict

- **Changes requested**; route `TASK-260823-17qhsl` to `to-dev`.
- This is ordinary autonomous implementation rework. There is no external
  blocker, human-only decision, or Stop-The-Line boundary.

## Authoritative Review Scope

- Reviewer goal checkpoint: `GOAL-260824-1f6a6d` revision 1.
- Resolved scope: `TASK-260823-17qhsl`.
- Change Request: `CR-TASK-260823-17qhsl-6` revision 6, supplied as `ready` in
  the managed Story workspace.
- Exact diff: base `85ce82c27b25a22c6124a30614c6e7b3bed9b8a0` to candidate tree
  `13d70c488e409c4d9d5fccdf387559736adb0a26`.
- Patch SHA-256 independently reproduced as
  `05702b89b6077c2848150999f4389b53e6d9e976242998b5d01510ffe2e55fac`;
  the materialized board patch byte-matched a fresh exact-diff export.
- All 37 candidate path blobs and modes matched the managed worktree; mismatch
  count was zero.
- No operator directive was present at the reviewer checkpoint.

## F1 — High: secret-bearing URL hostnames and paths bypass the canonical boundary

Negative shapes: **bypass path around the check** and **narrowed gate
survives**.

The architecture decision requires URL parsing to classify the decoded host
and path through the single normalized policy. Revision 6 does not enforce
that contract:

- `scanOutbound` calls `sanitizeOutboundURLs`, then removes every recognized
  URL from the `remainder` that receives credential, assignment, opaque-value,
  and normalized-variant scanning (`internal/browserfacade/outbound.go:87-127`,
  `139-164`).
- `sanitizeOutboundURL` validates scheme/host presence, user info, query names
  and values, path scalar syntax, and fragment redaction, but never classifies
  `parsed.Host`/`parsed.Hostname()` (`internal/browserfacade/outbound.go:167-223`).
- The path call at lines 211-215 uses generic `scanNestedValue` only. That path
  catches an opaque credential grammar such as `sk-proj-*`, but it does not
  apply `outboundNameState` to decoded path components. Cookie, session, and
  storage-shaped path components therefore remain clean.

Independent production reproduction used a bounded fake exact-target Chrome
transport and synthetic values. Raw synthetic values are intentionally omitted
from this board artifact.

| Attack | Source-built q | Freshly installed q | stdout/cache result |
| --- | --- | --- | --- |
| Recognized `sk-proj-*` credential in URL hostname, JSON | exit 0 | exit 0 | credential present in stdout and cache |
| Same hostname attack, compact | exit 0 | exit 0 | credential present in stdout and cache |
| Cookie-shaped hostname | exit 0 | exit 0 | synthetic cookie value present in stdout and cache |
| Session-shaped hostname | exit 0 | exit 0 | synthetic session value present in stdout and cache |
| Storage-shaped hostname | exit 0 | exit 0 | synthetic storage value present in stdout and cache |
| Cookie-shaped URL path | exit 0 | exit 0 | synthetic cookie value present in stdout and cache |
| Session-shaped URL path | exit 0 | exit 0 | synthetic session value present in stdout and cache |
| Storage-shaped URL path | exit 0 | exit 0 | synthetic storage value present in stdout and cache |

The source-built and installed JSON/compact credential-host checks each created
one cache file containing the synthetic credential. The installed checks were
rerun after this reviewer successfully executed `./scripts/setup.sh`; the
installed binary byte-matched the newly built `bin/mac-browser-site`.

This contradicts R6, the URL contract in
`TASK-260823-17qhsl_boundary-architecture-decision.md`, and the public claim
that recognized credential/browser-session material and secret-bearing URLs
cannot reach output or cache. The existing full green suite has no production
negative test for hostname or canonical path-component classification.

### Required rework

- Keep one `EnforceOutbound` owner. Do not add q/cache/renderer-specific
  filters.
- Structurally classify the decoded hostname and every decoded path component
  with the same normalized sensitive-name policy used for JSON keys,
  assignments, and query names, while also scanning each component for
  recognized credential/opaque-value forms.
- Preserve bounded normalization and fail closed on malformed or exhausted
  host/path decoding. Rescan the canonical transformed URL to a clean fixed
  point before release.
- Add source-built and freshly installed q production tests in JSON and compact
  modes for credential-bearing hosts plus cookie/session/storage host and path
  components, including mixed case/separators and encoded forms. Require
  nonzero refusal or explicit unknown and absence from stdout, stderr, and
  cache.
- Add a narrowing mutant that removes only hostname/path-component
  classification; run the named production test with `-count=1` and require it
  to fail.

## What Independently Passed

- One exported `EnforceOutbound` owner and one
  `clean | redacted | refused | unknown` vocabulary are structurally present;
  `safePublicField` delegates to the central normalized name policy.
- Final q/grep/m renderers buffer and call `WriteOutbound`; transport errors
  project a generic `TRANSPORT_FAILED` without raw stdout/stderr.
- Fresh-installed rev1-rev4 matrix checks passed for cookie/query redaction,
  uppercase duplicate query keys, encoded nested query-name URLs,
  `sk-proj-*` scalar values, ambiguous opaque values, escaped schema metadata,
  escaped transport errors, duplicate extractor/advance/mutation evidence,
  duplicate cache keys, ancestor symlinks, and mutation confirmation/preview.
- Fresh-installed pagination reported `unknown` for duplicate pages and the
  adapter bound, and `false` only for explicit non-paginated exhaustion.
- The installed Chrome transport received the exact window id, tab id, and
  origin arguments.
- Cache grep remained browser-free and descriptor-rooted for the reviewed
  duplicate-key and ancestor-symlink attacks.
- Deterministic extraction, q/grep/m separation, projection, batching, compact
  output, guarded mutation behavior, documentation, setup/deinit wiring, and
  LOGBOOK entries remain present.
- Representative comparison independently matched the producer evidence:
  1,789-byte raw fixture versus 288-byte compact projection, an 83.9% byte and
  estimated output-token reduction.

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
| `./scripts/setup.sh` | pass; fresh installed binary and skill/reference produced |
| source/install binary comparison after setup | exact byte match |
| source/install skill and facade-reference comparison | exact byte match |
| candidate path comparison | 37/37 blobs and modes match; zero mismatches |
| board patch SHA / fresh exact diff | exact byte match |
| source-built + installed hostname/path attacks | exit 0; synthetic protected material reached stdout and cache |

The positive gates establish the unaffected facade behavior but do not establish
the mandatory no-secret-escape predicate. Revision 6 is therefore not
acceptable and must return to implementation.
