# TASK-260823-17qhsl Review Verdict — CR Revision 7

Date: 2026-08-24 MSK

## Verdict

- **Changes requested**; route `TASK-260823-17qhsl` to `to-dev`.
- This is ordinary autonomous implementation rework. There is no external
  blocker, human-only decision, or Stop-The-Line boundary.

## Authoritative Review Scope

- Reviewer run: `RUN-260824-a3510a`.
- Goal checkpoint: `GOAL-260824-962650` revision 1.
- Resolved scope: `TASK-260823-17qhsl`; review policy `required`.
- Change Request: `CR-TASK-260823-17qhsl-7` revision 7, supplied as `ready`.
- Exact diff: base `85ce82c27b25a22c6124a30614c6e7b3bed9b8a0` to candidate tree
  `44fe0148887b25204f42250118d72a4fb6af9f61`.
- Patch SHA-256 independently reproduced as
  `13e559f1f164e89cbd5c71d568f86b3cafa789bfeb9e4b666c26d95127c35d40`;
  the board patch byte-matched a fresh exact-diff export.
- All 37 candidate path blobs and modes matched the managed worktree; mismatch
  count was zero. Relative to revision 6, exactly the six declared paths
  changed.
- No operator directive was present at the review checkpoints.

## F1 — High: explicitly requested final cache symlink is laundered into absence

Negative shapes: **absence treated as satisfied / failure to read treated as
absence** and **bypass path around the check**.

The architecture decision requires final cache symlinks to produce a nonzero
refusal through source-built and installed `grep`, and requires malformed or
unsafe cache reads never to become an empty result. Revision 7 still violates
that contract:

- `Cache.Grep` validates `--file` as one basename, but then combines final
  symlinks with unrelated/non-JSON entries in one `continue` branch
  (`internal/browserfacade/cache.go:107-110,143-146`).
- Therefore a caller that explicitly requests a symlinked
  `query-final-link.jsonl` never reaches the descriptor-rooted `Open`; the
  unsafe final component is reported as an ordinary empty match set.
- The existing test intentionally accepts this behavior under
  `TestGrepIsBoundedToNamedSiteCacheAndIgnoresSymlinks`
  (`internal/browserfacade/cache_test.go:11-35`). It does not drive the explicit
  `--file` production path or require a refusal.
- This contradicts the authoritative architecture matrix row for
  `symlink final file`, the descriptor-rooted/no-follow invariant, and the
  public reference statement that unsafe cache reads are refusals rather than
  empty results.

Independent production reproduction created a cache-site symlink named
`query-final-link.jsonl` to an external synthetic JSONL file, then invoked
`grep --file query-final-link.jsonl` for its marker. The external marker is
intentionally summarized rather than copied into this board artifact.

| Production entry | Format | Exit | Output | External path |
| --- | --- | ---: | --- | --- |
| Source-built `mac-browser-site grep` | compact | 0 | empty stdout/stderr | preserved |
| Source-built `mac-browser-site grep` | JSON | 0 | `[]` plus newline; empty stderr | preserved |
| Freshly installed `mac-browser-site grep` | compact | 0 | empty stdout/stderr | preserved |
| Freshly installed `mac-browser-site grep` | JSON | 0 | `[]` plus newline; empty stderr | preserved |

No external bytes were disclosed and the external file was preserved, but
non-disclosure alone does not satisfy the explicit-refusal contract. Exit 0 is
false evidence that the requested cache was safely searched and contained no
match.

### Required rework

- Keep the existing descriptor-rooted/no-follow cache owner; do not add a CLI
  or renderer-specific filter.
- Treat a final symlinked `.jsonl` candidate as `CACHE_SCOPE_REFUSED`, at
  minimum whenever it is explicitly named by `--file`. Do not convert it to an
  empty result.
- Drive the real source-built and freshly installed `grep --file` entry in JSON
  and compact modes. Require nonzero typed refusal, no marker in stdout/stderr,
  and preservation of the external physical file.
- Add a narrowing mutant that changes only final-symlink refusal back to
  `continue`; the named production test must fail with `-count=1`.

## Revision-7 hostname/path finding is closed

The revision-6 hostname/path bypass no longer reproduces:

- `EnforceOutbound` remains the sole exported decision owner. Parsed hostname
  and every bounded-decoded path component pass the shared credential/opaque
  scanner and normalized sensitive-name policy.
- Source-built and freshly installed matrices each ran 22 q attacks (11 attack
  classes across compact and JSON). Project-token and opaque hostnames,
  cookie/session/storage hostnames, credential and browser-session paths,
  mixed separators/case, percent encoding, and normalization exhaustion all
  returned typed refusal/unknown with attack material absent from stdout,
  stderr, and cache.
- Additional source and installed production checks for double encoding,
  malformed percent encoding, and uppercase mixed-separator paths also failed
  closed in both formats.
- Separate hostname-only and path-only narrowing mutants each made
  `TestRunQProductionEntryRefusesSensitiveURLHostnameAndPathComponentsAcrossFormats`
  fail under `-count=1`.

## Other independently passing evidence

- Full uncached `go test -count=1 ./...`: exit 0.
- `go vet ./...`, `go build ./...`, `gofmt -l cmd internal scripts`, exact CR
  `git diff --check`, and `task-board validate`: exit 0; format/diff output empty.
- Relevant coverage: `internal/browserfacade` 81.4%; `cmd/mac-browser-site`
  88.7%.
- `./scripts/setup.sh`: exit 0. Installed binary symlink byte-matches
  `bin/mac-browser-site`; installed `SKILL.md` and facade reference byte-match
  the candidate sources.
- Source-built and installed rev1-rev6 regression matrices pass: canonical
  redacted q/grep, nested and duplicate evidence refusals, generic transport
  errors, ancestor-symlink refusal, mutation preview/confirm guard, Chrome exact
  target/origin, and pagination-bound `unknown`.
- Source-built and installed schema batching passes in JSON and compact modes;
  mutation dry-run passes in both formats.
- Output-size comparison independently reproduced 893-byte raw extraction
  versus 132-byte compact projection (85.2% reduction; estimated 223 versus 33
  output tokens). The earlier 1,789-byte / 288-byte representative evidence
  remains consistent.
- Deterministic extractor/template/predicate behavior, q/grep/m separation,
  projection/batching, pagination tri-state semantics, transport error
  projection, renderer buffering, and exact target/origin tests remain green.

The green suite demonstrates that the final-symlink explicit-refusal shape is
missing; it does not override the reproduced production failure. Revision 7 is
not acceptable and must return to implementation.
