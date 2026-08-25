# TASK-260823-17qhsl — CR Revision 7 Final-Cache-Symlink Rework Validation

Date: 2026-08-24 MSK  
Run: `RUN-260824-dd7751`  
Goal checkpoint: `GOAL-260824-7c106b` revision 1  
Resolved scope: `TASK-260823-17qhsl`  
Review policy: `required`

## Finding And Scoped Fix

Revision 7 treated an explicitly requested final cache symlink as an unrelated
directory entry and skipped it before the descriptor-rooted open. Source-built
and freshly installed `grep --file` therefore returned exit 0 and an empty
result, laundering a failed read into absence. The independent revision-7
review reproduced all four format/install combinations; this run accepted that
already-attached baseline evidence and did not claim to rerun it before editing.

The fix remains inside `browserfacade.Cache.Grep`, the existing
descriptor-rooted/no-follow owner. When `ReadDir` identifies a symlink whose
basename exactly equals explicit `GrepOptions.File`, the cache returns
`CACHE_SCOPE_REFUSED`. Unrequested symlinks still do not participate in broad
cache scans. No CLI, renderer, outbound-scanner, q, m, pagination, extractor, or
browser-transport filter was added, and the external target is not followed or
modified.

README, the mac-infra facade reference, and LOGBOOK now state the failed-read
contract explicitly.

## Production Negative And Narrowing Evidence

Every command below ran directly as a standalone process without `tee`.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site -run 'TestGrepIsBoundedToNamedSiteCacheIgnoresUnrequestedSymlinksAndRefusesExplicit|TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats'` | 0 | Unit owner and compact/JSON `runGrep` production entry refuse the explicit final symlink. |
| Narrow only the explicit-final-symlink branch from typed refusal back to `continue`; `go test -count=1 ./cmd/mac-browser-site -run '^TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats$'` | 1 | Expected red: compact and JSON both returned exit 0/empty; the named production test failed. |
| `cmp -s internal/browserfacade/cache.go .temp/TASK-260823-17qhsl/cache.go.before-final-symlink-mutant` after restoration | 0 | Production source restored byte-exact. |
| Same named production test after restoration | 0 | Restored gate is active. |
| Fresh source-built binary final-symlink smoke, compact / JSON | 0 / 0 | Each inner CLI exits 1 with `CACHE_SCOPE_REFUSED`; marker/path absent from stdout/stderr; external bytes and symlink preserved. |
| Freshly installed binary final-symlink smoke, compact / JSON | 0 / 0 | Same installed production evidence and preservation assertions. |

The smoke harness is
`.temp/TASK-260823-17qhsl/final-symlink-production-smoke.sh`. It invokes the
actual binary as a process, not a cache helper.

## Source Gates

| Command | Exit | Result |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` | 0 | Focused facade and CLI packages pass. |
| `go test -count=1 ./...` | 0 | Full uncached module passes. |
| `go vet ./...` | 0 | Empty output; vet/lint clean. |
| `go build ./...` | 0 | All commands compile. |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `git diff --check` | 0 | Empty output. |
| `go test -count=1 -cover ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 81.4% / 88.7% statement coverage. |
| `task-board validate` | 0 | Authoritative board valid. |
| `./scripts/setup.sh` | 0 | Tests/build/sign/install and skill sync pass; privileged daemon untouched. |

The full suite retains deterministic extractor/template/predicate behavior,
Chrome/Safari exact target/origin guards, q projection/batching/schema,
pagination tri-state and partial-read failures, cache canonicalization and
no-follow traversal, central outbound enforcement, transport-error projection,
and mutation preview/confirmation.

## Installed Regression Matrix

| Installed entry | Exit | Result |
| --- | ---: | --- |
| 22 hostname/path attack cases (11 classes x compact/JSON) | 0 harness; each attack 1 | Typed refusal/unknown; stdout/stderr/cache disclosure absent. |
| Canonical redacted q -> grep, compact / JSON | 0 / 0 | Protected query/fragment values absent from output and cache. |
| Nested encoded query-name URL, compact / JSON | 1 / 1 | Typed refusal; disclosure/cache absent. |
| Duplicate extractor evidence, compact / JSON | 1 / 1 | Typed refusal; shadow/cache absent. |
| Escaped raw transport error, compact / JSON | 1 / 1 | `TRANSPORT_FAILED`; raw detail absent. |
| Duplicate-key cache grep | 1 | Sensitive shadow absent. |
| Ancestor-symlink cache grep | 1 | `CACHE_SCOPE_REFUSED`; external target preserved. |
| Mutation no-confirm / dry-run / confirm | 1 / 0 / 0 | Refusal and preview do not dispatch; declared confirmed mutation dispatches. |
| Pagination adapter bound, compact / JSON | 0 / 0 | `hasMore=unknown`. |
| Chrome exact target/origin capture | 0 | Window 11, tab 22, and `https://shop.example` preserved. |

Fresh output-size evidence from the installed regression matrix:

| Output | Bytes | Estimated tokens (`bytes / 4`) | Delta |
| --- | ---: | ---: | ---: |
| Raw extractor response | 893 | 223 | baseline |
| Projected compact q | 132 | 33 | -761 bytes / -190 tokens (-85.2%) |

## Source / Install And Revision Provenance

- Source and installed `mac-browser-site` SHA-256:
  `11cac7d23b87238e90cf9401978b4a6b6d26e4b3b2a0363a84d0c2def080559e`.
- Binary `cmp`, installed `SKILL.md` `cmp`, and installed
  `browser-site-facade.md` `cmp`: exit 0.
- Revision-7 candidate contains 37 changed paths. Working-tree blob comparison
  found exactly six intentional revision-8 changes: `internal/browserfacade/cache.go`,
  `internal/browserfacade/cache_test.go`, `cmd/mac-browser-site/main_test.go`,
  README, the facade skill reference, and LOGBOOK. The other 31 blobs match
  revision 7; mode mismatch count is zero.
- The first provenance probe exited 127 because zsh variable `path` overwrote
  the shell PATH array. It changed no state and was rerun successfully with
  `candidate_path`; the failure is preserved in
  `.temp/TASK-260823-17qhsl/rev7-blob-probe-failure-01.log`.
- `task-board version` is not a supported command; readiness instead succeeded
  through `task-board --help` plus real goal/query/mutation/validation calls.
- No reset, checkout, stage, commit, rebase, merge, or discard was performed.
  Existing shared Story-lane work remains preserved and is not claimed as new
  revision-8 scope.

No directive was present at checkpoints. No human-only decision or external
blocker remains. This candidate is ready for independent review under the
Task's required review policy.
