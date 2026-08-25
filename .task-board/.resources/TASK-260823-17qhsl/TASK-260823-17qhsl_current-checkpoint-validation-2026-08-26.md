# TASK-260823-17qhsl — Current Checkpoint Recovery Validation

Date: 2026-08-26 MSK  
Run: `RUN-260826-42e886`  
Resolved scope: `TASK-260823-17qhsl`  
Review policy: `required`

## Recovery Result

The revision-8 Change Request snapshot was stale behind later Story checkpoints,
so this run revalidated the facade from the current managed Story tree at
`513250c427ac115fadc7b9239e6bd594c4e4e88e` without broadening the design.

No current defect reproduced. The checkpoint already contains the owner-level
final-cache-symlink fix and its source production tests:

- `browserfacade.Cache.Grep` returns nonzero `CACHE_SCOPE_REFUSED` when
  `--file` explicitly names a final `.jsonl` symlink.
- Broad cache scans still ignore unrequested symlinks.
- The descriptor-rooted/no-follow cache owner does not follow or modify the
  external target.
- Compact and JSON production paths disclose neither the external marker nor
  its physical path.
- The single `EnforceOutbound` owner, normalized outbound state, deterministic
  extractor, tri-state pagination, exact target/origin guards, q/grep/m
  separation, mutation preview/confirm contract, and token comparison remain
  unchanged.

No task-owned source edit was required. `cmd/mac-browser-site`,
`internal/browserfacade`, and
`agents/skills/mac-infra/references/browser-site-facade.md` are clean relative
to current `HEAD` and index. Existing staged/unstaged Chrome, Safari,
browser-session, setup/deinit, README, skill, and LOGBOOK changes are sibling
Story-lane work; this run did not reset, stage, commit, discard, or claim them.

## Negative And Narrowing Evidence

Every gate below ran as a standalone process without `tee`.

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site -run 'TestGrepIsBoundedToNamedSiteCacheIgnoresUnrequestedSymlinksAndRefusesExplicit\|TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats'` | 0 | Cache owner and real compact/JSON `runGrep` entry refuse an explicitly named final symlink. |
| Narrow only the explicit-final-symlink branch from refusal to `continue`; `go test -count=1 ./cmd/mac-browser-site -run '^TestRunGrepProductionEntryRefusesExplicitFinalCacheSymlinkAcrossFormats$'` | 1 | Expected red: compact and JSON both returned false-success exit 0/empty, so the named production test failed. |
| `cmp -s internal/browserfacade/cache.go .temp/TASK-260823-17qhsl/cache.go.before-recovery-mutant` after restoration | 0 | Owner source restored byte-exact. |
| Same named production test after restoration | 0 | Restored gate active. |
| Source-built final-symlink production smoke, compact / JSON | 0 harness; inner exits 1 / 1 | Typed refusal; marker/path absent; external file and symlink preserved. |
| Freshly installed final-symlink production smoke, compact / JSON | 0 harness; inner exits 1 / 1 | Same installed production behavior and preservation assertions. |

The first attempted full-suite run was not counted: its process reached terminal
state after the caller lost attachable exit metadata. The suite was rerun from
scratch in an observed PTY and only that terminal exit is reported below.

## Source Gates

| Command | Exit | Result |
| --- | ---: | --- |
| `go test -count=1 ./...` (observed rerun) | 0 | Full uncached module green; `cmd/mac-browser-site` 128.847s, `internal/browserfacade` 18.939s, `internal/browserquery` 6.679s, `internal/browsersession` 28.706s, `internal/chromectl` 140.473s. |
| `go vet ./...` | 0 | Empty output. |
| `go build ./...` | 0 | All commands compile. |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `git diff --check` | 0 | Unstaged layer has no whitespace errors. |
| `git diff --cached --check` | 0 | Staged sibling layer has no whitespace errors. |
| `git diff HEAD --check` | 0 | Composed current tree has no whitespace errors. |
| `go test -count=1 -cover ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 81.4% / 88.7% statement coverage. |
| `task-board validate` | 0 | Authoritative board valid. |
| `./scripts/setup.sh` | 0 | Project tests/build/sign/install and skill sync pass; privileged daemon untouched. |

## Installed Architecture Regression Matrix

| Installed entry | Exit | Result |
| --- | ---: | --- |
| Canonical redacted q -> grep, compact / JSON | 0 / 0 | Protected query/fragment values absent from output and canonical cache. |
| Nested encoded URL, duplicate extractor evidence, escaped transport error, compact / JSON | 1 for each attack | Typed refusal/unknown; disclosure and cache absent. |
| Duplicate-key cache grep | 1 | Shadowed sensitive value absent. |
| Ancestor-symlink cache grep | 1 | `CACHE_SCOPE_REFUSED`; external target preserved. |
| Explicit final-symlink grep, source and installed, compact / JSON | 1 for each inner CLI | `CACHE_SCOPE_REFUSED`; external bytes/link preserved. |
| Mutation no-confirm / dry-run / confirm | 1 / 0 / 0 | Refusal and preview do not dispatch; declared confirmed mutation dispatches. |
| Pagination adapter bound, compact / JSON | 0 / 0 | `hasMore=unknown`. |
| Chrome exact target/origin capture | 0 | Window 11, tab 22, and `https://shop.example` preserved. |
| Hostname/path attacks | 0 harness; 22 inner attacks exit 1 | Credential/opaque/cookie/session/storage host and path variants refuse/unknown; stdout, stderr, and cache disclosure absent. |

Fresh output-size evidence remains:

| Output | Bytes | Estimated tokens (`bytes / 4`) | Delta |
| --- | ---: | ---: | ---: |
| Raw extractor response | 893 | 223 | baseline |
| Projected compact q | 132 | 33 | -761 bytes / -190 tokens (-85.2%) |

## Source / Install Parity And Provenance

- Source and installed `mac-browser-site` SHA-256:
  `83e89780db5adc0a31fb6b38fb0a24742249d0aee25b9f7d50f5d99306e4e9f3`.
- Binary `cmp`, installed `SKILL.md` `cmp`, and installed
  `browser-site-facade.md` `cmp`: exit 0.
- `internal/browserfacade/cache.go` SHA-256:
  `57eb400efb59104ddeb437dad119bdc5c447a62a9e566f5fec4f13f4c72aca4b`.
- `cmd/mac-browser-site/main_test.go` SHA-256:
  `61b826b7df09d8b366d6701a7adc825046665419767fd555e28a172235a8ef26`.
- Current Story branch is one commit behind `main`; the assignment forbids
  merge/rebase/switch, so no branch mutation was attempted.
- No human-only decision, external blocker, or forced-fit workaround remains.

The current checkpoint is ready for a fresh independent review Change Request.
