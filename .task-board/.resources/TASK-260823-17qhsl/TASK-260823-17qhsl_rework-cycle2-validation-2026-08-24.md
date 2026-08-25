# TASK-260823-17qhsl — Revision 3 Validation

Date: 2026-08-24 MSK
Run: `RUN-260823-2142a1`
Rework target: `CR-TASK-260823-17qhsl-2`, revision 2 findings; producer candidate for revision 3

## Authoritative Scope

- Goal checkpoint: `GOAL-260823-c561be`, revision 1.
- Resolved scope: `TASK-260823-17qhsl`.
- Review policy: `required`.
- No operator directives were recorded at the pre-validation checkpoint.
- Shared Story worktree changes were preserved; no reset, checkout, staging,
  commit, rebase, merge, or discard was performed.

## Centralized Boundary Evidence

The revision replaces per-surface secret decisions with one canonical scanner,
one normalized decision type, and one `EnforceOutbound` call used by:

- `Facade.Query` for q schema/list structured values;
- `Cache.Write`, `readBoundedLines`, and `Cache.Grep` for cache read/write and
  canonical grep results;
- `Adapter.Validate` and `ExecRunner`/CLI `fail` for metadata and errors;
- `RenderQuery`, `RenderGrep`, and `RenderMutations` through buffered
  `WriteOutbound` for compact and JSON output.

The first focused run after adding revision-3 narrowing tests exited 1 and
reproduced uppercase URL, GitLab token, nested encoded URL, malformed URL,
duplicate-key JSONL, direct renderer, cache-write, and CLI error bypasses. After
the production change, the same command exited 0. Synthetic values are omitted
from this artifact.

## Standalone Source Gates

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` before fix | 1 | Expected red: all revision-3 narrowing variants reproduced. |
| same focused command after fix | 0 | Central boundary and production entry tests pass. |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `go test -count=1 ./...` | 0 | All packages pass; deterministic extractor tests remain green. |
| `go vet ./...` | 0 | Empty output. |
| `go build ./...` | 0 | All commands compile. |
| focused coverage command | 0 | browserfacade 80.6%; CLI 88.7% statement coverage. |
| `git diff --check` | 0 | Empty output. |
| `task-board validate` | 0 | Board valid. |
| `./scripts/setup.sh` | 0 | Tests/build/sign/install and skill sync succeeded; privileged daemon untouched. |

## Installed Artifact Attack Smokes

Every command below invoked `/Users/alexis/.local/bin/mac-browser-site` with a
task-scoped fake exact-target transport and isolated task cache.

| Smoke | Exit | Evidence |
| --- | ---: | --- |
| version | 0 | Installed binary available. |
| safe schema + compact projected q | 0 | Batching/projection rendered and cache was created. |
| safe cache-only grep | 0 | Canonical cached record found without browser access. |
| uppercase scheme/host with duplicate mixed-case sensitive query keys | 0 | Every sensitive value redacted in stdout and cache. |
| GitLab-token list attack | 1 | `SENSITIVE_RESPONSE_REFUSED`; no cache created. |
| nested/repeatedly encoded secret-URL list attack | 1 | `SENSITIVE_RESPONSE_REFUSED`; no cache created. |
| malformed secret-bearing URL | 1 | `SENSITIVE_RESPONSE_UNKNOWN`; no cache created. |
| duplicate-key cache shadowing grep | 1 | `SENSITIVE_RESPONSE_REFUSED`; raw JSONL was not rendered. |
| secret-bearing uppercase schema metadata | 2 | Adapter refused before `schema()` output. |
| GitLab-token transport error | 1 | `TRANSPORT_FAILED` with generic withheld detail. |
| mutation `--dry-run` | 0 | Preview only; no dispatch. |
| mutation without confirmation | 1 | Expected `CONFIRM_REQUIRED` refusal. |
| confirmed declared mutation | 0 | Dispatch occurred; verification remained honestly `unknown`. |
| rejected-read cache-absence checks | 0 | GitLab, nested, malformed, and transport-error homes contain no cache root. |
| installed `SKILL.md` and facade-reference `cmp` | 0 | Runtime skill bytes match source. |

One preliminary safe-smoke shell invocation exited 1 before the CLI launched
because zsh expanded an unquoted `?` in an environment value. The corrected
standalone CLI command exited 0; this shell quoting retry is not counted as a
product gate.

## Output-Size Evidence

The representative comparison remains unchanged: raw synthetic marketplace DOM
text is 1,789 bytes / about 448 tokens versus 288 bytes / about 72 tokens for
projected compact q output, a reduction of 1,501 bytes and approximately 83.9%.

## Provenance

Revision-3 repository changes are limited to the browserfacade centralized
outbound boundary and its production callers/tests, `cmd/mac-browser-site`
final error enforcement/tests, README, facade skill reference, and LOGBOOK.
Earlier Safari/Chrome/extractor/setup and sibling Story work remain shared-lane
scope and are not claimed as revision-3 authorship.
