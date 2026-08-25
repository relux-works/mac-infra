# TASK-260823-17qhsl — Revision 4 Validation

Date: 2026-08-24 MSK  
Run: `RUN-260823-80c93c`  
Rework target: `CR-TASK-260823-17qhsl-3` revision 3 findings; producer candidate for revision 4

## Authoritative Scope

- Goal checkpoint: `GOAL-260823-9da10a`, revision 1.
- Resolved scope: `TASK-260823-17qhsl`.
- Review policy: `required`.
- The directive checkpoint reported no operator directives.
- Shared Story worktree changes were preserved; no reset, checkout, staging,
  commit, rebase, merge, or discard was performed.

## Revision 4 Production Fix

- `internal/browserfacade/outbound.go` remains the single scanner and normalized
  `clean` / `redacted` / `refused` / `unknown` decision owner. It now scans
  decoded URL query names as well as values, refuses a secret-bearing name,
  boundedly rescans transformed URLs, and recognizes common `sk-proj-*` and
  `sk-*` opaque credential forms alongside the existing token families.
- `CLITransport.Extract`, pagination advance decoding, and mutation evidence
  decoding now call the same outbound decision before any lossy JSON decode.
  Duplicate item, `advanced`, or `applied` keys therefore become explicit
  refusal/unknown rather than plausible evidence.
- Cache traversal now opens a descriptor-rooted `os.Root` beneath the trusted
  user-config anchor, verifies every facade-owned directory component with
  `Lstat`, refuses symlink components, and performs cache create/open/rename/read
  inside the rooted descriptor. The reviewed `mac-infra` ancestor-symlink escape
  cannot reach an external physical directory.
- README and the installed browser-site facade reference describe the bounded
  recognizable-token contract truthfully and document query-name scanning,
  transformed-output rescanning, pre-decode evidence validation, and physical
  cache anchoring.

## Negative Evidence

The production-entry tests were added before production changes. The first
standalone focused run exited 1 and reproduced every revision 3 finding:

- nested encoded secret URL in an outer URL query name escaped compact/JSON q;
- `sk-proj-*` and `sk-*` escaped compact/JSON q and cache;
- duplicate extractor item keys, advance keys, and mutation attestation keys
  were accepted after lossy decode;
- production grep followed a symlinked `mac-infra` ancestor and rendered the
  external record.

After the centralized fix, the exact focused command exited 0. Tests assert
non-zero refusal/unknown, absence from stdout/stderr/cache, and no escaped
filesystem record. Production call sites are `runQuery -> Facade.Query ->
CLITransport.Extract`, `Facade.advance`, `runMutation -> Facade.Mutate`, and
`runGrep -> Cache.Grep`.

## Standalone Source Gates

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go test -count=1 ./internal/browserfacade ./cmd/mac-browser-site` before fix | 1 | Expected red; all four rev3 findings reproduced at production entries. |
| Same focused command after fix | 0 | New narrowing tests and existing facade tests pass. |
| `gofmt -l cmd internal scripts` | 0 | Empty output. |
| `go test -count=1 ./...` | 0 | Full module passes; deterministic extractor/template/predicate coverage remains green. |
| `go vet ./...` | 0 | Empty output. |
| `go build ./...` | 0 | Every command compiles. |
| `go test -count=1 -cover ./internal/browserfacade ./cmd/mac-browser-site` | 0 | 80.5% / 88.7% statement coverage. |
| `git diff --check` | 0 | Empty output. |
| `task-board validate` | 0 | Board valid. |
| `./scripts/setup.sh` | 0 | Tests/build/sign/install and runtime skill sync succeeded; privileged daemon untouched. |

`task-board version` was also probed during tool readiness and truthfully exited
1 because that command does not exist. Working board commands, including status,
q, goal/directive checkpoints, resource materialization, validation, and later
handoff, produced their expected output.

## Installed Artifact Smokes

Every command invoked `/Users/alexis/.local/bin/mac-browser-site`, whose symlink
resolved to the Story worktree's freshly installed binary. Synthetic attack
values are intentionally omitted from this artifact.

| Smoke | Exit | Evidence |
| --- | ---: | --- |
| version | 0 | Installed binary available. |
| nested URL in query name, JSON / compact | 1 / 1 | `SENSITIVE_RESPONSE_REFUSED`; attack value absent. |
| `sk-proj-*`, JSON / compact | 1 / 1 | `SENSITIVE_RESPONSE_REFUSED`; token absent. |
| `sk-*`, JSON / compact | 1 / 1 | `SENSITIVE_RESPONSE_REFUSED`; token absent. |
| duplicate extractor item keys, JSON / compact | 1 / 1 | `SENSITIVE_RESPONSE_REFUSED`; safe shadow value and secret absent; no cache. |
| duplicate pagination `advanced` keys | 1 | `SENSITIVE_RESPONSE_UNKNOWN`; no guessed continuation evidence. |
| duplicate mutation `applied` keys | 1 | `SENSITIVE_RESPONSE_UNKNOWN`; no success attestation. |
| symlinked installed site-cache component | 1 | `CACHE_SCOPE_REFUSED`; external record absent. |
| task-scoped rejected-read cache absence | 0 | No site cache existed after rejected q/advance reads. |
| safe schema + projected compact q | 0 | Batch/projection rendered and cache was created. |
| safe cache-only grep | 0 | Canonical cached record found without browser access. |
| mutation `--dry-run` | 0 | Preview only; no dispatch. |
| installed `SKILL.md` / facade-reference `cmp` | 0 / 0 | Runtime skill bytes match source. |

The source production grep test covers the exact reviewed ancestor shape
(`Application Support/mac-infra` symlink). The installed smoke uses a unique
task-scoped symlinked site component under the real cache anchor and proves the
installed descriptor-rooted refusal without replacing the user's real
`mac-infra` directory. The task-created symlink and safe cache directory were
moved into `.temp/TASK-260823-17qhsl/revision4-installed/artifacts/` after the
smokes; no user cache record was left behind.

## Preserved Acceptance Evidence

- Deterministic extractor/template/predicate behavior remains unchanged and the
  full suite passes.
- Pagination retains tri-state evidence: only observed extra records prove
  `true`, only complete `none` or explicit `advanced:false` prove `false`, and
  bounded/duplicate/indeterminate continuation remains `unknown`.
- q/grep/m separation, projection, batching, schema, cache-only search,
  confirmation/dry-run mutation boundaries, and compact rendering remain green.
- Representative output comparison is unchanged: raw synthetic marketplace DOM
  1,789 bytes / about 448 tokens versus projected compact q 288 bytes / about 72
  tokens, an 83.9% reduction.

## Provenance

Revision 4 changes are limited to the centralized browser-facade outbound
boundary, evidence decoders, physically rooted cache implementation, their
production-entry negative tests, README, facade skill reference, LOGBOOK, and
task-scoped evidence. Earlier Safari/Chrome/extractor/setup and sibling Story
work remain shared-lane scope and are not claimed as revision 4 authorship.
