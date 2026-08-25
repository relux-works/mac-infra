# TASK-260823-17qhsl — Revision 2 Validation

Date: 2026-08-24 MSK
Run: `RUN-260823-11dfef`
Change Request: `CR-TASK-260823-17qhsl-1`, revision 2 producer candidate

## Authoritative Scope

- Goal snapshot at the validation checkpoint: `GOAL-260823-5fb86b`, revision
  1, resolved scope `TASK-260823-17qhsl`.
- No operator directives were recorded at the checkpoint.
- Shared Story worktree changes were preserved; no reset, checkout, staging,
  commit, rebase, merge, or discard was performed.

## Regression Evidence

The first focused run after adding tests exited 1 and reproduced every requested
class: `api_key`/`signature` remained visible, GitHub-token material reached
list/cache, schema metadata emitted Bearer/secret URLs, duplicate/bounded pages
reported guessed booleans, and a partial advance envelope became false
exhaustion. This was the expected red state, not a passing gate.

After the production fix, the same focused command exited 0. Tests drive these
production call sites:

- `cmd/mac-browser-site.runQuery -> browserfacade.Facade.Query`
- `cmd/mac-browser-site.runGrep -> browserfacade.Cache.Grep`
- `browserfacade.CLITransport.Extract/Evaluate`
- `browserfacade.Cache.Write/readBoundedLines`

The narrowed negative classes are Bearer metadata, GitHub token prefixes,
`api_key`, `signature`, duplicate pages, caller/adapter/global bounds, missing
extract fields, and missing `advanced` evidence. Synthetic secret values were
asserted absent from stdout, stderr, and cache; raw values are intentionally not
repeated in this artifact.

## Standalone Gate Results

| Command | Exit | Evidence |
| --- | ---: | --- |
| `gofmt -l cmd internal scripts` | 0 | Empty output |
| `go test -count=1 ./...` | 0 | All packages pass |
| `go vet ./...` | 0 | Empty output |
| `go build ./...` | 0 | Empty output |
| focused coverage command | 0 | browsersession 69.5%; browserfacade 80.7%; CLI 88.9% |
| `git diff --check` | 0 | Empty output |
| `task-board validate` | 0 | Board valid |
| `./scripts/setup.sh` | 0 | Tests/build/sign/install/skill sync succeeded |
| installed q schema/list smoke | 0 | Projection and URL redaction visible |
| installed q pagination-bound smoke | 0 | `hasMore:"unknown"` |
| installed grep smoke | 0 | Sanitized cache-only match |
| installed mutation preview | 0 | No-write preview |
| installed mutation without confirm | 1 | Expected `CONFIRM_REQUIRED` refusal |
| installed GitHub-token list attack | 1 | Expected `SENSITIVE_RESPONSE_REFUSED` refusal |
| installed secret schema attack | 2 | Expected `SENSITIVE_RESPONSE_REFUSED` adapter refusal |
| installed skill reference `cmp` | 0 | Source/runtime bytes equal |

## Output Size Evidence

The existing representative fixture remains unchanged and valid: raw DOM text
1,789 bytes / about 448 tokens versus projected compact output 288 bytes / about
72 tokens, a reduction of 1,501 bytes and approximately 83.9%.

## Provenance

Revision-2 code changes are limited to browser-facade pagination/secret policy,
the shared browser-session URL redactor required by F1, their tests, README,
the facade skill reference, and LOGBOOK. Earlier Safari/Chrome/extractor/setup
work remains shared-lane scope and is not newly claimed here.
