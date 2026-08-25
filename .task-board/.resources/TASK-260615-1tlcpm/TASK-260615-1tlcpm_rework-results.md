# TASK-260615-1tlcpm Rework Results

## Scope

Resolved reviewer findings F1-F3 for the authenticated Safari `fetch-file`
path. The source case remains linked from task notes:
`/Users/alexis/src/mts/mts-pjsc-regulations` (`AGENTS.md`,
`documents/harvesting-notes.md`, `.scripts/safari-session.zsh`, and
`.scripts/harvest-receiver.py`).

## Behavior

- `cmd/mac-safari-session/main.go` now refuses an empty page-context chunk.
- Decoded bytes must exactly equal Safari's reported `blob.size` before output
  or metadata is written.
- Failure does not print `saved:`, replace an existing destination, or publish
  metadata.
- `internal/browsersession.ParseJavaScriptResult` retains its production
  origin re-check for a sentinel-valid `outcome:"ok"` envelope.

## Negative Evidence

Before the production fix:

- `go test ./cmd/mac-safari-session -run 'TestFetchFileProductionEntry' -count=1`
  — exit 1 as expected. Both the size-mismatch and missing-middle-chunk cases
  reached exit 0 inside the CLI and printed `saved:`, reproducing the reviewer
  finding.

After the production fix:

- `go test ./cmd/mac-safari-session -run 'TestFetchFileProductionEntry' -count=1`
  — exit 0.
- `go test ./internal/browsersession -run 'TestParseJavaScriptResultRefusesSentinelValidOKWithWrongOrigin' -count=1`
  — exit 0.
- The byte-count negative reports a larger browser size than the decoded body,
  so narrowing equality to only reject oversized local output makes the named
  production-entry test fail.

## Verification

- `go test ./cmd/mac-safari-session ./internal/browsersession ./internal/safarictl -count=1`
  — exit 0.
- `go test ./... -count=1` — exit 0 across 28 packages.
- `go vet ./...` — exit 0.
- `go build ./...` — exit 0.
- `git diff --check` — exit 0.
- `./scripts/setup.sh` — exit 0; rebuilt, signed, and installed the Safari CLI
  and refreshed the installed mac-infra skill.
- `mac-safari-session help` — exit 0; installed CLI exposes `open-bg`,
  `check-js`, `run-js`, `snapshot`, and `fetch-file`.
- `/usr/bin/codesign --verify --strict /Users/alexis/.local/bin/mac-safari-session`
  — exit 0.
- `cmp -s agents/skills/mac-infra/SKILL.md /Users/alexis/.codex/skills/mac-infra/SKILL.md`
  — exit 0.
- `task-board validate` — exit 0; no issues found.

No live authenticated page was read during rework. Browser-profile secrets,
cookies, storage, authorization headers, and tokens were not exported or
persisted.
