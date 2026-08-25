# BUG-260825-357yix developer rework outcome

## Reviewer findings addressed

- Boundary-rejected xox/xapp matches now resume scanning at the next byte, so a valid nested token start is still found.
- JWT-like compact tokens now consume every additional dot-delimited segment instead of returning a raw 4+/5-part tail.
- Overlapping Bearer and xox/xapp spans are explicitly covered through the production response path and unioned before replacement.
- The shared request-side secret-shape guard rejects the same nested-start shape before browser execution.

Production call site under proof: `Session.SlackRead` -> `sanitizeSlackResponse` -> `redactSlackTokenSpans`.

## Red and green evidence

- Pre-fix focused regression command: exit 1. Nested xapp/xox bytes survived, compact-token segments 4 and 5 survived, and the same nested token reached the browser execution boundary.
- Post-fix focused regression command: exit 0.
- Restored six-test production mutant set: exit 0.

## Narrowing mutant evidence

Each mutant ran separately with `-count=1`, failed the named production `Session.SlackRead` test with exit 1, and production source was restored from a task-scoped copy with byte equality checked by `cmp`.

- Rejected-match search advanced to the rejected match end: `TestSlackReadProductionPathRescansAfterRejectedTokenStart`, exit 1; nested synthetic token leaked.
- Compact-token regexp narrowed to exactly three segments: `TestSlackReadProductionPathRedactsEveryCompactTokenSegment`, exit 1; synthetic segments 4 and 5 leaked.
- Overlap union narrowed to equal-start spans: `TestSlackReadProductionPathUnionsOverlappingSecretSpans`, exit 1; production sanitizer panicked on overlapping Bearer/xox spans.
- Bearer collector removed: `TestSlackReadProductionPathBearerClassCannotBeNarrowed`, exit 1; synthetic Bearer value leaked.
- Replacement narrowed to the first span: `TestSlackReadProductionPathEveryOccurrenceCannotBeNarrowed`, exit 1; the second synthetic xox span leaked.
- Span-local replacement replaced with whole-string replacement: `TestSlackReadProductionPathWholeStringRedactionCannotReturn`, exit 1; safe synthetic surrounding reference was lost.

## Validation

- `go test ./... -count=1`: exit 0.
- `go vet ./...`: exit 0.
- `go build -o .temp/BUG-260825-357yix/mac-chrome-session ./cmd/mac-chrome-session`: exit 0.
- `git diff --check`: exit 0.
- `bash -n scripts/setup.sh`: exit 0.
- `./scripts/setup.sh`: exit 0; installed and signed the updated CLI.
- `codesign --verify --strict bin/mac-chrome-session`: exit 0.

## Installed content-free live smoke

The installed CLI performed one read-only `search.messages` request rooted only at the authorized synthetic `REF-SYN-4242` reference. The projection stayed in memory and printed only booleans/counts. No Slack write, message content, browser authorization material, or raw response was persisted.

- CLI exit: 0
- Envelope OK: true
- Synthetic reference count: 11
- Redaction marker count: 6
- Raw token-shape count: 0
- Surrounding synthetic reference preserved: true
- Raw token shapes absent: true

## Repository scope

- `internal/chromectl/slack.go`
- `internal/chromectl/slack_test.go`
- `cmd/mac-chrome-session/main_test.go`
- `README.md`
- `LOGBOOK.md`

No provider method or Slack write behavior changed.
