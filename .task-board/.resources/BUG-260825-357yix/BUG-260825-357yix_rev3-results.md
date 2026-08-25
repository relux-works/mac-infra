# BUG-260825-357yix developer revision 3 outcome

## Implementation

- Replaced the quadratic rejected-boundary rescan with one `FindAllStringSubmatchIndex` pass per token class.
- Encoded the left boundary in each regexp and used only capture group 1 as the replacement span.
- Preserved nested xox/xapp detection, arbitrary compact JWT/JWE tails, overlap union, request-side refusal, structured secret-key/URL handling, JSON bounds, and span-local surrounding text.
- Added a production `Session.SlackRead` cost gate at the exact 256 KiB response ceiling and a deterministic 200,000-case legacy differential corpus.

Production call site under proof: `Session.SlackRead` -> `sanitizeSlackResponse` -> `redactSlackTokenSpans`.

## Cost and differential evidence

- Linear scanner ceiling test: exit 0, 0.46 seconds in the final rerun, under a 3-second bound.
- CR revision 2 quadratic mutant: exit 1 after 3.00 seconds in the same named ceiling test.
- Differential corpus: exit 0; all 101,326 legacy detections preserved across 200,000 deterministic cases.

## Narrowing mutant evidence

Every mutant ran with `-count=1`, failed its named production-path test with exit 1, and `internal/chromectl/slack.go` was restored from a task-scoped copy with byte equality verified.

- Slack left boundary narrowed to exclude the nested hyphen start: response leak and request-side browser-execution bypass tests failed.
- Compact JWT/JWE tail narrowed to one extra segment: the fifth segment leaked.
- Overlap union deleted: overlapping Bearer/xox spans panicked in production sanitization. This was a delete-shaped mutant, not proof of the end-extension narrowing branch.
- Bearer collector removed: synthetic Bearer bytes leaked.
- Replacement narrowed to the first occurrence: the second synthetic xox span leaked.
- Whole-string replacement restored: the safe synthetic surrounding reference was lost.

## Green validation

- `go test ./internal/chromectl ./cmd/mac-chrome-session -count=1`: exit 0.
- `go test ./... -count=1`: exit 0 on the counted terminal rerun; 28 packages were exercised.
- `go vet ./...`: exit 0.
- `go build -o .temp/BUG-260825-357yix-rev3/mac-chrome-session ./cmd/mac-chrome-session`: exit 0.
- `gofmt -l ./cmd ./internal`: exit 0 with empty output.
- `git diff --check`: exit 0.
- `bash -n scripts/setup.sh`: exit 0.
- `./scripts/setup.sh`: exit 0; installed and signed the current CLI.
- `codesign --verify --strict bin/mac-chrome-session`: exit 0.

## Installed content-free live smoke

The installed CLI performed one read-only `search.messages` request rooted only at the authorized synthetic `REF-SYN-4242` reference. The response remained in memory and only counts/booleans were printed. No Slack write, real message content, browser authorization material, or raw response was persisted.

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
