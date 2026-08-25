# BUG-260825-357yix developer revision 5 outcome

## Scope

- Added `TestSlackReadProductionPathRedactsTokenInURLPath` to cover the
  reviewer-identified URL policy fall-through through production
  `Session.SlackRead`.
- Retained the revision 4 partial-overlap production-path regression and the
  revision 3 exact-ceiling cost bound.
- This rework is test-only relative to CR revision 4; production sanitizer
  logic was not changed for revision 5.
- Production call site under proof:
  `Session.SlackRead` -> `sanitizeSlackResponse` -> URL policy ->
  `redactSlackTokenSpans`.

## Negative mutant evidence

Each mutant was applied separately, tested uncached, and restored before the
green validation.

- Partial-overlap end-extension narrowing mutant: deleted only the branch that
  extends the merged span end. The named production-path test
  `TestSlackReadProductionPathUnionsPartiallyOverlappingSecretSpans` failed with
  exit 1 and exposed the synthetic Bearer tail as
  `REF-SYN-4242 [redacted] abcdefghij tail`.
- URL policy fall-through narrowing mutant: restored the pre-change early
  return after `RedactSensitiveURL`. The named production-path test
  `TestSlackReadProductionPathRedactsTokenInURLPath` failed with exit 1 and
  returned the synthetic URL path token unchanged.

## Green validation

- Focused partial-overlap, URL-path, and exact-ceiling tests: exit 0; 2.176s
  initial run and 1.584s restoration rerun.
- Deterministic differential corpus: exit 0; all 101,326 legacy detections
  preserved across 200,000 cases.
- `go test ./internal/chromectl ./cmd/mac-chrome-session -count=1`: exit 0.
- `go test ./... -count=1`: exit 0 on the counted terminal rerun. An earlier
  invocation whose terminal exit was not retained was explicitly discarded as
  evidence and rerun.
- `go vet ./...`: exit 0.
- `go build ./...`: exit 0.
- `gofmt -l internal/chromectl/slack.go internal/chromectl/slack_test.go
  cmd/mac-chrome-session/main_test.go`: exit 0 with empty output.
- `git diff --check`: exit 0.
- `bash -n scripts/setup.sh`: exit 0.
- `./scripts/setup.sh`: exit 0; current CLI installed and signed.
- Supported signing readiness probe `codesign -d --verbose=2
  bin/mac-chrome-session`: exit 0. The earlier unsupported
  `codesign --version` probe returned exit 2 and was not treated as a gate.
- `codesign --verify --strict bin/mac-chrome-session`: exit 0.

## Installed content-free live smoke

The installed CLI performed one read-only `search.messages` request rooted only
at the authorized synthetic `REF-SYN-4242` reference. The response stayed in
process memory and only the following booleans/counts were printed. No Slack
write, real message/channel/user content, browser authorization material, or
raw response was persisted.

- CLI exit: 0
- Envelope OK: true
- Synthetic reference count: 11
- Redaction marker count: 6
- Raw token-shape count: 0
- Surrounding synthetic reference preserved: true
- Raw token shapes absent: true

## Repository state

The task candidate remains limited to the established five paths:

- `internal/chromectl/slack.go`
- `internal/chromectl/slack_test.go`
- `cmd/mac-chrome-session/main_test.go`
- `README.md`
- `LOGBOOK.md`

No provider method or Slack write behavior changed.
