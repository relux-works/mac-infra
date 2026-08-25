# BUG-260825-357yix developer revision 4 outcome

## Test-only rework

- Added `TestSlackReadProductionPathUnionsPartiallyOverlappingSecretSpans` in `internal/chromectl/slack_test.go`.
- The test drives `slackReadProductionData` -> `Session.SlackRead` -> `sanitizeSlackResponse` -> `redactSlackTokenSpans` with partially overlapping JWT/Bearer spans whose Bearer span extends past the JWT span.
- Expected output preserves `REF-SYN-4242` and `tail` while replacing the entire union with `[redacted]`.
- Production sanitizer code was not changed. After the mutant attack, `internal/chromectl/slack.go` was restored byte-for-byte from the task-scoped pristine copy (SHA-256 `c457edb54aeeeb12411cf34943d19e5982634be151cb14cd58c824db2d8f8144`).
- Updated the existing `BUG-260825-357yix_rev3-results.md` board resource to state truthfully that its equal-starts overlap mutant deleted the union; it did not narrow the end-extension branch.
- Recorded the evidence gap and regression proof in `LOGBOOK.md`.

## Narrowing-mutant evidence

Mutant: delete only the overlap end-extension branch in `findSlackTokenSpans`:

```go
if span.end > merged[len(merged)-1].end {
    merged[len(merged)-1].end = span.end
}
```

Command: `go test ./internal/chromectl -run '^TestSlackReadProductionPathUnionsPartiallyOverlappingSecretSpans$' -count=1 -v`

- Shipped implementation: exit 0.
- Narrowing mutant: exit 1, expected red.
- Observed leaked mutant output: `REF-SYN-4242 [redacted] abcdefghij tail`.
- Named production-path test therefore detects the Bearer-tail leak while preserving the synthetic surrounding reference.

## Validation rerun by revision 4 developer

- Named partial-overlap production-path test: exit 0.
- Exact response-ceiling cost test: exit 0; production `Session.SlackRead` completed the 256 KiB hostile response case in 0.61s under its 3s bound.
- Deterministic differential corpus: exit 0; all 101,326 legacy detections preserved across 200,000 cases.
- `go test ./internal/chromectl ./cmd/mac-chrome-session -count=1`: exit 0.
- `go test ./... -count=1`: exit 0 on the counted rerun.
- `go vet ./...`: exit 0.
- `go build ./...`: exit 0.
- `gofmt -l ./cmd ./internal`: exit 0 with empty output.
- `git diff --check`: exit 0 after the final logbook edit.
- `task-board validate`: exit 0.
- Worktree measurement base: `192effd`; `git rev-list --count HEAD..main` returned 0.

## Live-smoke boundary

Revision 4 changed tests and evidence only, so installation and authenticated Slack live smoke were not rerun. The already-attached revision 3 evidence is accepted for that unchanged production artifact: installed read-only `REF-SYN-4242` search exit 0, synthetic reference count 11, redaction marker count 6, raw token-shape count 0. No Slack write or real message content was created or persisted in revision 4.

## Repository delta for revision 4

- `internal/chromectl/slack_test.go`: one named production-path regression test.
- `LOGBOOK.md`: one evidence-gap entry.

No provider method, Slack write path, or production sanitizer logic changed.
