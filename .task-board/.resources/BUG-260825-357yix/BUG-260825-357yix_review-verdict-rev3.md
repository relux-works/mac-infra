# BUG-260825-357yix — reviewer verdict, CR revision 3

- Reviewer run: RUN-260825-d23b20
- Change Request: `CR-BUG-260825-357yix-3`, revision 3, `repository_delta=present`
- Reviewed delta: `192effdb96a02588a73bf02e2a440c7205d2327d..af2e67d2c365c5fe3d705367db7f63d3d485fdb8`
- Verdict: **changes requested** — routed to `to-dev`

## Verdict summary

The linear-scan rework is correct and its cost bound is real. One narrowing
mutant of the overlap-union branch survives the whole suite while leaking a
Bearer credential tail through the production `Session.SlackRead` response
path. That is a delete-only-mutant gap on a branch the rev3 contract names
explicitly, and `BUG-260825-357yix_rev3-results.md` reports it as covered when
it is not.

## Finding 1 — overlap-union end-extension has no discriminating test (leak on narrowing)

`internal/chromectl/slack.go` `findSlackTokenSpans`:

```go
if span.end > merged[len(merged)-1].end {
    merged[len(merged)-1].end = span.end
}
```

Narrowing mutant (delete only these three lines, keep the `append`/`continue`
disjoint branch, replace the body with `_ = span`):

- `go vet ./...` clean, `go test -count=1 ./internal/chromectl/... ./cmd/mac-chrome-session/...` — **PASS**, zero failures.
- Same mutant, driven through the production path helper `slackReadProductionData` -> `Session.SlackRead` -> `sanitizeSlackResponse` -> `redactSlackTokenSpans`:

| Input string (Slack response value) | Shipped rev3 | Narrowed mutant |
| --- | --- | --- |
| `REF-SYN-4242 aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc-Bearer abcdefghij tail` | `REF-SYN-4242 [redacted] tail` | `REF-SYN-4242 [redacted] abcdefghij tail` |
| `REF-SYN-4242 aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc.Bearer abcdefghij tail` | `REF-SYN-4242 [redacted] tail` | `REF-SYN-4242 [redacted] abcdefghij tail` |
| `REF-SYN-4242 aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc_Bearer abcdefghij tail` | `REF-SYN-4242 [redacted] tail` | `REF-SYN-4242 [redacted] abcdefghij tail` |

Mechanism: the JWT/JWE span consumes the compact token plus its trailing
`-Bearer`/`.Bearer`/`_Bearer` segment and stops at the whitespace, so the
JWT span `[13,58)` and the Bearer span `[52,69)` **partially** overlap — neither
contains the other. Only the end-extension line unions them; without it the
merged span truncates at the JWT end and the Bearer credential bytes survive
into the emitted envelope.

Why the existing test does not catch it — `TestSlackReadProductionPathUnionsOverlappingSecretSpans`
uses `pre Bearer xoxc-12345678-secret post`, where the Slack span `[11,31)` is
fully **contained** in the Bearer span `[4,31)` and shares its end offset. That case
exercises only the `continue`-suppression, never the extension. Deleting the
whole merge loop (`return spans`) fails that test and panics, which is why the
producer's "narrowed to equal starts" mutant looked covered — it is a
delete-shaped mutant, not a narrowing one.

The shipped code is correct today; the branch is simply unproven and will
regress silently.

### Requested rework (small)

Add one named production-path test, e.g.
`TestSlackReadProductionPathUnionsPartiallyOverlappingSecretSpans`, asserting

```
REF-SYN-4242 aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc-Bearer abcdefghij tail
  -> "REF-SYN-4242 [redacted] tail"
```

through `slackReadProductionData` (or an equivalent `Session.SlackRead` driver),
then re-run the narrowing mutant above and record that it now fails by name.
Correct the "Overlap union narrowed to equal starts" bullet in
`BUG-260825-357yix_rev3-results.md`: that mutant deletes the union, it does not
narrow it.

No production-code change is required.

## Everything else verified — passes

### Mutants killed (13 of 14)

Each applied to an isolated copy of the tree under
`.temp/BUG-260825-357yix-review/mutant`; the worktree's
`internal/chromectl/slack.go` was byte-compared against a pristine copy
afterwards and is unmodified.

| # | Mutant | Killed by |
| --- | --- | --- |
| A | drop the JWT class collector | `...PreservesNonSecretBytesAroundEveryTokenSpan`, `...RedactsEveryCompactTokenSegment`, `...LegacyDifferentialCorpus`, `...ArgumentsRejectSecretShapes` |
| B | drop the Bearer class collector | `...BearerClassCannotBeNarrowed`, `...UnionsOverlappingSecretSpans`, CLI `...EmitsVersionedSanitizedEnvelope` |
| C | drop the Slack xox/xapp collector | 8 tests incl. `...RejectsNestedTokenStartBeforeBrowserExecution`, `...AtResponseCeilingMeetsCostBound` |
| D | replace only the first occurrence | `...EveryOccurrenceCannotBeNarrowed`, CLI envelope test |
| E | restore whole-string replacement | 8 production-path tests + CLI envelope test |
| F | drop the JWE tail `(?:\.[A-Za-z0-9_-]+)*` | `...RedactsEveryCompactTokenSegment` |
| G | delete the whole merge loop (`return spans`) | `...UnionsOverlappingSecretSpans`, then panics `slice bounds out of range [31:11]` |
| **H** | **narrow the union: drop the end-extension** | **nothing — see Finding 1** |
| I | narrow Slack left boundary `[^a-z0-9]` -> `[[:space:]]` | 6 tests incl. request-guard and ceiling tests |
| J | narrow JWE tail `*` -> `?` | `...RedactsEveryCompactTokenSegment` |
| L | drop the `xapp-` alternative | 6 tests incl. `...WholeStringRedactionCannotReturn` |
| M | narrow token length `{8,}` -> `{16,}` | 6 tests + CLI envelope test |
| N | drop the span sort | `...UnionsOverlappingSecretSpans` |
| P | span start from `match[0]` instead of the capture group | 8 production-path tests + CLI envelope test |

### Cost bound is real and discriminating

Reconstructed CR revision 2's `internal/chromectl/slack.go` from
`BUG-260825-357yix_change-request_rev2.patch` applied to base
`192effdb`, and ran rev3's test against it:

| Implementation | `TestSlackReadProductionPathAtResponseCeilingMeetsCostBound` |
| --- | ---: |
| rev3 linear scan | PASS, ~0.46s |
| rev2 quadratic rescan | **FAIL**, hit the 3s bound |

Independent worst-case sweep at the exact 262144-byte ceiling (12 hostile
shapes: `9xapp-` spam, dense xoxb/Bearer/JWT, all-dashes, `xox` spam,
single 256 KiB token, long JWE tail, partial-overlap repeats, multibyte)
— every shape 52–69 ms, no superlinear outlier. The cost test is not
cherry-picked to a shape that only rev3 handles cheaply.

### Confidentiality fixpoint fuzz (independent, 400,000 cases)

Invariant: after `redactSlackTokenSpans`, neither the current detector nor the
pre-change legacy detector may still see a token shape in the emitted string.
Alphabet included both token classes, whitespace/tab, JWT segments, `. - _ / = + ~ % : [ ]`,
Cyrillic and emoji.

- current-detector residues: **0**
- legacy-detector residues: **0**

This covers the AC's repeated, adjacent, punctuation/boundary, Unicode, and
nesting cases beyond the fixed table in the CR.

### Contract items 1–3 of `review-rev2-leak-fixes.md`

1. Nested valid start behind an invalid left boundary — verified. `9xapp-xapp-12345678secret` -> `9xapp-[redacted]`; `tag9xoxb-xoxb-12345678secret end` -> `tag9xoxb-[redacted] end`. Request-side guard refuses `invalid-arguments` before `osascript`, proven by `...RejectsNestedTokenStartBeforeBrowserExecution` (mutants C, I, M all kill it). Regex equivalence with rev2's rescan re-derived by hand and corroborated by the 200k differential corpus (101,326 legacy detections all preserved).
2. 5-part JWE — verified; mutants F and J both kill.
3. Overlap union — delete-mutant killed and no panic in the shipped implementation; **narrowing mutant survives** (Finding 1).

### Bounds, guards, and preservation

- Response bounds: `response-too-deep`, `response-too-large`, `response-too-complex`, `response-invalid` (both truncated and trailing-JSON forms) all asserted, plus a `malformed-response-json` case through `Session.SlackRead`.
- URL policy composition reviewed: `RedactSensitiveURL` is applied to the trimmed URL, spliced back at the original offset (offsets computed on the pre-assignment string — correct), then span redaction runs over the result. Sensitive params/fragment still redacted, `keep=ok` preserved. No detection is lost by the reordering — both paths use the same detector, and no token character is percent-encoded by `url.URL.String()`/`Values.Encode()`.
- Structured secret-key replacement preserved and asserted for a composite value (`access_token` object, `api_key` array).
- In-place merge `merged := spans[:0]` aliasing audited: the append index never exceeds the already-copied loop element. Safe.
- No provider method changed; no Slack write path touched.

### Build/lint/suite (rerun by this reviewer, not accepted from the producer)

| Check | Result |
| --- | --- |
| `go vet ./...` | exit 0 |
| `go build ./...` | exit 0 |
| `gofmt -l ./cmd ./internal` | empty |
| `git diff --check` | exit 0 |
| `go test -count=1 ./internal/chromectl/... ./cmd/mac-chrome-session/...` | ok, 10.66s / 2.13s |
| `go test -count=1 ./...` | all 28 packages ok |

### Accepted from attached evidence, not independently reproduced

The installed content-free live smoke (`REF-SYN-4242`, exit 0, synthetic
reference count 11, redaction marker count 6, raw token-shape count 0) is taken
from `BUG-260825-357yix_rev3-results.md`. It needs an authenticated Chrome Slack
session and this review is read-only and must not create Slack traffic, so it
was not rerun. Its shape is consistent with the count-only contract and no raw
response was persisted. Reported as **unverified-by-reviewer**, not as verified.
