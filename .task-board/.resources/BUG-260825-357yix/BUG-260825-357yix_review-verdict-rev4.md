# BUG-260825-357yix — reviewer verdict, CR revision 4

- Run: `RUN-260825-308408` (reviewer)
- Change Request: `CR-BUG-260825-357yix-4` revision 4
- Base `192effdb96a02588a73bf02e2a440c7205d2327d` -> candidate `dcf2e54535de6fd9fc0a95709cfc0b4ecd05c461`
- Worktree verified byte-identical to the candidate tree before review, after every
  mutant, and at verdict time (`git diff dcf2e54 --stat` empty). No repository file changed.

## Verdict: CHANGES REQUESTED

One confirmed finding. Everything the revision 4 contract asked for is done and
independently reproduced; the finding is a coverage gap in the cumulative delta,
not a defect in the shipped sanitizer.

## Finding 1 — the URL branch's token-span fall-through is unproven (surviving narrowing mutant)

`internal/chromectl/slack.go:725-729` is new production behavior in this CR. The
pre-CR code returned early from the URL branch:

```go
return browsersession.RedactSensitiveURL(trimmed), nil
```

The CR replaced that with an in-place splice that then falls through to
`redactSlackTokenSpans(typed)`. That fall-through is load-bearing:
`browsersession.RedactSensitiveURL` redacts sensitive query parameters and
fragments but leaves a token sitting in a **path segment** completely untouched.

Reverting only that branch to the pre-CR early return — mutant `M10` — leaks a raw
Slack token through production `Session.SlackRead`, and **the entire suite stays
green**:

| input | shipped | `M10` mutant |
| --- | --- | --- |
| `https://example.com/p/xoxb-12345678-secret` | `https://example.com/p/[redacted]` | `https://example.com/p/xoxb-12345678-secret` |

Directly confirmed that `browsersession.RedactSensitiveURL(in) == in` for that
input, so the fall-through is the only thing redacting it.

This is the AC's own central invariant — "every secret-shaped span is replaced" —
applied to the string class the AC explicitly names ("URLs"), with no negative test.
The existing `TestSanitizeSlackResponsePreservesURLPolicyAndStructuredSecretKeys`
does not cover it: it asserts `data["url"] == browsersession.RedactSensitiveURL(url)`
for a URL with **no** token span, which is exactly what `M10` still returns. That is
positive-path-only evidence for the branch.

### Rework asked for (test-only, no production change expected)

Add one named production-path test — drive `Session.SlackRead`, not
`sanitizeSlackValue` — over a response string whose value is a URL carrying an
`xox*`/`xapp-`/`Bearer`/JWT span in a component `RedactSensitiveURL` does not touch
(path segment is the proven case). Assert the span is replaced and the safe URL bytes
around it survive. Reverting `internal/chromectl/slack.go:727-728` to
`return browsersession.RedactSensitiveURL(trimmed), nil` must fail that named test.
Cover the leading/trailing-whitespace splice in the same test if convenient
(`"   https://…/xoxb-… "` currently yields `"   https://example.com/p/[redacted]   "`).

## Everything else: verified, no findings

### Revision 4 contract, item by item

| Contract item | Result |
| --- | --- |
| One named `Session.SlackRead` partial-overlap test, second span extends past the first | Present: `TestSlackReadProductionPathUnionsPartiallyOverlappingSecretSpans` (`slack_test.go:352`) |
| Deleting only the merge end-extension branch must fail by exposing the Bearer tail | Reproduced (`M1`): mutant output `REF-SYN-4242 [redacted] abcdefghij tail`, byte-identical to the producer log |
| Production sanitizer logic unchanged in rev4 | Confirmed against the rev3 patch; the rev4 delta is one test + one logbook entry |
| Rerun focused/full tests, vet, diff checks | `go test ./... -count=1` green (28 packages); `go vet ./...` exit 0; `go build ./...` exit 0; worktree pristine |
| Rerun the response-ceiling cost test | Green 3/3 consecutive runs at 1.130s / 1.024s / 1.034s wall against a 3s bound (~3x headroom, not flaky-tight) |
| Correct the rev3 wording that mislabeled the equal-starts union deletion | Done — `BUG-260825-357yix_rev3-results.md` now says it deleted the union |
| No Slack writes; live checks read-only and count-only | Confirmed. Rev4 correctly states it did **not** rerun install/live smoke and explicitly reuses rev3's evidence for the unchanged production artifact — that is honest reporting, not a fabricated re-run |

### Independent mutation attack (12 mutants, full detail in `BUG-260825-357yix_rev4-mutants.log`)

11 of 12 killed by named tests. `M2` (deleting the whole overlap-union block) is
worth calling out: it panics `slice bounds out of range [31:11]` inside
`redactSlackTokenSpans` reached from `Session.SlackRead` — so the union block is
load-bearing against a crash, and the shipped implementation does not panic. The
only survivor is Finding 1.

`M12` lifts the **actual** revision 2 scanner verbatim out of
`BUG-260825-357yix_change-request_rev2.patch` and fails the cost bound
(`exceeded 3s at the 262144-byte response ceiling`). The revision 3 quadratic-cost
claim is therefore true against the real prior code, not against a reconstruction.
My own first attempt at reconstructing a quadratic scanner (`M11`) survived because
the reconstruction was wrong, not because the test is weak — recorded so the next
reader does not repeat it.

### Independent adversarial sweep (detail in `BUG-260825-357yix_rev4-adversarial-sweep.log`)

- 400,000-case fuzz on a reviewer seed and an alphabet independent of the CR's own
  corpus: `legacyHits=55948, narrowings=0, residual=0`. No panic; every
  legacy-detected input is still detected; every legacy-detected input comes back
  modified; no sanitized **output** ever still matches a legacy secret shape.
- ~20 targeted attacks through production `Session.SlackRead`, all fail-closed and
  all valid UTF-8: nested starts after `-`/`_`/`.`, triple-nested `xoxb-`, tokens
  adjacent to Cyrillic and to an emoji (byte-offset spans never split a rune),
  4/5/6-segment JWE, equal-start and partial and chained overlaps, `Bearer\t` and
  `Bearer\n`, token at both string edges, adjacent repeats, uppercase tokens.
- Request-side guard: every nested-start, multibyte-prefixed, JWE and Bearer query
  returned `invalid-arguments` before `osascript` execution.
- Producer numbers spot-checked and reproduced exactly, including the differential
  corpus log line `preserved all 101326 legacy detections across 200000 cases`.

### Fit and scope

Fits the existing fail-closed layering: the span replacer is a separate concern from
structured secret-key replacement, sensitive-URL redaction, depth/node/size bounds,
exact target/origin/workspace guards, and the generic `run-js` storage refusal — all
of which the diff leaves intact. No provider method changed, no Slack write path
touched. `containsTokenShape` now delegates to `findSlackTokenSpans`, so the four
request-side guards (`slack.go:385,441,465,482`) tighten with the response
sanitizer instead of drifting from it. README and LOGBOOK are accurate, including the
deliberate fail-closed over-redaction of compact JWE tails.

## Note, not a finding

`redactSlackTokenSpans` assumes its input spans are sorted and disjoint and will
panic if that invariant is ever broken (`M2` demonstrates the exact panic). The
invariant holds today because `findSlackTokenSpans` is the only producer of spans.
If a fourth secret class or a second caller is added later, that assumption is the
thing to re-check. Not blocking — the shipped code is correct.
