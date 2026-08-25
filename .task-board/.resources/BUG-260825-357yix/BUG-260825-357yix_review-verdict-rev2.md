# BUG-260825-357yix review verdict — CR revision 2 — changes requested

- Change Request: `CR-BUG-260825-357yix-2` revision 2, state `ready`, repository delta `present`
- Base OID `192effdb96a02588a73bf02e2a440c7205d2327d` → candidate tree `6dc7fb6caa79294a2efff53f7b92b959221a7809`
- Reviewer run `RUN-260825-a90ea9`. Reviewed worktree byte-identical to the candidate tree before and after review (`git diff 6dc7fb6c --stat` empty); no repository file modified by this run. All probes ran in disposable copies under `.temp/BUG-260825-357yix/{rev2,rev1,rev2mut,proto}`.

## Verdict

**changes_requested → `to-dev`.**

All three findings from `RUN-260825-2ab20b` are genuinely fixed, and the fixes
are covered by named production-path tests that fail under both delete-only and
narrowing mutants. Confidentiality is clean: across 200 000 random corpus cases
and 81 920 exhaustive neighbour-byte cases there is **zero** shape the
pre-change sanitizer caught and this one admits.

But the fix for finding 1 introduced a **new regression of its own**, in the
exact property the task contract names as must-preserve ("JSON depth/node/size/
**deadline** bounds"): resuming a boundary-rejected search at `start + 1` makes
`redactSlackTokenSpans` **quadratic**, and the cost is driven by untrusted
Slack message bytes. A 200 KB in-bounds response takes **96 seconds** through
production `Session.SlackRead` and blows straight through the caller's 5-second
context deadline. The response bounds no longer bound the work they exist to
bound.

For the record: that `start + 1` resume is precisely what the previous verdict's
"validated remediation" section recommended. The producer implemented the
recommendation faithfully; the recommendation was cost-blind. The finding stands
on its own evidence regardless of who authored it.

## Finding 4 (blocking) — the finding-1 fix is quadratic and defeats the response/deadline bound

`appendSlackTokenSpans` (`internal/chromectl/slack.go:800-815`) restarts a full
regex search at `start + 1` on every boundary rejection. Each restart re-runs a
greedy `[a-z0-9-]{8,}` match that can run to end-of-string, so a string of `n`
rejectable starts costs O(n²). `sanitizeSlackResponse` takes no `context`, so
nothing cancels it.

Production call site: `Session.SlackRead` (`slack.go:164`) → `sanitizeSlackResponse`
(`:656`) → `sanitizeSlackValue` (`:729`) → `redactSlackTokenSpans` (`:751`).

Driven through the real `Session.SlackRead` entry point with the shipped
fake-osascript harness, payload `{"text":"9xapp-9xapp-…"}` — in bounds at every
gate (< 256 KiB, 2 nodes, depth 1):

| Response bytes | Elapsed | 5 s ctx deadline honoured |
| ---: | ---: | --- |
| 16 007 | 1.38 s | yes |
| 64 007 | 10.33 s | **no** |
| 200 009 | **1 m 35.97 s** | **no** |

Direct `redactSlackTokenSpans` scaling — clean 4× per doubling, against base and
against the rev1 candidate at the same 256 KiB production ceiling:

| Input bytes | base `192effdb` | candidate **rev1** | candidate **rev2** |
| ---: | ---: | ---: | ---: |
| 15 996 | 2.0 ms | 3.9 ms | 492 ms |
| 31 998 | 3.9 ms | — | 2.33 s |
| 63 996 | 8.2 ms | 14.5 ms | 9.66 s |
| 262 140 (ceiling) | ~33 ms | **48.8 ms** | **2 m 43.2 s** |

This is new in rev2. rev1 collected spans with one `FindAllStringIndex` pass per
class and was linear.

The trigger is content, not configuration: `search.messages` and
`conversations.history` return message text written by anyone in the workspace,
and a single ~250 KB run of `9xapp-` hangs the CLI for minutes with no
cancellation path.

**The shipped suite cannot see this.** `go test ./internal/chromectl
./cmd/mac-chrome-session -count=1` is green at 2 m 43 s and green at 31 ms. That
is positive-path-only evidence for cost.

## Validated remediation (prototyped in `.temp/BUG-260825-357yix/proto`, not applied)

Put the boundary back inside the pattern and take the **submatch group** span.
Go's leftmost-first RE2 semantics already skip to the later valid start, so this
fixes nested starts *and* stays linear — one pass per class, no rescan:

```go
slackTokenSpanPattern  = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(xox[a-z]-[a-z0-9-]{8,}|xapp-[a-z0-9-]{8,})`)
bearerTokenSpanPattern = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])(bearer[[:space:]]+[a-z0-9._~+/=-]{8,})`)
jwtTokenSpanPattern    = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])([A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}(?:\.[A-Za-z0-9_-]+)*)`)

func appendSlackTokenSpans(spans []slackTokenSpan, value string, pattern *regexp.Regexp) []slackTokenSpan {
	for _, match := range pattern.FindAllStringSubmatchIndex(value, -1) {
		spans = append(spans, slackTokenSpan{start: match[2], end: match[3]})
	}
	return spans
}
```

Greedy `[a-z0-9-]` / `[A-Za-z0-9_-]` already guarantees the right boundary, so
`hasASCIIBoundaries`, `isASCIIAlphaNumeric` and `isJWTCharacter` drop out. Keep
the sort + overlap-union exactly as shipped — it is still needed for cross-class
overlap.

Measured with that prototype:

| Check | rev2 candidate | Prototype |
| --- | ---: | ---: |
| 262 140 B `redactSlackTokenSpans` | 2 m 43.2 s | **30.9 ms** |
| Full shipped suite `./internal/chromectl ./cmd/mac-chrome-session -count=1` | ok | **ok** |
| `TestSlackReadProductionPathRescansAfterRejectedTokenStart` | pass | **pass** |
| `TestSlackReadProductionPathRedactsEveryCompactTokenSegment` | pass | **pass** |
| `TestSlackReadProductionPathUnionsOverlappingSecretSpans` | pass | **pass** |
| 200 000-case guard differential, base-only admits | 0 | **0** |
| 81 920-case neighbour sweep, regressions vs base | 0 | **0** |
| `go vet ./...` | 0 | **0** |

Rework must also ship a **cost bound the suite can fail on** — a production-path
test that sanitizes a hostile in-bounds response under a wall-clock or context
deadline. Without it the next refactor reintroduces this silently, exactly as
this one did.

## Verified-good (reproduced, not taken on report)

- `gofmt -l ./cmd ./internal` empty; `git diff --check` clean; `go vet ./...` exit 0.
- `go test ./... -count=1` exit 0, all 28 packages ok (`.temp/BUG-260825-357yix/rev2-go-test-01.log`).
- **Finding 1 fixed.** Mutant "resume at rejected-match end" (rev1 behaviour) fails
  `TestSlackReadProductionPathRescansAfterRejectedTokenStart` **and**
  `TestSlackReadProductionPathRejectsNestedTokenStartBeforeBrowserExecution` —
  both the response path and the request-side guard are covered.
- **Finding 2 fixed.** Two mutants caught, one delete-only and one *narrowing*:
  removing `(?:\.[A-Za-z0-9_-]+)*` and capping it at `?` (one extra segment) both
  fail `TestSlackReadProductionPathRedactsEveryCompactTokenSegment`.
- **Finding 3 fixed.** Deleting the union loop **and** narrowing it to equal-start
  spans both fail `TestSlackReadProductionPathUnionsOverlappingSecretSpans` with
  `panic: slice bounds out of range [31:11]`. The unmutated implementation does
  not panic on overlapping Bearer + Slack-token spans.
- **Differential guard, 200 000 random cases** over an adversarial alphabet
  (`xox`/`xapp-`/`Bearer`/digits/dots/dashes/Cyrillic/emoji): base 30 210 hits,
  candidate 30 210 hits, **0 base-only**, 0 candidate-only. The rev1 3-string
  gap is closed with no over-tightening.
- **Exhaustive neighbour sweep**, 5 secret shapes × 128 left bytes × 128 right
  bytes = 81 920 cases: 58 112 would have been redacted by the pre-change
  sanitizer, **0 emit the raw secret** now.
- **Post-redaction residue**, 200 000 cases: no output of `redactSlackTokenSpans`
  is still detectable by either the pre-change or the current detector.
- **UTF-8 integrity**, 50 000 cases: no span boundary splits a multi-byte rune.
- URL policy (`keep=ok` survives, `code=secret`/`#private` do not), structured
  secret keys with composite values, depth/node/size/malformed-JSON bounds,
  exact target/origin/workspace guards and generic `run-js` storage refusal are
  unchanged and covered; the new `malformed-response-json`, node-count and
  two-JSON-values cases are real additions.

## Non-blocking notes (fix opportunistically, not gating)

1. **Greedy compact-token tail over-redacts safe trailing words.** Verified:
   `"see abcdefghijkl.mnopqrstuvwx.yzABCDEFGHIJ.Then_we_continue here"` →
   `"see [redacted] here"`. `Then_we_continue` is eaten. Strictly safer than base
   (which returned `[redacted]` for the whole string) and required to kill JWE
   tails, so it is the right trade — but it is a residual tension with the AC
   phrase "preserving every byte outside the matched sensitive span" and belongs
   in the README sentence describing the behaviour.
2. `merged := spans[:0]` aliases the collector's backing array. Correct as
   written, but it is a non-obvious in-place rewrite worth one comment.

## Not re-verified by this run (reported, not confirmed)

The installed content-free live smoke (`./scripts/setup.sh`, `codesign --verify
--strict`, one read-only `search.messages` rooted at synthetic `REF-SYN-4242`,
counts `reference=11 / marker=6 / raw-token-shape=0`) is taken from
`BUG-260825-357yix_rework-results.md` as **reported**. I did not re-run it: it
needs an authenticated live browser session and is outward-facing. Treat it as
**unknown**, not as independent confirmation. It would not have caught finding 4
either — the synthetic root never produces a 200 KB hostile-prefix run.
