# BUG-260825-357yix review verdict — changes requested

- Change Request: `CR-BUG-260825-357yix-1` revision 1
- Base OID `192effdb96a02588a73bf02e2a440c7205d2327d` → candidate tree `63d59940f295a6503387ca107ee54c769ce9d7ee`
- Reviewed worktree byte-identical to the candidate tree before and after review (`git diff <candidate> --stat` empty; no repository file modified by this run).
- All probes and mutants were executed in a disposable copy at `.temp/BUG-260825-357yix/mutant` and a base-commit copy at `.temp/BUG-260825-357yix/base`.

## Verdict

**changes_requested → `to-dev`.**

The in-place span replacement is the right shape and the safe-text preservation
works for the cases the producer tested. But the rewrite from
"whole-string `[redacted]` when `containsTokenShape` matches" to "replace each
matched span" introduced **two fail-open regressions in the exact secret classes
this bug touches**, both reproducible through the production
`Session.SlackRead` → `sanitizeSlackResponse` → `sanitizeSlackValue` path
(`internal/chromectl/slack.go:164`, `:656`, `:729`). The AC requires the change
to preserve fail-closed browser-secret confinement; it does not.

The decisive evidence is that the shipped suite passes **identically** with and
without a fix for both leaks. It cannot distinguish the leaking sanitizer from
the correct one, so its green is positive-path-only for these classes.

## Verified-good (reproduced, not taken on report)

- `go vet ./...` — exit 0.
- `go test ./... -count=1` — exit 0, all 24 packages ok (`.temp/BUG-260825-357yix/go-test-01.log`).
- `gofmt -l ./cmd ./internal` — empty. `git diff --check` — clean. No golangci/staticcheck config exists in the repo.
- The three producer-claimed narrowing mutants reproduce, each failing a **named** production-path test:
  | Mutant | Failing named tests |
  | --- | --- |
  | Remove Bearer collector | `TestSlackReadProductionPathBearerClassCannotBeNarrowed`, `...PreservesNonSecretBytesAroundEveryTokenSpan`, `TestSlackReadProductionEntryEmitsVersionedSanitizedEnvelope`, `TestSlackReadKnownStringArgumentsRejectSecretShapes/list-cursor` |
  | First-occurrence-only Slack collector | `TestSlackReadProductionPathEveryOccurrenceCannotBeNarrowed`, `...PreservesNonSecretBytesAroundEveryTokenSpan` |
  | Restore whole-string replacement | `TestSlackReadProductionPathWholeStringRedactionCannotReturn` + 4 others |
- Two additional narrowing mutants I added are also caught: removing the JWT
  collector and removing only the `xapp-` alternative both fail named tests.
  Class coverage is genuinely there.
- Structured secret keys, sensitive-URL redaction (`keep=ok` survives,
  `code=secret`/`#private` do not), depth/node/size/malformed bounds, exact
  target/origin/workspace guards and generic `run-js` storage refusal are
  unchanged and covered.
- The URL branch's new `strings.Index(typed, trimmed)` splice is correct:
  `trimmed` cannot occur before the leading-whitespace offset.

## Finding 1 (blocking) — boundary-failed match is dropped without rescanning inside it

`findSlackTokenSpans` (`internal/chromectl/slack.go:771`) takes
`FindAllStringIndex` results and then *discards* any match whose left neighbour
is alphanumeric. `FindAllStringIndex` has already consumed those bytes, so a
**valid token start nested inside the rejected match is never examined**. The
old regexes carried the boundary inside the pattern, so the engine backtracked
to the later, valid start. The new code cannot.

Production `Session.SlackRead` output, same fake-osascript harness the shipped
tests use:

| Input string | base `192effdb` | candidate `63d59940` |
| --- | --- | --- |
| `9xapp-xapp-12345678secret` | `[redacted]` | `9xapp-xapp-12345678secret` |
| `tag9xoxb-xoxb-12345678secret end` | `[redacted]` | `tag9xoxb-xoxb-12345678secret end` |

The full token bytes are emitted raw. This is a secret leak, not a cosmetic
difference.

The same function backs the **request-side** guard `containsTokenShape`
(`slack.go:385` search query, `:441` cursor, `:465` timestamp, `:482` team id),
so the guard also newly *accepts* secret-shaped input. A 20 000-case
differential corpus over base vs. candidate `containsTokenShape` found 467 base
detections vs. 464 candidate detections — three strings the base rejected and
the candidate admits, zero in the other direction:

```
"12345678xapp-xapp-12345678abcdefghijkl+. "
"9)9xapp-xapp-12345678xoxZ"
"bearerxapp-xoxb-Bearerxox-"
```

## Finding 2 (blocking) — JWT-shaped values with more than three segments leak their tail

`jwtTokenSpanPattern` matches exactly three dot-separated segments, so on a
4+-segment compact token (e.g. a 5-part JWE: header.key.iv.ciphertext.tag) the
span ends after segment three and the remaining segments are written out raw.

Production `Session.SlackRead`, key `jwe`:

| | Output |
| --- | --- |
| base `192effdb` | `"[redacted]"` |
| candidate `63d59940` | `"[redacted].dddddddddddd.eeeeeeeeeeee"` |

Same for `prefix aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc.SECRETTAILXXXX suffix`
→ `prefix [redacted].SECRETTAILXXXX suffix`.

## Finding 3 (non-blocking, but fix with the above) — the overlap-union branch has zero coverage

`BUG-260825-357yix_results.md` claims spans are "unioned when overlapping", but
no shipped test produces overlapping spans (`adjacent` uses `|` separators, so
the classes never overlap). Deleting the merge loop from `findSlackTokenSpans`
leaves `go test ./internal/chromectl ./cmd/mac-chrome-session -count=1`
**green**, while `sanitizeSlackResponse` then panics on a real overlap:

```
pre Bearer xoxc-12345678-secret post
panic: runtime error: slice bounds out of range [31:11]
  chromectl.redactSlackTokenSpans  internal/chromectl/slack.go:763
  chromectl.sanitizeSlackValue     internal/chromectl/slack.go:729
  chromectl.sanitizeSlackResponse  internal/chromectl/slack.go:656
```

A claimed, load-bearing, crash-preventing behavior with no test that fails when
it is removed. Add an overlapping-class case (`Bearer ` + an xox token, and
`Bearer ` + a JWT) to the production-path table.

## Validated remediation (prototyped in the disposable copy, not applied)

Both leaks close with a change confined to `findSlackTokenSpans`:

1. Replace the `FindAllStringIndex`-then-filter loops with a scan that, on a
   boundary rejection, resumes at `start + 1` instead of `end`, so nested
   token starts are still found. One shared collector can serve all three
   classes (`leftOnly` for Bearer, which has no right boundary).
2. Extend the JWT span to consume trailing segments:
   `[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}(?:\.[A-Za-z0-9_-]+)*`.

Measured with that prototype in `.temp/BUG-260825-357yix/mutant`:

| Check | Candidate rev1 | Prototype fix |
| --- | ---: | ---: |
| `containsTokenShape` corpus detections vs. base (20 000 cases) | 464 / 467 | 467 / 467 |
| Base-detects-but-misses | 3 | 0 |
| `9xapp-xapp-12345678secret` via `SlackRead` | leaks raw | `9xapp-[redacted]` |
| `tag9xoxb-xoxb-12345678secret end` via `SlackRead` | leaks raw | `tag9xoxb-[redacted] end` |
| 5-segment JWE via `SlackRead` | `[redacted].dddddddddddd.eeeeeeeeeeee` | `[redacted]` |
| `REF-SYN-4242 before xoxc-… after` | preserved | preserved |
| `go test ./internal/chromectl ./cmd/mac-chrome-session -count=1` | ok | ok |

The last row is the point: the shipped suite is green either way. Rework must
add production-path tests that **fail on rev1** — at minimum a token preceded by
an alphanumeric character, a 4+-segment JWT-shaped value, and an overlapping
Bearer+xox / Bearer+JWT string — plus a differential or explicit assertion that
`containsTokenShape` still rejects everything the pre-change guard rejected.

## Not re-verified by this run (reported, not confirmed)

The installed content-free live smoke (`./scripts/setup.sh`, `codesign --verify`,
one read-only `search.messages` rooted at synthetic `REF-SYN-4242`, counts
`reference=11 / marker=6 / raw-token-shape=0`) is taken from
`BUG-260825-357yix_results.md` as reported. I did not re-run it: it needs an
authenticated live browser session and is outward-facing. Treat it as **unknown**
for the purpose of this verdict rather than as independent confirmation — and
note it would not have caught either finding, since both require token bytes the
synthetic root never produces.
