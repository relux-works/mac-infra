# BUG-260825-357yix — reviewer verdict, Change Request revision 5

- Run: `RUN-260825-759ebe` (reviewer archetype)
- Change Request: `CR-BUG-260825-357yix-5`, revision `5`
- Base OID: `192effdb96a02588a73bf02e2a440c7205d2327d`
- Candidate tree OID: `86eb634190f23e4562eadbd5e5690cdc3a09da89`
- Patch sha256 verified: `1b001eaa181ac6d83ffa2a7c05c1ec581e32dd792d1e16e0fc69171e3c44a7d5`
- Worktree left byte-identical to the candidate tree (`git diff 86eb6341 --stat` empty
  at start and at end; all reviewer scratch confined to gitignored
  `.temp/BUG-260825-357yix/rev5/`)

## Verdict: ACCEPTED

Revision 5 is exactly the test-only delta the revision-4 verdict asked for, the
finding it was raised against is now killed by a named production-path test, and
every other guarantee in the contract survived an independent attack pass.

## What revision 5 actually changed

Diffing `BUG-260825-357yix_change-request_rev4.patch` against
`..._rev5.patch` shows a single added hunk — `internal/chromectl/slack_test.go`
gains `TestSlackReadProductionPathRedactsTokenInURLPath` (7 lines, `+236/-10` →
`+243/-10`). `internal/chromectl/slack.go`, `cmd/mac-chrome-session/main_test.go`,
`README.md`, and `LOGBOOK.md` are byte-identical between the two revisions. The
developer's claim "production sanitizer code unchanged from CR revision 4" is
confirmed, not taken on trust.

## The revision-4 finding is closed

Reverting only the URL fall-through (`internal/chromectl/slack.go:725-728`) back
to the pre-CR `return browsersession.RedactSensitiveURL(trimmed), nil`:

```
--- FAIL: TestSlackReadProductionPathRedactsTokenInURLPath (0.42s)
    slack_test.go:362: url = "https://example.com/p/xoxb-12345678-secret"
```

That is the named production-path failure the verdict required. Confirmed
independently in this run, not read from the developer's log.

## Mutant battery — 16 applied, 16 killed

Full table in `BUG-260825-357yix_rev5-mutants.log`. Reviewer-authored test files
are deleted before each mutant run, so every kill is by a test the candidate
ships. Coverage across delete AND narrowing shapes:

| Mutant | Shape | Killed by |
| --- | --- | --- |
| M01 URL fall-through reverted | delete | `…RedactsTokenInURLPath` |
| M02/M03/M04 drop one secret class | delete | request guard + envelope + span tests |
| M05 only first span redacted | narrow | `…EveryOccurrenceCannotBeNarrowed` |
| M06 whole-string redaction restored | widen | `…BearerClassCannotBeNarrowed` + 3 others |
| M07 JWT tail segments removed | narrow | `…RedactsEveryCompactTokenSegment` |
| M08 union end-extension deleted | narrow | `…UnionsPartiallyOverlappingSecretSpans` |
| M09 whole merge loop deleted | delete | `…UnionsOverlappingSecretSpans` |
| M10/M11/M12 min token length 8→24, 12→24 | narrow | request guard + span tests |
| M13 `isSlackSecretKey` drops `*token` suffix | narrow | structured-key + recursive tests |
| M14 URL branch narrowed to `http://` only | narrow | URL-policy + recursive tests |
| M15 `containsTokenShape` always false | bypass | `…KnownStringArgumentsRejectSecretShapes` (all 3 subtests) |
| M16 span start off-by-one (leaks first token byte) | narrow | envelope + 3 span tests |

M08 is the mutant the revision-4 contract was written around; it is killed by the
revision-4 test, and its LOGBOOK references (`slack_test.go:352`,
`slack.go:792`) resolve to the correct lines in the candidate.

## The cost bound is not vacuous

The revision-2 quadratic scanner was lifted verbatim out of
`BUG-260825-357yix_change-request_rev2.patch` (patterns without the encoded left
boundary, plus the `searchStart = start + 1` rescan and the
`hasASCIIBoundaries`/`isASCIIAlphaNumeric`/`isJWTCharacter` post-filters) and
grafted onto the revision-5 tree:

```
slack.go (rev2 scanner):  --- FAIL: …AtResponseCeilingMeetsCostBound (3.00s)
                              production SlackRead exceeded 3s at the 262144-byte response ceiling
slack.go (rev5 shipped):  ok  1.716s / 1.627s / 1.540s  (3 uncached runs)
```

Decomposing the shipped margin: `redactSlackTokenSpans` at the 256 KiB ceiling
costs 26–35 ms across six hostile shapes (xapp-prefix, dot-dense, bearer-dense,
all-dashes, xoxb-dense, benign), and full `Session.SlackRead` costs 970 ms at the
ceiling versus 957 ms for a 16-byte response. The scanner contributes ~13 ms of
the 3 s budget.

## Independent attack pass (not the developer's evidence)

40-case hostile battery driven through production `Session.SlackRead`, full log
in `BUG-260825-357yix_rev5-adversarial-sweep.log`. Every case was checked for
*residue* — whether the pre-CR detector still finds a token shape in the
sanitized output. **0 residues in 40/40 cases.** Selected results:

| Attack | Output |
| --- | --- |
| uppercase / mixed case `XOXB-…` | `[redacted]` |
| Cyrillic and emoji boundaries | `Ж[redacted]Ж`, `🔐[redacted]🔐` |
| RTL-override / bidi wrapper | `‮[redacted]‬` |
| `Bearer` with tab, LF, CRLF, lowercase | `pre [redacted] post` |
| 3-, 5-segment and 11-segment compact tokens | `pre [redacted] post` |
| three repeats, three adjacent classes | every span replaced |
| nested + double-nested rejected starts | `9xapp-[redacted]`, `9xapp-9xapp-[redacted]` |
| partial overlap (JWT tail + Bearer) | `REF-SYN-4242 [redacted] tail` |
| URL query / fragment / path / leading-space / uppercase scheme / mid-sentence | token replaced, `keep=ok` preserved |
| `[redacted]` marker injection around a real token | `[redacted] [redacted] [redacted]` |

Two fuzz passes with reviewer-chosen seeds, independent of the developer's:

- **Fixpoint fuzz**, 400 000 random compositions over 29 token/boundary
  fragments: `containsTokenShape(redactSlackTokenSpans(s))` residues = **0**.
  No secret-shaped span survives one sanitization pass.
- **Detection-parity fuzz**, 400 000 cases, 179 093 legacy detections: the
  current `containsTokenShape` narrowed on **0** of them. The request-side
  fail-closed guard (`slack.go:385`, `:441`, `:465`, `:482` — four production
  call sites, all reachable before `osascript`) never admits a shape the base
  detector rejected.

## Contract items verified

- Secret-shaped substrings replaced in place with a fixed `[redacted]` marker;
  no digest, prefix, or length-preserving derivation of the secret is emitted.
- Structured secret-key replacement (M13), sensitive-URL redaction (M14, M01),
  depth/node/size/deadline bounds, exact target/origin/workspace guards, and the
  generic `run-js` storage refusal are untouched by the diff and still covered.
- No provider method changed; no Slack write path touched. Diff is confined to
  the five declared paths.
- `go test ./... -count=1`: **exit 0**, 24 packages
  (`BUG-260825-357yix_rev5-full-tests.log`).
- `go vet ./...`: exit 0. `gofmt -l`: empty.
  `git diff --check 192effdb 86eb6341`: clean.

## Non-blocking observations (do not gate acceptance)

1. **JSON object *keys* are never sanitized.** Through production
   `Session.SlackRead`, `{"xoxb-12345678-secret":"v"}` comes back with the key
   verbatim, and a nested `{"Bearer abcdefghijkl":"v"}` likewise —
   `sanitizeSlackValue`'s `map[string]any` branch recurses on values only. This
   is **not a regression**: the base sanitizer at `192effdb` had the identical
   map branch (the CR contains no hunk there), and the bug's scope is response
   *string* span replacement. It deserves its own tracked item rather than being
   folded into this CR.
2. **Cost-bound headroom is real but modest in wall-clock terms.** The 3 s bound
   sits over a fixed ~957 ms fake-osascript floor, so a ~3x slower machine could
   flake the test for reasons unrelated to the scanner. Its discriminating power
   is nonetheless proven (rev2 blows past 3 s with ~100x the scanner cost).
3. **LOGBOOK stops at entry 1823 (the revision-4 partial-overlap finding).** The
   revision-5 URL-policy coverage gap — a real reviewer finding — has no entry.
   Cosmetic.

## Explicitly not verified

The developer's **installed content-free live smoke** (CLI exit 0, synthetic
reference count 11, redaction marker count 6, raw token-shape count 0) requires
an authenticated live Chrome Slack session and was **not** reproduced in this
run. It is reported as unknown, not as confirmed. It is also not load-bearing for
this verdict: neither the revision-4 finding nor any of the 16 mutants would have
been caught by it. Note also that `BUG-260825-357yix_rev5-url-path-test.md` says
"No browser or Slack write was performed" while
`BUG-260825-357yix_rev5-developer-results.md` reports an installed live smoke;
the two artifacts are most likely describing different scopes, but the wording is
ambiguous and the smoke remains unreproduced either way.

## Handoff

Accepted via `accept_cr(BUG-260825-357yix, revision=5, …)`, which parks the
element at `to-review`. This reviewer run supplies **no** `commit_ack`. The
commit-owning mover (Orchestrator) commits the scope and makes the `done`
transition with `commit_ack=scope_committed`.
