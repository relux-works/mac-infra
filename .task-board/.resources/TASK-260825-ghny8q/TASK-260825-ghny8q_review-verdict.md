# TASK-260825-ghny8q Review Verdict — ACCEPTED

Change Request `CR-TASK-260825-ghny8q-1` revision 1, base `e3605f6`, candidate tree `279f111`.
Working tree verified byte-identical to the candidate tree (`git diff 279f111 --stat` empty, no untracked
files), branch `task-board/story/STORY-260615-3izx6l` is 0 commits behind `main`, so all evidence below was
gathered at exactly the reviewed revision and is current with trunk. All review probes lived in `/tmp`;
the reviewed checkout was never modified.

## Verdict

Accepted. The compiled allowlist grows by exactly the five contracted reads, every added argument is
decoded by a closed typed decoder, and every gate in the delta was attacked — not read — at the named
production call site `run -> runSlackRead -> chromectl.Session.SlackRead`.

## Gate Attack: Narrowing Mutants

Mutants were applied to a scratch copy (`/tmp/ghny8q-mutant`), each restored afterwards. Narrowing
mutants, not delete-only ones, except where the gate has no meaningful narrower form.

| # | Mutant (narrowing / widening the gate, not deleting it) | Result | Killed by |
| --- | --- | --- | --- |
| M1 | pagination bound `limit > 100` widened to `> 1000` | KILLED | `TestSlackReadTypedArgumentBounds.../history-limit-large`, `/users-limit-large`, **production entry** `TestSlackReadProductionEntry.../out-of-range-pagination` |
| M2 | `addSlackTeamID` workspace-equality clause removed, pattern/length kept | KILLED | `/search-cross-workspace-team`, `/users-cross-workspace-team`, **production entry** `/cross-workspace-team` |
| M3 | `conversationIDPattern` loosened to `^[A-Za-z0-9]+$` | KILLED | conversation-id cases |
| M4 | `slackTimestampPattern` loosened to `^.*$` | KILLED | timestamp cases |
| M5 | `decodeSlackArguments` drops `DisallowUnknownFields` | KILLED | 5 decoder subtests + **production entry** `/unknown-argument` |
| M6 | cursor bound widened to 4096 and token-shape check dropped | KILLED | `/history-oversized-cursor`, `TestSlackReadKnownStringArgumentsRejectSecretShapes/{list,history}-cursor` |
| M7 | `addSlackEnum` accepts any value | KILLED | `/search-sort`, `/search-sort-dir` |
| M8 | `search.messages` query drops `containsTokenShape` | KILLED | `/search-query` + **production entry** `/secret-shaped-argument` |
| M9 | `validate()` allowlist widened to admit `chat.postMessage` | survived | equivalent mutant — see below |
| M10 | `arguments()` switch widened to admit `chat.postMessage` | survived | equivalent mutant — see below |
| M11 | `conversations.replies` `ts` made optional | KILLED | `/replies-missing-ts` |
| M12 | `search.messages` page ceiling widened 1000 -> 1e9 | KILLED | `/search-page-large` |
| M13 | **both** allowlist switches widened together (true admission) | KILLED | `Decode.../write` and **production entry** `.../write` |

M9 and M10 are equivalent mutants, not a coverage hole: the method allowlist is enforced twice
(`SlackReadRequest.validate` and the `arguments()` switch), so widening either one alone still admits
nothing. M13 proves that the moment a write method is genuinely admissible, the production-entry test
goes red. That is the correct property — the gate is doubled and the test kills the real admission.

The production-entry suite additionally asserts a filesystem marker: a fake `osascript` that `touch`es a
marker is never invoked for any refused payload, so every refusal above is proven to happen *before*
browser execution, not merely to return the right error string.

## Gate Attack: Adversarial Payloads At The Production Entry

31 hand-built bypass payloads driven through `run()` with the marker `osascript`. Every one was refused
(`code != 0`), and the marker was touched only by the three payloads that are *legitimately valid* under
the contract (`oldest:""` omitted-optional, a query containing literal `&token=`, `sort_dir:null`
omitted-optional) — those correctly proceed to the exact-target guard. No payload was admitted.

Attempted and refused: case-variant method (`Auth.Test`), path-traversal method
(`auth.test/../chat.postMessage`), percent-encoded method (`chat%2EpostMessage`), trailing-space method,
`args` as string / as array, duplicate JSON keys (`"channel"` twice, last-wins `../evil`), `__proto__`
key, `limit` as string / float / negative / int64-overflow, lowercase `team_id`, prefix-extended
`team_id` (`T073GL82HJBXXXX`), empty `team_id`, `channel` with trailing newline, lowercase `channel`,
`channel: null`, negative and exponent timestamps, `version` as string, `version: 2`, a second envelope
appended after a valid one, nested-object cursor, mixed-case enum, empty required `ts`, `xoxc-`-shaped
query, JWT-shaped cursor.

## Secret Confinement — Verified On The Generated Artifact

Captured the exact JXA the binary writes to `osascript` stdin for a fully-populated `search.messages`
request. Confirmed on the composed production artifact, not on its pieces:

- Arguments reach the page as one JSON object whose keys are the hardcoded allowlist only; the caller's
  `&token=` text is `&`-escaped in JSON and then percent-encoded by `URLSearchParams.set`, so no
  extra POST parameter can be injected.
- `__body.set("token", __token)` is set from `localStorage` **inside** the guarded page; no decoder in
  any method exposes a `token` field, so the argument loop that runs after it cannot override the token.
- The token appears in the transferred script only as the in-page shape regex `/^xoxc-.../`. No token
  value is in argv, environment, the start reply, or the poll reply (`__job.response` only).
- Origin and workspace-path guards precede the storage read in both start and poll scripts; no
  `activate`/focus call anywhere in the generated JXA.

## Installed-Artifact Validation (non-destructive; no reinstall)

Driven against `/Users/alexis/.local/bin/mac-chrome-session` as shipped.

- Ten refusal probes — `chat.postMessage`, `admin.users.list`, unknown `token` arg, `limit:101`,
  `channel:"general"`, `ts:"yesterday"`, `Bearer`-shaped query, cross-workspace `team_id`, `page:1001`,
  `sort:"channel"` — all returned `ok:false` with `method-not-allowed`/`invalid-arguments`.
- Three valid new-method requests against a nonexistent window returned `target-missing`, proving they
  passed validation and reached the exact-target guard rather than being refused for the wrong reason.
- Generic `run-js` storage guards unchanged: `document.cookie`, `localStorage`, `sessionStorage`,
  `indexedDB` all still blocked by literal token.

## Independent Content-Free Live Smoke

Run by the reviewer through the installed binary against the authorized workspace `T073GL82HJB`, exact
window/tab, no focus, no Slack writes. Only booleans and counts persisted — no channel names, user data,
queries, message text, or authorization material.

| Method | transport ok | Slack `ok` | count |
| --- | --- | --- | ---: |
| `auth.test` | true | true | 1 |
| `conversations.list` | true | true | 3 |
| `conversations.info` | true | true | 1 |
| `conversations.history` | true | true | 3 |
| `conversations.replies` | true | true | 3 |
| `users.list` | true | true | 2 |
| `search.messages` | true | true | 0 |

`search.messages` returned a genuine `ok:true` with zero matches for the probe term (inner Slack `ok`
inspected explicitly, not inferred from the transport envelope). A deliberately bogus `ts` on
`conversations.replies` returned Slack `thread_not_found`, confirming the round trip is real.

## Suite, Build, Lint

`go test ./...` green (full module). `go test -count=1 ./internal/chromectl/... ./cmd/mac-chrome-session/...`
green uncached. `go vet ./...` clean. `gofmt -l internal cmd` empty. `go build ./cmd/mac-chrome-session`
succeeds.

## Contract Conformance

Every clause of `slack-read-method-contract.md` is met: five added methods and no more; `auth.test` and
`conversations.list` unchanged; every typed argument present with the contracted bound; all decoders
reject unknown fields and trailing JSON; oversized strings, malformed ids/timestamps and
token/JWT/Bearer shapes refused before Chrome; the 16 KiB / 256 KiB / deadline / depth / node /
secret-key / token-shape / sensitive-URL bounds untouched; `run-js` storage refusal intact. README and
`agents/skills/mac-infra/references/chrome-session.md` describe the shipped bounds exactly — the
boundary values they document (`page` 1000, query 512 bytes, `limit` 100) were probed and accept.

## Non-Blocking Observations

1. `SlackRead` calls `validate()` (which internally builds the argument map) and then `arguments()`
   again, so argument construction runs twice per request. No correctness impact; a cleanup opportunity.
2. The `team_id == workspace` constraint is enforced in `SlackRead` only — `DecodeSlackReadRequest`
   validates with an empty workspace. Safe today because the single production consumer chains both
   calls and refuses before `osascript` (proven by the marker test), but a future caller that used the
   decoder alone would lose that check.
3. Generic `run-js` does not block a bare `fetch("/api/...")`. Pre-existing behavior outside this delta,
   and harmless because a generic caller cannot obtain the token — noted only so it is not mistaken for
   a regression introduced here.

None of these blocks acceptance.
