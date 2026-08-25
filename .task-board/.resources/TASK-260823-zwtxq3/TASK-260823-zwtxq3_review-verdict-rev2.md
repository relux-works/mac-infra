# TASK-260823-zwtxq3 — Review verdict (CR-TASK-260823-zwtxq3-2 rev 2)

Reviewer run: RUN-260825-5c241b (claude)
Reviewed delta: `be2db77..9a791b4` (rev1 → rev2), 4 paths, +46/-6
Candidate tree: `9a791b4aa963550017279432503835945b13b724` — verified byte-identical to
this worktree via a throwaway index (`git write-tree` == candidate OID) at entry
**and** at exit.
Verdict: **accepted → `accept_cr`**

Scope followed `rev2-rereview-scope.md`: only the rev1 F1/F2 delta and its
evidence. The rev1 broad 39-path mutation matrix, live heartbeat survey, and
sibling-task acceptance were not repeated; nothing in the rev2 delta invalidates
them (it touches three test files and `LOGBOOK.md`, no production source).

---

## F1 — Slack sealed-read start guards: CLOSED

`internal/chromectl/slack_test.go` now routes the fake `osascript` on
`*localConfig_v2*` and writes the **start** evaluation to its own
`start-source` file (poll goes to `poll-source`), then asserts the start source
alone. It adds an ordering assertion: `location.origin !== __origin` and
`location.pathname.startsWith` must both precede `localStorage.getItem` and
`fetch(`.

I attacked the production start script directly (`slackStartPageJavaScript`,
`internal/chromectl/slack.go:337`), mutating **only** the text above
`func slackPollPageJavaScript` so the poll guards stayed intact — the exact
masking condition that made rev1's assertion vacuous. Named production-path
test: `TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv`, which
drives `Session.SlackRead`.

| Mutant applied to the START evaluation only | Suite |
| --- | --- |
| both guards → `if (false)` | **killed** (`slack_test.go:78`) |
| origin guard alone → `if (false)` | **killed** |
| workspace guard alone → `if (false)` | **killed** |
| both guards moved *below* the `localStorage` secret read, text unchanged | **killed** (`slack_test.go:87`, the ordering assertion) |
| secret read rewritten to `window["local"+"Storage"]` | **killed** |

The rev1 defect — poll source masking a fully unguarded start source — no longer
reproduces. The fourth row is the one that matters most: it proves the new
assertion pins *placement*, not just presence, which is what
`slack-sealed-read-contract.md` ("atomically ... in the same page evaluation that
locates browser-owned Slack authorization and starts the request") actually
requires.

## F2 — Blocked-token contract: CLOSED, and wider than the finding

`internal/browsersession/session_test.go` asserts `BlockedJavaScriptTokens()`
against a literal expected list by exact ordered join, and
`cmd/mac-chrome-session/main_test.go` drives a literal token list through the
production `run()` entry point (`newChromeSession` swapped for a fake
`osascript` that touches a marker file; the test asserts the marker never
appears, so no refused payload reached Apple Events).

I dropped each token from the production list in turn:

| Dropped token | `internal/browsersession` | `cmd/mac-chrome-session` |
| --- | --- | --- |
| `document.cookie` | killed | killed |
| `cookiestore` | **killed** (survived in rev1) | **killed** |
| `localstorage` | killed | killed |
| `sessionstorage` | killed | killed |
| `indexeddb` | killed | killed |
| `navigator.credentials` | killed | killed |
| `opendatabase` | **killed** (survived in rev1) | **killed** |

All seven are now pinned at both the library contract and the production CLI
path. Rev1 killed five by fixture accident; rev2 kills seven by construction.

I also narrowed the matching semantics rather than the list, which the finding
did not ask for:

| Mutant in `GuardJavaScript` | Result |
| --- | --- |
| drop `strings.ToLower` (case-sensitive matching) | **killed** — `cmd/mac-safari-session` fails on its mixed-case `indexedDB.databases()` fixture |
| `strings.Contains` → `lower == needle` (exact match) | **killed** in 4 packages |

## Restore and green validation (rerun by me, not accepted from the note)

The producer's claimed restore hashes reproduce exactly:

- `internal/chromectl/slack.go` — `9d24561bcb72421014eb142fbe74bcba940096b0257d1222f4f0bc1b7d56015f`
- `internal/browsersession/session.go` — `b04be005c4f6d985e9b9748bf9a7bb0425f5588c35f706acf846d253be2492c9`

Every mutant was applied to a backup-and-restore copy and reverted inside the
same shell call. After the last mutant the worktree hashes to the candidate tree
OID again.

| Gate | Result |
| --- | --- |
| `go build ./...` | 0 |
| `go vet ./...` | 0 |
| `gofmt -l cmd internal scripts` | empty |
| `go test -count=1 ./...` (baseline, 28 packages) | 0, no FAIL |
| `go test -count=1` over the 9 browser-session packages after restore | 0 |

The rework note's `gofmt -l .` disclosure checks out: the only listed path is a
gitignored scratch mutant under `.temp/TASK-260823-17qhsl-review4/`, which is
outside production source and absent from the CR's 39 paths. Scoped lint is the
clean gate and it is clean.

## Live state — untouched, observed read-only

I ran no browser command and started/stopped/reconfigured nothing. Confirming
the test runs did not clobber managed state:

| Heartbeat | launchd | Evidence |
| --- | --- | --- |
| `mos-sud-court-session` | pid 16902 | log fresh |
| `tbank-support` | pid 8191 | `{"outcome":"ok","origin":"https://tmsg.tbank.ru","readyState":"complete"}` at 13:09Z |
| `tbank-retail` | pid 27615 | `{"outcome":"refused","origin":"https://id.tbank.ru"}` — drift still fail-closed |

State files `0600`, log lines still carry only timestamp/outcome/origin/readyState
— no page title, no page text. Plists intact.

---

## Non-blocking observations

**New, from this pass.** The guard assertions are substring + ordering, so a
mutant that keeps the condition text and drops its effect survives:
`if (location.origin !== __origin) { void 0; }` (same for the workspace guard)
leaves `./internal/chromectl` green while the start script would read the
`xoxc-` token and fire the request on a drifted page. This is not a live
vulnerability — rev1 live-proved the semantics (`--workspace-id T00000000`
against the real Slack tab returned `workspace-mismatch` with no request
started), and the mutant leaves obviously-dead code rather than resembling an
accidental regression. Cheap hardening if someone touches this file again:
widen the two `want` substrings to the whole statement, i.e.
`if (location.origin !== __origin) return __reply("origin-mismatch")` and
`return __reply("workspace-mismatch")`. Proving in-page *semantics* rather than
structure would need a JS engine in the test harness; that is a dependency I am
not asking for, and I am recording this as structure-pinned + live-proven rather
than claiming semantic proof the suite does not have.

**Carried forward from rev1, still open, still non-blocking** (rev2 was correctly
scoped to F1/F2 and did not touch them): `isSlackSecretKey`'s
`HasSuffix(compact, "token")` rule is redundant-guard-survivable (value and URL
redaction halves are pinned); heartbeat *state*-file mode can be relaxed 0600 →
0644 with the suite green (the *log* mode is pinned; state files hold ids and
origins, not secrets); the library-level Safari empty-origin refusal in
`RunJavaScriptResult` is backstopped by the pinned CLI parse-time check.

## Preservation

Nothing was modified or committed. No browser was focused, no tab touched, no
LaunchAgent or heartbeat altered, no installed binary replaced. Worktree entered
and exited at tree `9a791b4a` with 19 porcelain entries, matching the CR.
