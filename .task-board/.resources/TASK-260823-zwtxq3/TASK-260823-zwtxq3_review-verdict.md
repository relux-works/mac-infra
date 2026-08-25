# TASK-260823-zwtxq3 — Review verdict (CR-TASK-260823-zwtxq3-1 rev 1)

Reviewer run: RUN-260825-28e372 (claude)
Reviewed delta: `85ce82c..be2db77`, 39 paths, +9357/-296
Verdict: **changes requested → `to-dev`**

## Summary

The implementation is strong and, in almost every dimension, genuinely proven.
The shared `internal/browsersession` layer removes the backwards
`chromectl -> safarictl` dependency, the origin guard is atomic in one injected
evaluation, focus is confined to two explicitly named handoff commands, the
heartbeat runtime pins a content-addressed managed executable, and `deinit.sh`
is covered by a real subprocess test. Live state on this machine corroborates
it: three named heartbeats run concurrently, one of them correctly reports
`drifted`, and the frontmost application was byte-identical across every probe
I ran.

Two gates, however, are **not pinned by any test that fails when the gate is
narrowed**. Both are on refusal behavior, and one is on the sealed Slack
primitive — the highest-risk surface in the change. That is the Definition of
Done item "negative tests that fail when the gate admits what it must reject",
so the work routes back rather than accepting.

The guards themselves are live-correct. This is a test-evidence gap, not a
live vulnerability. The rework is narrow.

---

## Blocking findings

### F1 — Slack sealed-read origin/workspace guards are unpinned in the start script

`internal/chromectl/slack.go:slackStartPageJavaScript`

Deleting **both** guards from the start evaluation — the one that reads the
workspace `xoxc-` token out of `localConfig_v2` and fires the POST:

```
if (location.origin !== __origin) return __reply("origin-mismatch");
...
if (!(location.pathname === __prefix || location.pathname.startsWith(__prefix + "/"))) return __reply("workspace-mismatch");
```

→ replaced with `if (false) ...` for both →

```
go test -count=1 ./internal/chromectl ./cmd/mac-chrome-session   =>   ok, ok
```

The full suite stays green. Two reasons:

- `TestSlackReadAtomicStartUsesExactTargetWithoutFocusOrSecretArgv`
  (`slack_test.go:48`) substring-matches `location.origin !== __origin` and
  `location.pathname.startsWith` against a capture file that the fake
  `osascript` **appends** to across the start *and* poll calls. The poll script
  still carries both strings, so the assertion passes with the start script
  fully unguarded.
- `TestSlackReadOriginAndWorkspaceDriftFailBeforePolling` (`slack_test.go:100`)
  feeds a fake `osascript` a canned `origin-mismatch` / `workspace-mismatch`
  envelope. It proves the Go side handles a refusal reply; it says nothing
  about whether the page ever performs the check. This is a green suite around
  a fake.

`slack-sealed-read-contract.md` makes this exact placement load-bearing:
"Check origin and workspace identity atomically in the same page evaluation
that locates browser-owned Slack authorization and starts the request."

Note the guard is genuinely present and working in production — I confirmed it
live: `--workspace-id T00000000` against the real Slack tab returned
`workspace-mismatch` with no request started. The defect is that nothing in the
suite would notice if it were removed.

**Fix shape:** capture start and poll sources into separate files (or index
them per call) and assert the start source independently. A mutant that guts
only the start script must fail.

### F2 — The blocked-token set is self-referential, so narrowing it is invisible

`internal/browsersession/session.go:73` (`BlockedJavaScriptTokens`)

| Mutant | Suite result |
| --- | --- |
| drop `"indexeddb"` | killed |
| drop `"navigator.credentials"` | killed |
| drop `"cookiestore"` | **survived** |
| drop `"opendatabase"` | **survived** |

Every consumer — `session_test.go:10`, `main_test.go:160`,
`transport_test.go:53`, `heartbeat_test.go:117` — iterates
`BlockedJavaScriptTokens()` itself, so deleting a token deletes its own test
case. The two that die do so only by accident of hardcoded fixtures
(`main_test.go:129` uses `navigator.credentials.get({})`,
`cmd/mac-safari-session/main_test.go:52` uses `indexedDB.databases()`).

The producer contract §4.6/N2 required exactly the opposite: "each new blocked
token refused; a *narrowed* guard (e.g. dropping `indexeddb`) fails the suite."

**Fix shape:** assert `BlockedJavaScriptTokens()` against a literal expected
set, and drive each token through the CLI entry point from a literal fixture
list rather than from the production list.

---

## Non-blocking observations

- `isSlackSecretKey`'s `strings.HasSuffix(compact, "token")` rule can be removed
  with the suite still green; `containsTokenShape` value redaction backstops it
  in practice. The delivery note's claim that
  `TestSlackReadProductionPathRecursivelyRedactsSecrets` "fails if the recursive
  key/value/URL policy is narrowed" is therefore overstated for the *key* half
  (the value and URL halves are correctly pinned — both mutants died).
- Heartbeat state-file mode can be relaxed from `0600` to `0644` with the suite
  green. The log mode *is* pinned (`TestRunHeartbeatLogsOnlyBoundedOutcomeAndMode0600`).
  State files hold window/tab ids and origins, not secrets.
- The library-level Safari empty-origin refusal in `RunJavaScriptResult` can be
  deleted with the suite green; the CLI parse-time check backstops it and *is*
  pinned. Redundant-guard survivor, low value.

---

## What I verified, and how

### Mutation testing (production source mutated, suite rerun, source restored)

Killed: wrapper origin check removed; empty automation output treated as
success; guard sentinel check removed; URL fragment redaction removed;
LaunchAgent managed-path check narrowed; heartbeat name pattern loosened to
`^.+$`; minimum interval 15s → 1s; log mode 0600 → 0644 (both `OpenFile` and
`Chmod`); Chrome `execute` script gains `activate`; Safari `run-js` script gains
`activate`; Safari front-document fallback reintroduced; Slack allowlist admits
`chat.postMessage` (both switches); Slack token-shape value redaction removed;
Slack URL redaction removed.

Survived: F1, F2, and the three non-blocking items above.

### Live attack (installed CLI = this worktree's `bin/`, signed
`works.relux.mac-infra.browser-session`)

| Probe | Result |
| --- | --- |
| `run-js --script 'document.cookie'` | refused, exit 1, no Apple Events |
| `run-js --origin https://wrong.example` | typed origin refusal, exit 1 |
| `run-js --tab-id 999999999` | typed target-missing, exit 1, **no active-tab fallback** |
| `run-js` correct target + origin | `complete`, exit 0 |
| `slack-read` `chat.postMessage` | `method-not-allowed`, exit 2, pre-browser |
| `slack-read` wrong workspace | `workspace-mismatch`, exit 1, no request started |
| `slack-read` wrong origin | `invalid-origin`, exit 2, pre-browser |
| `slack-read` forged `token` arg | `invalid-arguments`, exit 2 |
| `slack-read` `limit: 9999` | `invalid-arguments`, exit 2 |
| obfuscated `window["doc"+"ument"][...]` | passes the blocklist — **as documented** |

`lsappinfo front` was byte-identical before and after every sequence.
No user tab was closed, navigated, reloaded, or reordered.

The obfuscation bypass is correctly and explicitly documented as a limitation
in `README.md:307`, `chrome-session.md:217`, and `safari-session.md:133`
("speed bump ... not a sandbox"). That honesty is right and I am not flagging it.

### Live runtime state (untouched, observed only)

Three concurrent named heartbeats, all pinned to managed content-addressed
copies under `~/Library/Application Support/mac-infra/browser-session/bin/`,
plists referencing no `.temp/`, `/tmp`, or `/var/folders` path:

| Name | State | Evidence |
| --- | --- | --- |
| `mos-sud-court-session` | `running` | fresh `ok` outcome |
| `tbank-support` | `running` | fresh `ok` outcome |
| `tbank-retail` | `drifted` | logs `refused` with `observedOrigin`, dispatches nothing |

Log lines carry only `{timestamp, outcome, origin, readyState}` at mode `0600` —
no page title, no page text. Drift is fail-closed and live-proven, which is
better evidence than any mock could give.

### Offline gates rerun by me

`go build ./...` 0 · `go vet ./...` 0 · `gofmt -l` empty ·
`go test -count=1 ./...` 0 (all 28 packages).

Working tree returned to the exact candidate state after every mutant;
`git status --short` matches the CR at entry and exit.

---

## Scope note (not a finding)

The CR delta necessarily carries sibling `TASK-260823-17qhsl` files
(`internal/browserfacade`, `internal/browserquery`, `cmd/mac-browser-site`,
`browser-site-facade.md`) because both leaves share the Story worktree. I
checked that the facade does not open a hole in this task's guards: it shells
out to `mac-chrome-session` / `mac-safari-session`, so every page-context call
still funnels through `WrapJavaScript` → `GuardJavaScript`, and
`browserquery.BuildJavaScript` JSON-marshals its whole spec with an attribute
allowlist, so there is no injection path. I did not review that task's own
acceptance criteria.

Grep confirms the only page-context path that bypasses the generic guard is
`chromectl/slack.go`, which is the intended compiled-allowlist exception.

## Preservation

Nothing was modified. All mutations were applied to a backup-and-restore copy
and reverted within the same shell call. No heartbeat was started, stopped, or
reconfigured. No browser was focused.
