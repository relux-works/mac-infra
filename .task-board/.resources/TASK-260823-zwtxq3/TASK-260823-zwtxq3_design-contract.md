# TASK-260823-zwtxq3 — Unified guarded browser session runtime: producer contract

Authoritative implementation contract prepared by the orchestrator run
RUN-260822-8f48e1. Read this before touching code. It records verified platform
facts, the exact live state to preserve, the pinned design, and the evidence the
reviewer will demand.

---

## 1. Why the worktree looks different from the owner's checkout

Producer runs execute in a Story worktree forked from committed `HEAD`
(`85ce82c`, `main` == `origin/main`). The owner's control checkout is
intentionally dirty and holds a partially implemented Chrome draft plus doc
edits that are **not** in `HEAD`. Two patch resources carry them across:

| Resource | Applies | Contents |
|---|---|---|
| `TASK-260823-zwtxq3_untracked-chrome-draft.patch` | `git apply` at repo root | `cmd/mac-chrome-session/{main.go,main_test.go}`, `internal/chromectl/{session.go,session_test.go}`, `agents/skills/mac-infra/references/chrome-session.md` |
| `TASK-260823-zwtxq3_tracked-doc-drafts.patch` | `git apply` at repo root | draft edits to `README.md`, `agents/skills/mac-infra/SKILL.md`, `LOGBOOK.md` |

Both were verified with `git apply --check` against a clean `HEAD` worktree on
2026-08-23. Apply them **first**, commit nothing, then build on top.

The draft compiles, `go vet` is clean, and its own tests pass. Salvage it — do
not rewrite from scratch and do not discard it. Its defects are enumerated in
§5.

Do **not** re-create the owner's `task-board.config.json` edits; those are
board-plane config and are excluded from Change Requests anyway.

---

## 2. Verified platform facts

These were probed read-only, without focusing either browser, on this machine.
They are the reason the contract is shaped the way it is. Do not re-litigate
them; do re-verify if something contradicts them.

### 2.1 Chrome exposes stable window AND tab ids

`osascript -l JavaScript` enumeration returns `window.id()` and `tab.id()` as
stable integers. Exact `(window-id, tab-id)` targeting is available, and
`Application("Google Chrome").execute(tab, {javascript: ...})` runs against that
exact tab with no activation, no window raise, and no tab selection.

### 2.2 Safari tabs have NO id — this is the load-bearing asymmetry

```
$ osascript -e 'tell application "Safari" to return id of tab 1 of window id 105'
execution error: Safari got an error: Can't get id of tab 1 of window id 105. (-1728)
$ osascript -e 'tell application "Safari" to return index of tab 1 of window id 105'
1
```

Safari **windows** have stable ids (verified: 55138, 54601, 105). Safari **tabs**
expose only `index` (positional, mutates when tabs move/close/open) and
`name`/`URL`. `do JavaScript` is addressable at `current tab of window id N` or
`front document`, not at an arbitrary pinned tab.

**Consequence, and it must be documented rather than papered over:** Chrome
targeting is tab-exact; Safari targeting is *window*-exact and *tab*-drifting.
If the user switches tabs inside a pinned Safari window, every later operation
would silently land on a different page. The origin guard is therefore not a
nicety for Safari — it is the only thing standing between the tool and acting on
the wrong page, so it is **mandatory** for every Safari operation that mutates
or heartbeats.

Do not invent a synthetic Safari tab id and do not fake tab pinning by index.
Both would be a forced fit: index is not identity, and a lookalike API that
promises exactness Safari cannot deliver is worse than an honest window-scoped
contract.

### 2.3 Both browsers gate JavaScript behind a manual user preference

- Safari: `Develop -> Allow JavaScript from Apple Events`
- Chrome: `View -> Developer -> Allow JavaScript from Apple Events`

Never toggle these with UI scripting. Detect the refusal and print the exact
menu path, as `safarictl.FormatAutomationError` already does for Safari; give
Chrome the equivalent.

---

## 3. Live state that must survive this task

Two ad hoc monitors are running right now against the owner's authenticated
Chrome session. Both keep real sessions alive. Breaking either loses live
authenticated state that only the user can restore.

### 3.1 FNS heartbeat — launchd, pure heartbeat, IS migratable

| Field | Value |
|---|---|
| launchd label | `com.relux.fns-chrome-heartbeat` (gui/501, pid 60888 at survey time) |
| Submitted by | `launchctl` directly — **no plist in `~/Library/LaunchAgents`** |
| Program | `/Users/alexis/src/casual-talks/.temp/fns-ip-close/chrome-activity-heartbeat` |
| Args | `-window-id 704793720 -tab-id 704793726 -interval 45s -log /Users/alexis/src/casual-talks/.temp/fns-ip-close/chrome-heartbeat.log` |
| Target origin | `https://lkip2.nalog.ru` |
| Behaviour | every 45s dispatches `mousemove`/`pointermove`/`keydown`/`keyup` into the page; refuses when `location.origin` differs; `os.Exit(1)` on osascript error (launchd `KeepAlive` restarts it) |

Its source is `chrome-activity-heartbeat.go` in that same directory. It is a
pure keepalive with an inline origin check — a clean 1:1 functional match for
the new `heartbeat` command. **Migrate it** under the protocol in §7.3.

### 3.2 T-Bank support watcher — shell loop, heartbeat + extraction, NOT fully migratable

A foreground `/bin/zsh -c` loop (pid 73464, tty s007) polling every 30s against
window `704793720`, tab `704793721`, origin `https://tmsg.tbank.ru`. It does two
things: the same synthetic-input keepalive, **and** it scrapes
`conversation-ui-message` elements and prints the count plus the last message
body when the count changes.

The scraping half is the repeated-element extractor that
**TASK-260823-17qhsl** owns and this task explicitly excludes. Replacing only
the keepalive half would silently destroy the user's chat watching.

**Therefore: leave the T-Bank loop running and untouched.** Record in the
migration runbook that its heartbeat half can move to
`mac-chrome-session heartbeat` once TASK-260823-17qhsl provides the extractor,
and say so plainly in the delivery note. This is a deliberate, reasoned scope
boundary, not an omission — do not "fix" it by killing the loop.

### 3.3 Current Chrome topology (survey time — re-enumerate, never hardcode)

```
window 704793649  tab 704793650  chrome://newtab
window 704793720  tab 704793721  https://tmsg.tbank.ru      <- T-Bank watcher target
                  tab 704793722  https://www.tbank.ru
                  tab 704793723  https://business.tbank.ru
                  tab 704793724  https://tmsg.tbank.ru
                  tab 704793725  https://business.tbank.ru
                  tab 704793726  https://lkip2.nalog.ru     <- FNS heartbeat target
```

Safari at survey time: windows 55138 (9 tabs), 54601 (9 tabs), 105 (25 tabs).

Every one of these tabs is user-owned borrowed state. Do not close, reload,
navigate, reorder, or focus any of them.

---

## 4. Pinned design

### 4.1 `internal/browsersession` — one shared core, no cross-driver import

The draft has `chromectl` importing `safarictl` for `GuardJavaScript` and
`RedactSensitiveURL`. That is backwards layering and it is why the two browsers
cannot currently share a contract. Extract a new `internal/browsersession`
package owning:

- `GuardJavaScript` / `ErrSensitiveJavaScript`
- `RedactSensitiveURL`, sensitive query-parameter set
- `SanitizeHeaders`, sensitive header set
- the origin-guard JavaScript wrapper (§4.3)
- heartbeat naming, state, launchd rendering, and lifecycle (§4.5)
- shared `Target`, `PageStatus`, and error/refusal types

`safarictl` and `chromectl` become thin drivers over it. `chromectl` must not
import `safarictl`. Keep exported names in `safarictl` only if something outside
still needs them; otherwise move them and update call sites.

### 4.2 Target descriptors

| Browser | Flags | Semantics |
|---|---|---|
| Chrome | `--window-id` + `--tab-id` (both required) | tab-exact |
| Safari | `--window-id` (required) | window-exact, acts on that window's current tab |

`--origin` is **required** for every Chrome and Safari `heartbeat` operation and
for every Safari `run-js`. It is optional but strongly recommended for Chrome
`run-js`; when omitted, say so in the output so a caller cannot mistake an
unguarded call for a guarded one.

Safari's window-scoped nature must appear in `--help`, the README, and the skill
reference. Do not describe Safari targeting as "exact tab".

### 4.3 The origin guard must be atomic — the draft's is not

`chromectl.RunJavaScript` currently makes **two** osascript round trips: one
reading `location.origin`, then a second one executing the payload. Between them
the tab can navigate or be replaced. That is a time-of-check/time-of-use hole in
exactly the guard the whole contract rests on.

Fold the check into the injected source so check and payload are one page-context
evaluation:

```js
(() => {
  if (location.origin !== <EXPECTED_JSON>) {
    return JSON.stringify({ __guard: "origin-mismatch", origin: location.origin });
  }
  return (() => { /* caller payload */ })();
})()
```

The Go side inspects the decoded `__guard` sentinel and returns a typed
refusal. Use a sentinel a page cannot plausibly forge by accident, and treat an
unparseable or missing response as a refusal, never as a pass. An absent answer
and a failed read are different facts: a failed osascript call is an error, not
"origin matched".

### 4.4 Focus policy

Forbidden everywhere except the one explicit handoff command: `activate`,
`set frontmost`, `set index of window`, `set active tab`, `set visible`,
`bring to front`, `AXRaise`, and any System Events UI scripting. The existing
`safarictl` `open-bg` minimize applies only to a window the agent itself
created; that stays legal.

Visible/handoff is a **separate, explicitly named command** — e.g.
`mac-chrome-session focus --window-id ID --tab-id ID` — never a flag that some
other verb might imply, and never a fallback when silent mode fails.

### 4.5 Named persistent heartbeats

Commands: `heartbeat start | status | stop | list | run` (`run` is the internal
launchd entry point, not documented for human use).

- Name pattern `^[a-z0-9][a-z0-9-]{0,47}$` — the draft already has this; keep it
  and keep its negative test.
- Multiple named heartbeats run concurrently, each pinned to its own exact
  target, each with its own LaunchAgent, state file, and log.
- Label `works.relux.mac-infra-browser-heartbeat.<name>`; state under
  `~/Library/Application Support/mac-infra/browser-session/`. Rename off the
  draft's Chrome-only `mac-infra-chrome-heartbeat` / `chrome-session` spellings —
  Safari joins this namespace.
- State records the browser, so one command surface manages both.
- Minimum interval 15s (draft value; keep).
- `start` runs a live preflight against the real target and refuses to install a
  LaunchAgent if the preflight fails.

**Executable pinning — this is the requirement that makes migration safe.**
A LaunchAgent whose `ProgramArguments[0]` points into a build tree is a time
bomb: the tree is rebuilt, moved, or deleted and the user's session keepalive
dies silently. `heartbeat start` must copy the running executable into a
content-addressed path under the managed state dir
(`.../browser-session/bin/mac-browser-session-<sha256-prefix>`) and point the
LaunchAgent at that copy. Garbage-collect copies no live heartbeat references,
on `stop` and in `deinit`.

Negative test: rendered `ProgramArguments` never contains a path under `.temp/`,
`/tmp`, or `/var/folders`, even when the running executable does.

**Heartbeat payload and logging.** The draft's heartbeat JS returns
`document.title` and the draft logs the whole result string into a persistent
file. Page titles carry account names, case numbers, and counterparty names.
Return and log only `{ok, origin, readyState}` plus a timestamp and an outcome
of `ok | refused | error`. Logs stay `0600`.

**Drift behaviour, fail-closed.** On origin mismatch the heartbeat logs
`refused` with the observed origin and dispatches nothing. It keeps its schedule
so the user can restore the tab, and `status` reports `drifted`. It must never
act on a mismatch and must never silently "re-find" the target.

`status` distinguishes at least: `not-configured`, `configured-not-loaded`,
`running`, `drifted`, `target-missing`, `unavailable`. Report `unknown` rather
than guessing when launchctl cannot be read — a failed read is not a stopped
service.

### 4.6 Secret guard — implement it, and describe it honestly

Extend the blocked-token set beyond the draft's four to at least:
`document.cookie`, `cookiestore`, `localstorage`, `sessionstorage`,
`indexeddb`, `navigator.credentials`, `openDatabase`.

It is a case-insensitive substring blocklist. It is a speed bump against
accident, **not** a sandbox: `window["doc"+"ument"]["coo"+"kie"]` walks straight
through it. Say exactly that in the README and the skill reference. Do not let
the docs imply the tool makes secret exfiltration impossible; the real guarantee
is that the tool never *itself* reads, prints, persists, or transports session
material, and refuses the obvious attempts.

The guard must run on **every** path that can reach page context: `run-js
--script`, `run-js --file`, `snapshot`, `fetch-file`, heartbeat payloads, and
the origin-guard wrapper's inner payload. Prove that from the CLI entry point,
not only from a direct call to the guard function (§6).

Response sanitization stays: `RedactSensitiveURL` on every URL that leaves the
tool, `SanitizeHeaders` on fetch metadata, fragment redaction as the draft's
`redactTabURL` already does.

### 4.7 setup / deinit

- `scripts/setup.sh`: build and install `mac-chrome-session` alongside the other
  binaries, with the same ldflags, symlink, and echo block.
- `scripts/deinit.sh`: **stop and remove every managed heartbeat before removing
  binaries**, then GC the pinned executable copies. Removing the binaries first
  would strand LaunchAgents pointing at deleted executables — launchd would
  respawn-fail them forever.
- Negative test: after deinit no `works.relux.mac-infra-browser-heartbeat.*`
  plist and no pinned copy remains.

### 4.8 Docs

- `README.md`: replace the draft's "Google Chrome Apple Events" low-level tool
  row with a real `mac-chrome-session` row; rewrite the Chrome section from
  "documented low-level workflow, not a guarded CLI" to the shipped CLI; add the
  heartbeat lifecycle and the Safari/Chrome targeting asymmetry.
- `agents/skills/mac-infra/SKILL.md`: Chrome workflow points at the CLI; add
  heartbeat triggers.
- `references/chrome-session.md`: drop the closing "not a guarded CLI"
  paragraph; lead with the CLI; keep the raw AppleScript only as background.
- `references/safari-session.md`: document window-scoped targeting, the
  mandatory origin guard, and heartbeat parity.
- `LOGBOOK.md`: one entry recording the Safari tab-id constraint (§2.2) and the
  TOCTOU fix (§4.3). These are the two non-obvious findings.

---

## 5. Known defects in the draft — fix all of these

1. `chromectl` imports `safarictl` (§4.1).
2. Two-round-trip origin check is TOCTOU-vulnerable (§4.3).
3. Heartbeat leaks `document.title` into a persistent log (§4.5).
4. `LaunchAgent` points at `os.Executable()` wherever it happens to live (§4.5).
5. `StopHeartbeat`/`InspectHeartbeat` fabricate a config via
   `DefaultHeartbeatConfig(name, "x","x","x", ...)` to recover a label. Placeholder
   values standing in for real state will eventually be written somewhere or
   compared against something. Derive the label from the name directly.
6. `RunHeartbeat` writes to `os.Stdout` and relies on launchd redirection; it
   also never re-reads state, so a `stop` racing a tick is unobserved.
7. `heartbeat status` reports only `running`/`stopped`/`unavailable` — no drift,
   no target-missing (§4.5).
8. `runList` swallows `fs.Parse` errors and positional args into a bare
   `return 2` with no message.
9. No `close`/`focus`/handoff command; no Safari support at all.
10. `main_test.go` asserts only usage text and one arg-validation path.

---

## 6. Evidence the reviewer will require

A green suite proves nothing unless something in it would have failed. For every
gate below, the test must fail when the gate is narrowed or admits what it must
reject — not merely when the gate is deleted.

Required negative tests, each driven through the **production entry point**
(`run()` in `cmd/...`, or the driver's public method — name the call site):

| # | Gate | Negative case that must fail closed |
|---|---|---|
| N1 | Secret guard | `run-js --script 'document.cookie'` and the `--file` equivalent both refuse, non-zero exit, nothing executed |
| N2 | Secret guard coverage | each new blocked token refused; a *narrowed* guard (e.g. dropping `indexeddb`) fails the suite |
| N3 | Origin guard | payload against a tab whose origin differs returns a typed refusal and dispatches nothing |
| N4 | Origin guard atomicity | the guard sentinel is present in the *same* injected source as the payload; a two-call implementation fails the test |
| N5 | Origin guard required | Safari `run-js`/`heartbeat` without `--origin` is rejected at parse time |
| N6 | Unreadable response | malformed/empty osascript output is an error, never a silent pass |
| N7 | Focus | no generated AppleScript/JXA in any silent path contains `activate`, `frontmost`, `set index`, `set active tab`, `set visible`, or `System Events`; the handoff command is the only exception |
| N8 | Tab drift (Chrome) | a `--tab-id` no longer present fails with a typed target-missing error, never falling back to the active tab |
| N9 | Tab drift (Safari) | window present but current-tab origin changed → refusal, not action |
| N10 | Heartbeat exec pinning | rendered plist never references `.temp/`, `/tmp`, `/var/folders` |
| N11 | Heartbeat name | traversal and over-long names rejected |
| N12 | Heartbeat interval | sub-15s rejected |
| N13 | Heartbeat log privacy | log lines contain no page title and no page text; file mode is `0600` |
| N14 | Heartbeat drift | mismatched origin logs `refused` and dispatches no synthetic input |
| N15 | deinit | no managed plist or pinned copy survives |
| N16 | URL/header sanitization | sensitive query params, fragments, and headers redacted on every output path |

Unit-testing a helper that production never calls is not evidence. If a gate
cannot be proven, report it as unproven rather than inferring it from a
neighbouring signal.

---

## 7. Live verification protocol

The point of the live smoke is that the mocked suite cannot prove Apple Events
behaviour. Run against the real browsers, on the real authenticated tabs,
without focusing anything and without disturbing §3.

### 7.1 Preserve first

Before any live step, snapshot the current state to task-scoped private files
(`umask 077`): `launchctl list | grep -i relux`, the FNS job's
`launchctl print gui/$(id -u)/com.relux.fns-chrome-heartbeat`, the current
Chrome enumeration, and `ps` for pid 73464. You will need these to prove nothing
was lost and to roll back.

### 7.2 Non-destructive smokes

Re-enumerate targets; never reuse the ids in §3.3 blindly.

1. `list` returns sanitized Chrome tabs; verify redaction on a URL with a query
   and a fragment.
2. Chrome `run-js` bounded read (`document.readyState`, `location.origin`)
   against a real tab with `--origin` — confirm Chrome never comes forward.
3. Chrome `run-js` with a deliberately wrong `--origin` — confirm typed refusal.
4. Chrome `run-js --script 'document.cookie'` — confirm refusal.
5. Safari `run-js` bounded read against a real window with `--origin`; then the
   same with a wrong origin — refusal.
6. Throwaway heartbeat: `heartbeat start --name smoke-<something>` against a
   safe real tab; let it run at least 3 intervals; `heartbeat status` shows
   `running`; the log shows `ok` lines and no page text; the plist points at the
   pinned managed copy. Then `heartbeat stop` and confirm the LaunchAgent, state,
   and pinned copy are gone.
7. Concurrency: two named heartbeats alive simultaneously, both reporting
   `running`, neither focusing a browser — this is the AC's "multiple exact
   sessions alive concurrently".
8. Drift: point a throwaway heartbeat at a target and change the expected origin
   so it mismatches; confirm `refused` in the log and `drifted` in `status`.

Confirm after every step that the FNS job (§3.1) and the T-Bank loop (§3.2) are
still alive.

### 7.3 FNS migration — only after 7.2 fully passes

1. Start `heartbeat start --name fns --browser chrome --window-id <resolved>
   --tab-id <resolved> --origin https://lkip2.nalog.ru --interval 45s`.
2. Let both the new and the old heartbeat run **concurrently** for at least 3
   new-heartbeat intervals. Confirm `ok` outcomes in the new log and that the
   FNS page is still authenticated.
3. Only then `launchctl bootout gui/$(id -u)/com.relux.fns-chrome-heartbeat`.
4. Re-verify the new heartbeat for another 3 intervals after the old one is
   gone, and re-verify the FNS session is still live.
5. Record the exact rollback command — the old binary remains at
   `/Users/alexis/src/casual-talks/.temp/fns-ip-close/chrome-activity-heartbeat`
   and can be re-submitted with the §3.1 arguments.

Do not delete anything under `casual-talks/.temp`. It is another project's
scratch space and the rollback path.

**Do not touch the T-Bank loop (§3.2).**

If the new heartbeat cannot be verified, leave the old FNS job running, report
it, and do not migrate. A migration that loses the user's authenticated FNS
session is a worse outcome than an unmigrated one.

---

## 8. Out of scope

- The repeated-element / marketplace extractor facade — **TASK-260823-17qhsl**.
  Do not build a generic DOM extraction API here.
- Screenshots (needs Screen Recording permission).
- Killing or replacing the T-Bank watcher loop (§3.2).
- Any change under `.task-board/` — board paths are stripped from Change
  Requests; use `task-board` CLI for board state.
- The owner's `task-board.config.json` edits.

## 9. Preserve

Unrelated dirty-checkout changes in the owner's control checkout are not yours.
You are in a worktree; stay there. Do not `git add -A` — it pollutes the Change
Request with checkout artifacts.
