# Authenticated Safari Session

Use `mac-safari-session` for a page already authenticated in the user's Safari
profile. Safari retains cookies, browser storage, authorization headers, and
tokens. The tool must never export or persist that session material.

## Safari Is Window-Exact, Not Tab-Exact

Safari windows expose stable ids, but Safari tabs expose no stable id. A command
can address only the current tab of one exact window. Never invent a Safari tab
id or treat a positional tab index as identity. If the current tab changes, the
mandatory atomic origin guard refuses before any page payload runs.

Enable JavaScript automation manually:

```text
Safari -> Settings -> Advanced -> Show features for web developers
Develop -> Allow JavaScript from Apple Events
```

Verify the preference without focusing Safari:

```bash
mac-safari-session check-js
```

## Background Windows And Guarded Commands

Create a task-owned background window and record the returned id:

```bash
mac-safari-session open-bg "https://example.com/private/page"
```

Run JavaScript only with the exact window id and expected origin:

```bash
mac-safari-session run-js \
  --window-id 12345 \
  --origin https://example.com \
  --script 'document.body.innerText.slice(0, 5000)'

mac-safari-session run-js \
  --window-id 12345 \
  --origin https://example.com \
  --file .temp/mac-safari-session/extract.js \
  --out .temp/mac-safari-session/result.txt
```

There is no front-document fallback. The origin check and payload share one
page-context evaluation, so a tab switch or navigation produces a typed refusal
and dispatches nothing.

Snapshot and authenticated fetch paths enforce the same target/origin contract:

```bash
mac-safari-session snapshot \
  --url "https://example.com/private/page" \
  --origin https://example.com \
  --json .temp/mac-safari-session/page-snapshot.json

mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --origin https://example.com \
  --resource "/api/private/file.pdf" \
  --out documents/raw/file.pdf \
  --meta documents/raw/file.pdf.json
```

With `--url`/`--page`, the tool pins every JavaScript step to the created window
and closes it on success or failure. Without them, supply `--window-id` and
`--origin`. `fetch-file` keeps `credentials: "include"` inside Safari, writes
the body and metadata with `0600`, sanitizes URLs/fragments/headers, and clears
the in-page chunk job.

## Agent-Created Browser Cleanup And Handoff

Treat every window opened by the agent as a task-scoped resource. Close the
exact id after multi-step work:

```bash
mac-safari-session close-window --id 12345
```

Do not close a pre-existing user window because its URL or title happens to
match. `snapshot --url` and `fetch-file --page` already clean up automatically.
If ownership cannot be established, preserve the window and report it.

Silent paths never activate or raise Safari. Visible handoff is a separate
command and the only Safari path allowed to focus a window:

```bash
mac-safari-session focus --window-id 12345
```

Use it only when the user explicitly asks to see or manually interact with the
page.

## Named Heartbeats

Safari exposes the shared Go heartbeat manager directly through
`mac-safari-session`:

```bash
mac-safari-session heartbeat start \
  --name safari-session \
  --window-id 12345 \
  --origin https://example.com \
  --interval 45s \
  --ttl 8h

mac-safari-session heartbeat status --name safari-session
mac-safari-session heartbeat list
mac-safari-session heartbeat restart --name safari-session --ttl 8h
mac-safari-session heartbeat stop --name safari-session
```

The heartbeat is window-scoped and origin-guarded; it never claims exact Safari
tab identity. `start` requires a positive window id, a canonical HTTPS origin,
a validated name, and an interval of at least `15s`; it rejects Safari tab ids.
Start also requires exactly one future `--ttl` or RFC3339 `--deadline`.
The Safari surface lists only Safari heartbeats and refuses to inspect, run, or
stop a Chrome-owned name in the shared namespace. Drift dispatches nothing and
reports `drifted`. State, private logs, LaunchAgent names, stable launcher identity,
concurrency, and deinit cleanup are the same as Chrome heartbeats. Start is
successful only after the background process returns its first bounded outcome;
a failed background preflight is booted out and cleaned up. Setup signs the
shared heartbeat launcher with the stable identifier
`works.relux.mac-infra.browser-session`; direct Safari CLI actions retain
`works.relux.mac-infra.safari-session`. macOS may still request Automation
consent the first time the stable background launcher controls Safari. Leave that prompt to the user
and treat a loaded job with no bounded outcome as `unavailable`.

Probe attempts are bounded independently of the configured interval, and
transient failures receive at most three short attempts. `status` rejects a
stale last-success timestamp as `unavailable` rather than equating a loaded
LaunchAgent with a healthy browser session.

`status`/`list` expose `deadline`, `expired`, and `migrationRequired`. Expiry
removes state/plist/log and boots out without another Safari probe. Legacy
content-addressed or deadline-free state reports `migration-required`; use
`heartbeat restart --name NAME --ttl DURATION` or `--deadline RFC3339` to
preflight the same exact window/origin before replacing it.

## Secret And Evidence Boundary

Every page-context path refuses case-insensitive occurrences of
`document.cookie`, `cookieStore`, `localStorage`, `sessionStorage`, `indexedDB`,
`navigator.credentials`, and `openDatabase`. This substring blocklist prevents
common accidents; it is not a sandbox and constructed property access can
bypass it. Never attempt a bypass. The tool itself does not read, print, persist,
or transport browser session material.

Returned DOM text may still be personal. Keep reads bounded, store raw evidence
only in private task-scoped files, and sanitize it with
`mac-document-sanitize` before agent inspection. Screenshots remain out of scope
because they require Screen Recording permission.

For paginated structured reads, cache-scoped grep, and explicit guarded page
mutations, use the [agent-facing site facade](browser-site-facade.md). Safari
adapters remain exact-window/current-tab and always carry this transport's
mandatory atomic origin guard.
