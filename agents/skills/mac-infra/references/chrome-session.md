# Authenticated Google Chrome Session

Use `mac-chrome-session` when a task needs a page already authenticated in the
user's Chrome profile or requires Chrome-specific extensions, signing software,
or behavior. Chrome retains the authenticated session. Never export cookies,
browser storage, authorization headers, access tokens, or refresh tokens.

## Enable Apple Events JavaScript

The user must manually enable:

```text
View -> Developer -> Allow JavaScript from Apple Events
```

If the CLI reports that JavaScript through Apple Events is disabled, ask the
user to enable that exact item. Never toggle it through UI scripting.

## Resolve And Guard The Exact Tab

Chrome exposes stable window and tab ids. Enumerate sanitized metadata without
activating Chrome, then pin every operation to both ids:

```bash
mac-chrome-session list

mac-chrome-session run-js \
  --window-id 123456 \
  --tab-id 123457 \
  --origin https://example.com \
  --script 'JSON.stringify({origin:location.origin,readyState:document.readyState})'
```

The origin check and caller payload are injected in the same page-context
evaluation. A missing tab returns `target-missing`; an origin mismatch is a
typed refusal and executes no payload. Never fall back to the active tab or tab
position. Chrome permits omission of `--origin` only for exceptional bounded
reads and prints `guard: unguarded`; treat that output as unguarded evidence.

`--file` is equivalent to `--script` and goes through the same guard:

```bash
mac-chrome-session run-js \
  --window-id 123456 \
  --tab-id 123457 \
  --origin https://example.com \
  --file .temp/browser/read.js \
  --out .temp/browser/result.txt
```

Optional `--out PATH` works with both `--script` and `--file`. The command
preflights a private temporary file in the destination directory before browser
dispatch, then atomically publishes the result with mode `0600`. Stdout reports
only `out: PATH`, never the page content. A missing value, blank or invalid
path, preflight failure, or publish failure returns nonzero without falling back
to stdout.

## Sealed Authenticated File Downloads

Use `fetch-file` when two or more protected same-origin resources must be saved
without focusing Chrome or entering its native multiple-download flow:

```bash
printf '%s' '{"version":1,"resource":"/api/private/document.pdf","maxBytes":26214400,"timeoutMs":90000}' \
  | mac-chrome-session fetch-file \
      --window-id 123456 \
      --tab-id 123457 \
      --origin https://example.com \
      --out .temp/BUG-000000-example/document.pdf \
      --request-stdin
```

The protected resource never appears in `mac-chrome-session` argv. It is carried
only by the bounded versioned stdin envelope above, because a command line is
durable agent session and tool evidence and an interactive shell may also write
it to history. There is no `--resource` flag; supplying one is refused. Prefer a
here-string or a process substitution over an intermediate file, and never write
the envelope to a shell history-visible literal you would not want retained.

The envelope accepts exactly `version` (must be `1`), `resource`, and the
optional `maxBytes` and `timeoutMs` bounds. It must be a single JSON object of
at most 8192 bytes with a resource of at most 4096 bytes; unknown fields,
trailing JSON, and out-of-range bounds are refused before any browser call, and
no refusal echoes the envelope back.

The command pins every start, poll, and chunk read to the supplied IDs and
origin. The resource must resolve to that canonical HTTPS origin; credentials,
fragments, cross-origin URLs, redirects, target loss, and origin drift are
refused. The tool-authored fetch uses browser-owned same-origin credentials but
never reads or returns cookies, authorization headers, or browser storage. Its
resource URL travels to Apple Events over private stdin and is never printed or
stored in response metadata.

All `fetch-file` failures share one owned diagnostic boundary. Whatever fails —
the invocation, the stdin envelope, same-origin validation, the output
preflight, the transfer, or the atomic publish — the command collapses it to a
single closed internal type holding one enum code and no error, path, origin, or
child text, and prints it through one emitter. Failure output is always exactly
one line:

```text
fetch-file: browser target origin changed
```

Exit status is `2` for a refused invocation or an unverifiable request envelope
and `1` for every other failure. The messages are a fixed vocabulary: invocation
refused, request could not be verified, request refused, target no longer
available, target origin changed, transport unavailable, transport failed,
response could not be verified, another sealed fetch already running, size
limit, timeout, non-success HTTP status, redirect refused, page-context fetch
failed, output could not be prepared, output could not be published, and a
catch-all safe failure. Anything unrecognized becomes the catch-all rather than
being rendered.

Do not parse a cause out of that line; there is none by design. Lower layers
still classify precisely — the sealed transport discards both child streams and
produces a Go-chosen kind, the JXA program reports target loss through a
sentinel-sealed `window-missing` / `tab-missing` envelope rather than throwing,
and a forged nested `origin-mismatch` envelope has its child-supplied `origin`
dropped at the transport — but those values only select a code and never reach
output. In Go, `errors.Is` still matches `browsersession.ErrTargetMissing` and
`ErrOriginMismatch`, while `errors.As` to the detail-bearing error types fails.
Expect no page source, URL, query name, query value, output path, or filesystem
text in any `fetch-file` failure output, whatever the child returns.

`timeoutMs` is compared against 300000 in integer milliseconds before it is
converted to a duration, so a value whose nanosecond conversion would wrap back
into range is refused as a bad request rather than silently executed.

The response is streamed under the requested byte/deadline bounds and checked
again before publication. Only numeric HTTP status, byte count, and a validated
media type leave page context. `--out` is preflighted before browser execution,
written through a same-directory private temporary file, and atomically renamed
with mode `0600`. Any refusal leaves an existing destination unchanged. The
maximum accepted bounds are 100 MiB and five minutes. Repeat the command with
the same exact target, a fresh stdin envelope, and a different explicit output
path for sequential files.

For repeated page elements, use the deterministic extractor instead of an ad
hoc DOM text dump. A template owns the item selector, optional capped open
shadow-root traversal, field selectors, allowlisted sources, and per-field text
limit; command arguments own projection, predicates, and pagination:

```bash
mac-chrome-session extract \
  --window-id 123456 \
  --tab-id 123457 \
  --origin https://example.com \
  --template .temp/browser/items.json \
  --fields author,text \
  --where-field text \
  --where-op contains \
  --where-value pending \
  --skip 0 \
  --take 20
```

`take` is capped at 100 and `maxFieldChars` at 4000. Attribute extraction is
restricted to non-URL metadata (`aria-label`, `class`, `datetime`, `role`, and
`title`). Store personal output privately and sanitize it before inspection.

## Promote A Cross-Origin Embedded App To A Top-Level Target

An authenticated host page may embed the useful application in a cross-origin
iframe. JavaScript running in the host page cannot inspect that iframe, but
this is not automatically a dead end. First check whether the embedded app can
bootstrap as a top-level page in the same authenticated Chrome profile.

- Inspect only bounded iframe metadata from the host: visibility, origin,
  pathname, and known non-secret configuration query keys.
- Never print, persist, or forward the complete iframe URL when its query or
  fragment may contain a session code, token, signed payload, or opaque state.
  Reconstruct a bootstrap URL from an allowlisted origin, pathname, and
  explicitly understood non-secret parameters. Drop fragments and unknown
  query keys.
- Use a user-designated disposable tab for promotion. Do not navigate the
  authenticated host tab away merely to simplify extraction. Keep the browser
  in the background and pin the disposable tab by exact window/tab ids.
- Navigate the disposable tab to the sanitized bootstrap URL, then poll a
  bounded app-specific readiness marker. `document.readyState == "complete"`
  is insufficient for a client-rendered app; wait for its list items, input,
  or another stable DOM contract.
- Once ready, use the promoted tab's new origin as the mandatory atomic guard.
  Select the intended entity deterministically, then use `extract` or a bounded
  `run-js` read. The top-level app now has a same-origin DOM without exporting
  the profile's cookies or other browser secrets.

Example readiness probe after a disposable tab has been promoted:

```bash
mac-chrome-session run-js \
  --window-id 123456 \
  --tab-id 123457 \
  --origin https://embedded.example \
  --script 'JSON.stringify({ready:document.readyState,items:document.querySelectorAll("app-list-item").length})'
```

If the top-level app does not authenticate, requires a secret-bearing URL, or
depends on parent-only `postMessage` state, stop. Do not copy session material,
weaken the origin guard, scrape browser storage, or use UI scripting as a
same-origin bypass. Ask for a visible handoff or use an approved site API.

## Silent And Visible Modes

Silent operation is the default. `list`, `run-js`, `fetch-file`, `extract`,
`slack-read`, heartbeat commands, and `close` contain no application activation,
window raise, or active-tab selection. Treat user tabs as borrowed state: do not close,
reload, navigate, reorder, or focus them unless the user explicitly requests it.

Visible handoff is a separate explicitly authorized command:

```bash
mac-chrome-session focus \
  --window-id 123456 \
  --tab-id 123457 \
  --origin https://example.com \
  --human-authorized
```

It re-enumerates fresh Chrome arrays rather than dereferencing the filtered tab
proxy whose stale `index` operation can fail with Apple Events `-1728` after
cross-origin navigation. The exact IDs and origin are checked before selection;
that exact Chrome window is moved to index 1 and Chrome is activated; then the
same window must be frontmost and the same tab/origin must verify again. Window
titles are not identity, and there is no fallback to whichever window/tab was
already frontmost.

Use it only when the user asks to see or manually interact with the page. For a
CAPTCHA, passkey, OTP, signing prompt, or permission dialog, stay in silent mode
and tell the user what must be handled unless they explicitly ask for the
handoff. A file picker may instead use the bounded `upload` contract below when
the user explicitly authorizes attaching the declared local files.

## Explicit Trusted Text And Autocomplete Selection

`trusted-input` is one of the two other Chrome paths allowed to focus a tab. Use it
only when the user explicitly authorizes visible text entry and optional named
autocomplete selection on one exact target:

```bash
printf '%s\n' \
  '{"version":1,"inputSelector":"input[type=search]","text":"non-secret test text","optionSelector":"[role=option]","optionText":"Named option","timeoutMs":5000}' |
  mac-chrome-session trusted-input \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://example.com \
    --human-authorized \
    --request-stdin
```

The command first performs the exact focus contract above. It admits one visible
editable `text`/`search` input, temporarily gives that DOM node an unguessable
Accessibility description, focuses that exact native element, sets the bounded
value and caret semantically, then posts only a fixed
non-secret append/Backspace pair while Chrome is active, the exact window is
the unique native main window, and the nonce element stays focused. The nonce
correlates the native element to the exact tab without title matching. It
accepts success only after a
trusted DOM `input` event with an exact value match. When `optionSelector` and `optionText` are both
present, it admits at most 20 visible options, requires one normalized exact
text match, presses the nonce-marked native option, and requires a trusted click
plus the selected input value. Any malformed evidence, ambiguity, target/origin
drift, timeout, or untrusted event refuses. Temporary labels/listeners are
restored on exit.

The JSON request is capped at 8192 bytes; selectors at 512 bytes; input text at
512 characters/2048 bytes; option text at 256 characters/1024 bytes; and timeout
at 10 seconds. Values stay in bounded stdin, process memory, page context, and
the native call. They do not enter argv, stdout, stderr, or normal logs. Output
contains only version, guarded origin, and boolean `ok`/`typed`/`selected`
attestation.

All explicit visible commands require Chrome's JavaScript-from-Apple-Events
setting. `trusted-input` and `upload` additionally require Accessibility access for the
installed signed executable. If macOS reports `accessibility-not-authorized`,
let the user grant the executable access in System Settings -> Privacy &
Security -> Accessibility. Never click or toggle that consent with UI scripting.

## Explicit Native File Upload

`upload` is the third and only other Chrome path allowed to focus a tab. Use it
only when the user explicitly authorizes attaching the declared files to one
visible file input on the exact target:

```bash
printf '%s\n' \
  '{"version":1,"inputSelector":"input[type=file]","paths":["/private/task/evidence.pdf","/private/task/order.doc"],"allowedExtensions":[".pdf",".doc"],"maxFileBytes":33554432,"maxTotalBytes":67108864,"timeoutMs":15000}' |
  mac-chrome-session upload \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://example.com \
    --human-authorized \
    --request-stdin
```

The single JSON request is capped at 32 KiB and closed to unknown fields or
trailing JSON. It admits one through eight clean absolute paths, requires a
non-empty explicit dot-extension allowlist, rejects symlinks, non-regular
files, hidden filenames, duplicate basenames, changed sources, and paths or
names containing controls. Caller byte ceilings are mandatory and cannot
exceed the fixed 32 MiB per-file and 64 MiB total bounds. Timeout is 1 through
30 seconds. Keep the request on private stdin; paths never belong in argv,
stdout, stderr, or a reusable adapter.

Before native interaction, the command atomically rechecks the exact window,
tab, and origin, requires one visible enabled `input[type=file]`, requires
`multiple` for more than one file, and refuses to overwrite a non-empty input.
If the input declares `accept`, the value is capped at 512 characters and 32
unique comma-separated tokens. The supported forms are dot extensions of at
most 16 characters, exact MIME types, and `image/*`, `audio/*`, or `video/*`;
every staged filename must match a token through its name or fixed known MIME
mapping. Unsupported forms, MIME evidence the tool cannot establish, and
mismatches refuse before focus. Effective visibility walks at most 64 element
ancestors, rejects hidden/ARIA-hidden, collapsed, zero-opacity, non-default
filter or mask, non-displayed, or non-targetable ancestry, and requires the
exact input to win a bounded viewport hit test. The command binds this decision
to the nonce-bearing input and reruns the same type, enabled, visibility,
hit-test, `multiple`, and `accept` gates immediately before native interaction
and again before success attestation. It then gives that DOM node an unguessable
temporary Accessibility description and copies only the validated bytes to a
private mode-`0700` staging directory whose entries are mode `0600`. After
exact-target focus, the Accessibility bridge requires Chrome's unique native
main window to have a successfully read zero-sheet state, presses only the
unique nonce element, and binds the resulting one chooser sheet by exact AX
identity through navigation, selection, and the final close wait. Only a
successfully read empty sheet array is retryable while waiting for the chooser
to appear, and only the retained chooser is retryable while waiting for it to
close; an AX read error, null value, wrong type, ambiguity, or replacement is a
terminal refusal. It uses the standard Go-to-folder
keyboard contract to enter the otherwise-empty staging directory and selects
all entries. It uses no screen coordinates, `System
Events`, active-tab fallback, cookie/storage reads, or DevTools remote-debugging
profile.

Success is not inferred from closing the chooser. The page must emit a trusted
`change` event, and `input.files` must match every intended basename, size, and
count exactly. Any target/origin/focus drift, selector ambiguity, hidden input,
unsupported or mismatched DOM acceptance, chooser ambiguity, untrusted event,
metadata mismatch, or timeout refuses and cleans the nonce/listener and staging
directory. Output contains only version, guarded origin, accepted basenames,
and count; file bytes and absolute paths never leave the private request/native
boundary. The command requires Accessibility permission for the installed
signed executable and intentionally brings Chrome forward, so do not use it as
a silent-mode primitive.

## Sealed Slack Reads

Use `slack-read` for the compiled Slack Web API reads `auth.test`,
`conversations.list`, `conversations.info`, `conversations.history`,
`conversations.replies`, `users.list`, and `search.messages`. Do not weaken
`run-js`: caller JavaScript still cannot read cookies, storage, authorization
data, or tokens.

```bash
printf '%s\n' '{"version":1,"method":"auth.test","args":{}}' |
  mac-chrome-session slack-read \
    --window-id 123456 \
    --tab-id 123457 \
    --origin https://app.slack.com \
    --workspace-id T0123456789 \
    --request-stdin
```

The command atomically verifies `https://app.slack.com` and the selected
`/client/<workspace-id>` path before its tool-authored script locates that
workspace's supported `localConfig_v2` web token and starts the request. The
token stays inside Slack page context: it is never returned, printed, logged,
persisted, or placed in argv/environment. Missing storage schema returns
`capability-unavailable`; never add a credential-export fallback.

Input, deadline, polling, response bytes, JSON depth, arguments, and methods are
bounded. Writes and unknown methods fail before browser execution. Response
keys and values are recursively checked for secrets, but ordinary channel/user
data can still be present. Project live-smoke evidence to booleans/counts and do
not persist channel, user, or message content unless explicitly required in a
private artifact.

Typed argument contract:

- `conversations.info` requires a Slack conversation `channel` and optionally
  accepts `include_locale` and `include_num_members`.
- `conversations.history` requires `channel` and optionally accepts a cursor,
  `limit` 1..100, Slack `oldest`/`latest` timestamps, `inclusive`, and
  `include_all_metadata`.
- `conversations.replies` has the history arguments and additionally requires
  a Slack message `ts`.
- `users.list` optionally accepts a cursor, `limit` 1..100, `include_locale`,
  and `team_id`; a supplied team must equal the guarded workspace.
- `search.messages` requires a query of at most 512 bytes and optionally accepts
  `count` 1..100, `page` 1..1000, a bounded cursor, `sort` (`score` or
  `timestamp`), `sort_dir` (`asc` or `desc`), `highlight`, and a matching
  `team_id`.

All argument objects reject unknown fields and trailing JSON. Malformed or
oversized ids, timestamps, cursors, and queries, plus token/JWT/Bearer-shaped
values, fail before browser execution. `auth.test` and `conversations.list`
retain their version-1 behavior.

## Named Heartbeats

The shared heartbeat lifecycle supports Chrome exact tabs and Safari exact
windows. Chrome example:

```bash
mac-chrome-session heartbeat start \
  --name account-session \
  --browser chrome \
  --window-id 123456 \
  --tab-id 123457 \
  --origin https://example.com \
  --interval 45s \
  --ttl 8h

mac-chrome-session heartbeat status --name account-session
mac-chrome-session heartbeat list
mac-chrome-session heartbeat restart --name account-session --ttl 8h
mac-chrome-session heartbeat stop --name account-session
```

Names match `[a-z0-9][a-z0-9-]{0,47}`, intervals are at least `15s`, and start
requires exactly one future `--ttl` or RFC3339 `--deadline`.
`start` performs a live guarded preflight before creating a LaunchAgent, then
requires a successful bounded outcome from that background process. A failed
background preflight is booted out and cleaned up rather than reported as a
successful start. Each name receives independent state and a private log under
`~/Library/Application Support/mac-infra/browser-session/`; LaunchAgents use
`works.relux.mac-infra-browser-heartbeat.<name>`. Every Chrome and Safari job
runs the same signed installed executable at
`~/Library/Application Support/mac-infra/browser-session/bin/mac-browser-heartbeat-launcher`.
Setup atomically replaces that path across rebuilds, so build-directory cleanup
cannot break a heartbeat and ordinary rebuilds do not create another background
activity identity. Multiple names may run concurrently without focusing Chrome.

Setup gives the heartbeat host a complete ad-hoc signature and the identifier
`works.relux.mac-infra.browser-session`; do not launch a raw linker-signed build
whose TCC identity cannot be retained. macOS may request Automation consent the
first time a new managed executable runs in the background. Let the user
approve or deny that system prompt; never click it with UI scripting or focus
Chrome to work around it. A loaded job with no bounded outcome reports
`unavailable`, not `running`.

`status` and `list` expose `deadline`, `expired`, and `migrationRequired`. At
expiry the runtime removes its state, plist, and private log before self-bootout
without dispatching another browser event. Existing content-addressed or
deadline-free state reports `migration-required`; migrate it with `heartbeat
restart --name NAME --ttl DURATION` or `--deadline RFC3339`. Restart preflights
the preserved exact target before stopping the legacy job.

Each scheduled check uses at most three 10-second attempts with short bounded
delays. The timeout is independent of the heartbeat interval, so a `20m`
schedule cannot leave one Apple Events call blocked for 20 minutes. `status`
also checks the timestamp of the last successful outcome; an expired success
reports `unavailable` with `errorKind: stale-outcome` instead of treating a
loaded process or an old log line as proof of health.

On drift the heartbeat dispatches nothing, logs `refused` without page text,
keeps its schedule, and reports `drifted` so the user can restore the target.
It never searches for a replacement tab. Logs contain only timestamp, outcome,
origin, and ready state—never title, account name, case number, or body text.

## Secret And Evidence Boundary

Every page-context path refuses case-insensitive occurrences of
`document.cookie`, `cookieStore`, `localStorage`, `sessionStorage`, `indexedDB`,
`navigator.credentials`, and `openDatabase`. This substring blocklist is a
speed bump against accidental reads, not a sandbox; constructed property names
can bypass it. Do not attempt a bypass. The enforceable tool contract is that it
does not itself read, print, persist, or transport browser session material.

URLs leaving the tool are redacted by structure, not by parameter name. Every
URL emitted by `list`, extraction metadata, and sealed reads keeps only scheme,
host (including a nonstandard port) and path; the whole query string collapses
to `?[redacted-query]`, the fragment to `#[redacted]`, and user info is dropped.
Payload-carrying opaque URLs (`data:`, `javascript:`, `view-source:`, `mailto:`)
become `[redacted-opaque-url]`. This is deliberate: an authenticated site names
its document, session and sticky identifiers whatever it likes, so a
parameter-name denylist cannot fail closed, and the identifier is as often the
parameter name as the value. Consequence for callers: you cannot recover a
download URL from `list` output. Read the link from page context and hand it to
`fetch-file --request-stdin` in the same turn, where it stays out of argv and
out of stdout. Keep page results bounded. Apple Events output can still contain personal page content,
so write raw evidence only to a task-scoped private file (`umask 077`), sanitize
it with `mac-document-sanitize`, and inspect only the returned sanitized path.

For paginated structured reads, cache-scoped grep, and explicit guarded page
mutations, use the [agent-facing site facade](browser-site-facade.md). It calls
this bounded extractor as its Chrome page-context primitive; do not reproduce
extraction with ad hoc unbounded DOM dumps.
