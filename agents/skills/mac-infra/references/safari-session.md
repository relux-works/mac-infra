# Authenticated Safari Session

Use this when the user asks to inspect, click, extract, or download from a page
that is already authenticated in their local Safari profile.

Core rule: use Safari as the authenticated browser and do not export, dump, copy,
log, or persist cookies, browser storage, authorization headers, or tokens. Let
Safari make same-origin/authenticated requests. Persist only page content,
downloaded files, sanitized response metadata, endpoint shapes, and notes.

Safari has no real headless mode with the user's live profile. Prefer background
Apple Events to avoid focus churn:

```bash
mac-safari-session open-bg "https://example.com/private/page"
```

`open-bg` prints the exact `window-id`. Close that agent-owned window when the
workflow finishes:

```bash
mac-safari-session close-window --id 12345
```

## Agent-Created Browser Cleanup

Treat every Safari tab or window opened by the agent as a task-scoped resource.
Track it when it is created and close it as soon as the browser work that needs
it is finished. This is mandatory for separate background windows created by
`open-bg`, `snapshot --url`, or `fetch-file --page`, including minimized
windows. Reuse one agent-owned page during a multi-step workflow instead of
leaving a new window behind after each read or download.

- Cleanup runs on success, failure, cancellation, and handoff; do not postpone
  it until a later conversation turn.
- Close only the exact tab or window created by the agent. Never close a
  pre-existing user tab or window merely because its URL or title matches.
- If the tooling cannot distinguish agent-owned browser state from user-owned
  state, do not guess. Preserve the user's browser state and report the leftover.
- Before ending browser work, account for every page the agent opened and
  confirm that no agent-created Safari windows remain.

`snapshot --url` and `fetch-file --page` pin their JavaScript to the exact
background window they create and close that window automatically on success or
failure. Do not add a second manual close for those commands.

Verify JavaScript-from-Apple-Events permission before DOM extraction or fetch:

```bash
mac-safari-session check-js
```

If Safari blocks the command, the user must enable it manually:

```text
Safari -> Settings -> Advanced -> Show features for web developers
Develop -> Allow JavaScript from Apple Events
```

Capture DOM text and links:

```bash
mac-safari-session snapshot \
  --url "https://example.com/private/page" \
  --json .temp/mac-safari-session/page-snapshot.json
```

Run guarded JavaScript:

```bash
mac-safari-session run-js --script 'document.body.innerText.slice(0, 5000)'
mac-safari-session run-js --file .temp/mac-safari-session/extract.js --out .temp/mac-safari-session/result.txt
```

For multi-step work in an agent-created background window, address the exact
`window-id` printed by `open-bg`. Never target a pre-existing user window:

```bash
mac-safari-session run-js --window-id 12345 --script 'document.title'
mac-safari-session close-window --id 12345
```

`run-js` refuses obvious browser-secret reads such as `document.cookie`,
`cookieStore`, `localStorage`, and `sessionStorage`. Do not bypass this with ad
hoc AppleScript. Page status and metadata redact OAuth-style query values.

For authenticated downloads where direct `curl` lacks the Safari session:

```bash
mac-safari-session fetch-file \
  --page "https://example.com/private/page" \
  --resource "/api/private/file.pdf" \
  --out documents/raw/file.pdf \
  --meta documents/raw/file.pdf.json
```

Operational notes:

- `fetch-file` uses `fetch(..., { credentials: "include" })` inside Safari.
- The CLI writes output files with `0600` permissions.
- Response headers are sanitized before metadata is written.
- Screenshots are not included because they require Screen Recording permission.
- Store durable endpoint/selector/limitation notes in the task flow.
