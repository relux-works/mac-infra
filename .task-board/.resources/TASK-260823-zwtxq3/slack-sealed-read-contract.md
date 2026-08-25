# Sealed Slack Browser Read Contract

## Purpose

Extend the existing exact-target Chrome session runtime with one compiled,
allowlisted Slack Web API read primitive. This is not a relaxation of generic
`run-js`: caller-supplied JavaScript must continue to refuse cookies, browser
storage, authorization data, and tokens.

## Security Boundary

- Accept exact Chrome window ID, tab ID, expected `https://app.slack.com`
  origin, and expected `/client/<workspace-id>` identity.
- Check origin and workspace identity atomically in the same page evaluation
  that locates browser-owned Slack authorization and starts the request.
- Locate the selected workspace's Slack web token only inside a tool-authored
  script. Never return, print, log, persist, or place it in argv or environment.
- Allow only a compiled list of read-only Slack methods. Reject writes and
  unknown methods before browser execution.
- Accept request parameters over bounded stdin JSON; never evaluate a shell or
  caller-supplied JavaScript.
- Perform the request in the same Slack page context so Chrome retains the
  companion cookies/session state.
- Bound deadline, request size, response size, polling, and parsed JSON depth.
- Recursively reject/redact secret-bearing response keys and token-shaped
  values before stdout.
- On missing/changed browser storage schema, fail as capability-unavailable;
  never fall back to exporting credentials.

## Interface

Prefer a stable machine interface shaped like:

```text
mac-chrome-session slack-read \
  --window-id ID --tab-id ID \
  --origin https://app.slack.com \
  --workspace-id T... \
  --request-stdin
```

Stdin contains a versioned envelope with method and args. Stdout contains a
versioned envelope with sanitized Slack response or a stable error kind.

## Verification

- Unit tests prove generic `run-js` still blocks browser storage access.
- Adversarial tests attack writes, unknown methods, origin/workspace drift,
  forged/malformed input, timeouts, oversized output, token-shaped values,
  and secret field names.
- Live smoke is read-only against the user-authorized test workspace
  `T073GL82HJB`: `auth.test`, then `conversations.list` with limit 1. Persist
  only booleans/counts, never channel/user/message content.
- Operation remains silent: no application activation, focus, tab selection,
  UI click, or active-tab fallback.
