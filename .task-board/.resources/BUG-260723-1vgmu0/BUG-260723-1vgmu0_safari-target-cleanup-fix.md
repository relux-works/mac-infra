# Safari background target and cleanup fix

## Root cause

`OpenBackground` created and minimized the requested Safari document, but later
`Snapshot` and `fetch-file` JavaScript calls addressed `front document`.
Switching Safari windows between those steps caused extraction to run against
an unrelated user page.

## Changes

- `OpenBackground` now stores the exact created Safari window ID.
- Page-context JavaScript targets that exact window and tab.
- `snapshot --url` and `fetch-file --page` close their exact agent-created
  window on success or failure.
- `open-bg` prints `window-id`; `close-window --id` closes that exact window.
- The skill and README document automatic and explicit cleanup.
- Unit coverage checks window-ID decoding, pinned AppleScript generation, and
  the new close command.

## Validation

- `go test ./internal/safarictl ./cmd/mac-safari-session` passed.
- `./setup.sh` passed the complete Go test suite, rebuilt all tools, installed
  the updated CLI, and synced the installed skill.
- Live smoke with HRlink frontmost and HUB 2024 opened in the background
  captured title `Корпоративный портал HUB` and URL
  `https://hub.mts.ru/vacation/my?curYear=2024`.
- A second smoke used the installed CLI for HUB 2023.
- After each capture, no agent-created visible or tabbed Safari window
  remained. Safari may retain an invisible zero-tab AppleScript tombstone for a
  closed window; it has no user-visible window or page content.
- Installed and source `SKILL.md` files are byte-identical.
- `git diff --check` passed.

No files were staged or committed.
