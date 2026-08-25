# Slack Sealed Read Method Contract

Keep version 1 envelope and the existing exact window/tab/origin/workspace guards. Add only these compiled read methods: conversations.info, conversations.history, conversations.replies, users.list, search.messages. Preserve auth.test and conversations.list.

Typed arguments:
- conversations.info: channel (required Slack conversation ID), include_locale, include_num_members.
- conversations.history: channel (required), cursor, limit 1..100, oldest/latest Slack timestamps, inclusive, include_all_metadata.
- conversations.replies: channel and ts required, cursor, limit 1..100, oldest/latest Slack timestamps, inclusive, include_all_metadata.
- users.list: cursor, limit 1..100, include_locale, team_id constrained to the configured workspace when supplied.
- search.messages: query required and bounded, count 1..100, page >=1 with a sane upper bound, cursor bounded, sort allowlisted, sort_dir allowlisted, highlight, team_id constrained to the configured workspace when supplied.

All decoders must reject unknown fields and trailing JSON. Reject oversized strings, malformed IDs/timestamps, and token/JWT/Bearer-shaped arguments before Chrome execution. The page script must continue constructing the Slack token only inside the exact guarded page and must never return, log, persist, or place it in argv/environment. Keep the 16 KiB request, 256 KiB response, deadline, depth/node, recursive secret-key, token-shape, and sensitive-URL bounds. Generic run-js must still reject cookie/localStorage/sessionStorage/authorization access. Live smokes persist only method success booleans/counts; do not persist channel names, users, queries, or message text.