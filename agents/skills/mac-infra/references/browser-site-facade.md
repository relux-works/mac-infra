# Agent-Facing Browser Site Facade

Use `mac-browser-site` for token-efficient structured access to repeated items
in an already authenticated Chrome or Safari page. It is a facade over
`mac-chrome-session` and `mac-safari-session`, not a replacement transport.
Browser cookies, storage, authorization headers, credentials, tokens, and
opaque session state remain inside the browser.

## Adapter Contract

Keep adapter files private and task-scoped. A Chrome marketplace adapter:

```json
{
  "name": "marketplace",
  "browser": "chrome",
  "target": {
    "windowId": "123456",
    "tabId": "123457",
    "origin": "https://market.example"
  },
  "template": {
    "itemSelector": "marketplace-card",
    "pierceShadowRoots": true,
    "maxFieldChars": 2000,
    "fields": {
      "id": {"selector": ".name", "source": "attribute", "attribute": "aria-label"},
      "title": {"selector": ".name", "source": "text"},
      "price": {"selector": ".price", "source": "text"}
    }
  },
  "pagination": {
    "kind": "next-page",
    "selector": "button.next",
    "maxPages": 5,
    "settleMilliseconds": 250
  },
  "mutations": {
    "install": {
      "description": "Install the selected marketplace item",
      "selector": "button.install",
      "destructive": false
    }
  }
}
```

For Safari, set `browser` to `safari` and omit `tabId`; Safari remains
exact-window/current-tab with the same mandatory atomic origin guard. The
origin must be exactly `http(s)://host[:port]`: credentials, paths, queries,
and fragments are refused. Templates retain the deterministic extractor
contract: allowlisted field sources, one optional predicate, `skip`/`take`,
bounded shadow traversal, and field-length caps.

Pagination kinds are explicit:

- `none`: `maxPages` must be `1` and no selector is accepted.
- `next-page`: click one declared next-page selector between bounded reads.
- `cursor`: click one declared site control. The site's page-owned handler
  retains its cursor; the facade never reads, serializes, caches, or places the
  cursor in a URL.
- `infinite-scroll`: scroll the declared container, or the document when
  `containerSelector` is empty, then repeat the deterministic extraction.

Every adapter declares `maxPages` from 1 through 20. Every query may narrow but
cannot widen it. Result `take` is at most 100 and one query scans at most 1,000
records. Duplicate records and unchanged pages stop repeated output; when the
facade cannot prove exhaustion it reports `hasMore: "unknown"`, not a guessed
false value. Specifically, observed records beyond the requested window prove
`true`; a complete `none` page or explicit `advanced:false` proves `false`;
duplicate/stale pages, caller or adapter page bounds, and the global scan bound
remain `unknown`. Partial or malformed extractor/advance envelopes are typed
failures and never become false exhaustion.

## Structured Reads (`q`)

```bash
mac-browser-site q --adapter .temp/browser/marketplace.json --format compact \
  'schema()'

mac-browser-site q --adapter .temp/browser/marketplace.json --format compact \
  'list(skip=0,take=20,max_pages=3) { id title price }'

mac-browser-site q --adapter .temp/browser/marketplace.json --format json \
  'list(where_field=title,where_op=contains,where_value=lamp) { id title }; schema()'
```

`schema()` exposes operations, public fields, mutation safety metadata,
formats, and pagination limits without exposing selectors, exact browser
targets, origins, or transport state. Semicolon-separated batches are parsed
without shell evaluation. Compact list output is CSV-style with one header,
followed by bounded metadata.

## Cache-Scoped Search (`grep`)

Successful `list` results are written as projected, sanitized `0600` JSONL
under:

```text
~/Library/Application Support/mac-infra/browser-site-cache/<adapter-name>/
```

Search never invokes a browser and never accepts a filesystem root:

```bash
mac-browser-site grep --adapter .temp/browser/marketplace.json \
  --format compact --file query-0123456789abcdef.jsonl -i -C 1 'lamp'
```

`--file` accepts one cache basename. Cache access is physically anchored with a
descriptor-rooted site directory; every facade-owned path component is checked
before opening that root, and symlinked components are refused. An explicitly
named final symlink returns `CACHE_SCOPE_REFUSED`; it is not skipped into an
empty result. Files are capped at 4 MiB / 1,000 records, context at 5 lines, and
matches at 100. A malformed or unsanitized cache is a refusal, not an empty
search result.

## Guarded Mutations (`m`)

Mutation names and selectors must be declared in the adapter. Preview first:

```bash
mac-browser-site m --adapter .temp/browser/marketplace.json --format compact \
  --dry-run 'invoke(name=install)'
```

Apply only with explicit authorization:

```bash
mac-browser-site m --adapter .temp/browser/marketplace.json --format compact \
  --confirm 'invoke(name=install)'
```

All statements are validated before the first click, so an unknown later
mutation cannot produce a partial batch. Every mutation requires `--confirm`,
including entries marked non-destructive. The facade reports browser-side
post-click verification as `unknown`; it does not invent success evidence from
a click dispatch. `--dry-run` never opens page context.

## Secret Boundary

One canonical outbound scanner and one normalized decision type own every
schema/list/cache/grep/error and compact/JSON rendering surface. Decisions are
`clean`, `redacted`, `refused`, or `unknown`; refused and unknown decisions
retain no inspected value. Adapter public fields and browser records refuse
cookie, storage, credential, authorization, token, and session-state names.
Authorization-shaped values, JWTs, and recognized opaque credential families,
including GitHub, GitLab, `sk-proj-*`, `sk-*`, and Stripe-style `sk_*` forms,
refuse the complete read before cache write. The scanner fail-closes known
secret shapes, and ambiguous long opaque credential candidates become
`unknown`; it does not claim that every arbitrary string can be semantically
identified as a token. One normalized sensitive-name policy serves fields,
JSON keys, assignments, and URL query names, including cookie, local/session
storage, session id/state, authorization, credential, key, and token families.
Adapter JSON and mutation descriptions pass the same duplicate-aware scalar
boundary before lossy decoding or `schema()` rendering.

HTTP(S) schemes, hosts, decoded query names, and query values are parsed
case-insensitively. The decoded hostname and every bounded-decoded path
component pass the same normalized name policy and recognized/opaque credential
scanner before release. User info, fragments, and every duplicate value for
sensitive keys such as `api_key`, `signature`, and credential/key/token variants
are redacted. A secret-bearing query name or nested/repeatedly encoded
secret-bearing URL is refused. A bounded normalization work queue covers literal,
percent-encoded, nested, JSON-escaped, backslash-escaped, and case-varied forms,
then rescans transformed output to a fixed point. Malformed URLs, malformed
JSON-shaped output, and duplicate or normalization-equivalent JSON object keys
fail closed as an explicit unknown or refusal rather than passing.
Extractor items, pagination advance evidence, and mutation evidence are checked
before lossy decoding. Cache write and read both revalidate; grep renders a
canonical encoding of the validated record and never returns the original
JSONL source bytes. Every browser transport failure is replaced with a generic
typed failure; raw stdout/stderr is discarded from public errors even when it
appears clean. Never attempt constructed JavaScript
access around the underlying browser-session token blocklist.
