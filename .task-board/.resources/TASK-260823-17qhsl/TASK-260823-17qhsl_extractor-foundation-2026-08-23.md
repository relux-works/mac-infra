# Deterministic Browser Extractor Foundation — 2026-08-23

## Implemented primitive

- JSON extraction templates define one repeated-item selector, projected field
  definitions, an optional capped open-shadow-root traversal, and a per-field
  character limit.
- Query arguments provide field projection, one deterministic predicate
  (`equals`, `contains`, or `prefix`), and bounded `skip`/`take` pagination.
- `take` is capped at 100, text at 4,000 characters per field, shadow roots at
  64, and elements inspected per root at 10,000.
- Attribute sources are allowlisted to non-URL metadata. Cookies, storage,
  credentials, URL-bearing attributes, and authorization material remain out of
  scope.
- `mac-chrome-session extract` reuses the exact window/tab and atomic origin
  guard. Output is JSON and browser focus remains unchanged.

## Live proof

The extractor traversed the T-Business component tree and returned 28 bounded
chat-message records. Raw output stayed in a private task-scoped directory and
was sanitized before inspection. The extracted support answer established the
USD ledger/available-balance distinction without exporting browser session
material.

## Remaining facade scope

The broader agent-facing `q`/`grep`/`m` layer, batching, cached scoped search,
site adapters, and output/token measurements remain open under this task. The
implemented extractor is the pure page-context primitive beneath that facade.

## Validation

- `go test -count=1 ./...`: exit 0.
- `go vet ./...`: exit 0.
- `git diff --check`: exit 0.
- `scripts/setup.sh`: exit 0; signed CLI and skill installed.
