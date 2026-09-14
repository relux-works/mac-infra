# BUG-260915-7elb3o implementation plan

## Objective

Compose the existing `internal/docsanitize` PII redactor with the
`mac-browser-site` facade so successful structured browser reads are safe for
agent consumption without weakening the facade's independent fail-closed secret
boundary.

## Implementation slice

1. Introduce the narrowest reusable structured-record sanitization entry point
   in `internal/docsanitize` if the facade cannot safely reuse the existing text
   API directly.
2. Apply it once to the complete projected list result before cache persistence
   and public rendering, preserving field names, non-PII data, record order, and
   stable placeholders for repeated values.
3. Keep the existing outbound secret decision before any public write and ensure
   rejected/unknown records create neither partial stdout nor cache bytes.
4. Keep `grep` cache-only; prove it can return only already-depersonalized cache
   records.
5. Document the composed PII-plus-secret contract in README, the mac-infra skill
   reference, and LOGBOOK.

## Evidence and negative expectations

- Positive controls retain ordinary IDs, titles, prices, and other non-PII.
- Representative names, emails, phones, addresses, dates of birth, passports,
  SNILS, tax IDs, payment cards, and IP addresses become stable placeholders in
  list stdout and cache.
- Repeated PII values map consistently within one result.
- Secret-shaped values still refuse the whole operation.
- Sanitization or decoding ambiguity fails closed without stdout/cache side
  effects.
- A bounded narrowing mutant that bypasses the production PII call site must make
  the named regression test fail, then source must be restored byte-for-byte.

## Validation

- Focused `internal/docsanitize`, `internal/browserfacade`, and
  `cmd/mac-browser-site` tests.
- Relevant race tests, full `go test ./...`, `go vet ./...`, `go build ./...`,
  `gofmt`/diff checks, and `task-board validate`.
- Independent reviewer checks the immutable Change Request candidate and attacks
  both PII leakage and secret-boundary preservation.
- Accepted candidate is integrated as signed commits and published through a
  GitHub pull request without including unrelated control-root board state.

## Critical path

Implementation and production-path tests -> independent review -> rework if
needed -> accepted integration -> PR/checks/review -> exact-head landing.
