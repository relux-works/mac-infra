# BUG-260915-7elb3o: depersonalize-browser-facade-records

## Description
Integrate the existing document PII sanitizer into mac-browser-site so structured browser records are depersonalized automatically before public rendering and cache persistence, while preserving the existing fail-closed secret boundary.

## Scope
Apply PII depersonalization to mac-browser-site list records before cache persistence and public rendering; grep must consume only depersonalized cache records. Reuse internal/docsanitize rather than duplicating patterns. Preserve exact-target browser behavior, query semantics, field names, non-PII values, and the independent secret refusal boundary. Update tests, README, mac-infra skill reference, and LOGBOOK.

## Acceptance Criteria
Representative full names, email addresses, phone numbers, addresses, birth dates, passport/SNILS/tax identifiers, payment cards, and IP addresses never appear raw in successful list stdout or facade cache. Repeated values receive stable placeholders within one result. Non-PII values remain unchanged. Secret-shaped values still refuse the complete read with no partial stdout or cache write. Malformed or unsafely sanitizable records fail closed. Focused and full Go validation pass, documentation describes the automatic boundary, an independent reviewer accepts the exact candidate, and the reviewed signed head is published and landed through the repository PR workflow.
