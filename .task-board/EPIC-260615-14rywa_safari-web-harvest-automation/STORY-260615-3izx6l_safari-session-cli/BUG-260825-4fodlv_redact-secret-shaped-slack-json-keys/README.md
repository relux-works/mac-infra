# BUG-260825-4fodlv: redact-secret-shaped-slack-json-keys

## Description
Ensure the sealed Slack response sanitizer never returns secret-shaped JSON object keys, which currently remain unchanged even though scalar values are span-redacted.

## Scope
Future internal/chromectl response-map key sanitization with collision handling and production-path tests; no work in the completed span-redaction task.

## Acceptance Criteria
Secret-shaped object keys cannot cross mac-chrome-session slack-read; safe keys remain stable; redacted-key collisions fail closed or use a deterministic non-leaking policy; nested maps, bounds, and downstream envelopes remain safe.
