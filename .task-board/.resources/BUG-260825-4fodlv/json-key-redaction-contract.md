# Secret-shaped Slack JSON key contract

The sealed `Session.SlackRead` boundary must not return token/Bearer/JWT-shaped
bytes in JSON object keys or values.

- Preserve safe keys byte-for-byte.
- Sanitize nested object keys before the response leaves `mac-chrome-session`.
- Define deterministic collision behavior when two input keys normalize to the
  same redacted key; fail closed rather than overwrite or lose evidence.
- Keep response depth/node/size and linear-cost bounds.
- Add named production-path tests and narrowing mutants for raw-key leakage,
  nested maps, and collisions.
- No live Slack writes. Live verification, if needed, is read-only/count-only.
