# Independent review of CR revision 2

Review the immutable Change Request `CR-BUG-260915-7elb3o-2`, revision 2. Do not edit production code.

Required review:

- Reproduce the revision 1 false-positive witness through the production `mac-browser-site` entry points: `name=Desk lamp`, `addressType=shipping`, and `author=OpenAI` must remain unchanged in JSON stdout, compact stdout, cache, and grep.
- Include an adjacent true PII control such as `fullName=Иванов Иван Иванович`; it must be replaced consistently and never appear raw.
- Verify representative PII categories, stable repeated placeholders, malformed-record fail-closed behavior, raw/legacy cache refusal, and the pre-existing secret refusal/no-side-effect contract.
- Attack the ambiguous-field narrowing with an independent behavioral mutant that keeps the sanitizer gate present but restores the overbroad generic-field classification. The production-path test must fail for the intended false-positive reason.
- Run focused tests, relevant race tests, the uncached full suite, vet, build, formatting, diff, and board validation. Record any retry and distinguish a real failure from a pre-existing timing flake.
- Report acceptance coverage as an explicit ratio with production call sites. Attach a fresh task-scoped verdict resource.
- If accepted, call `accept_cr(BUG-260915-7elb3o, revision=2, evidence=<fresh verdict resource>)`. Otherwise attach findings and route to `to-dev`.

The reviewer owns only review evidence and board verdict state. Leave the candidate worktree content unchanged and uncommitted.
