# TASK-260825-ghny8q: extend-slack-sealed-read-methods

## Description
Extend the reviewed mac-chrome-session slack-read sealed primitive with the remaining Slack Web API read methods required by slack-mgmt while preserving the compiled allowlist, typed argument validation, exact workspace/origin guards, bounded output, no-focus behavior, and browser-secret confinement.

## Scope
internal/chromectl Slack request validation and tests, mac-chrome-session documentation, installed artifact validation, and content-free live smokes against authorized workspace T073GL82HJB. No Slack writes.

## Acceptance Criteria
slack-read accepts conversations.info, conversations.history, conversations.replies, users.list, and search.messages with method-specific bounded typed arguments; auth.test and conversations.list remain compatible; unknown methods and unknown/secret-shaped arguments fail before browser execution; exact target/origin/workspace guards and response bounds remain unchanged; browser credentials never leave Chrome; tests, setup/install, and sanitized content-free live method smokes pass.
