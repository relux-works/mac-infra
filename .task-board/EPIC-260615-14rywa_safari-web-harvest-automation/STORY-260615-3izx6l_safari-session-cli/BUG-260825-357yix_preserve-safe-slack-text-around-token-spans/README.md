# BUG-260825-357yix: preserve-safe-slack-text-around-token-spans

## Description
Refine mac-chrome-session slack-read response sanitization so token-shaped substrings are replaced in place without replacing the entire surrounding Slack message text, while preserving fail-closed browser-secret confinement and response bounds.

## Scope
internal/chromectl Slack response sanitizer and adversarial tests; no provider method changes and no Slack writes.

## Acceptance Criteria
Slack response strings containing xox*/Bearer/JWT-like substrings preserve non-secret surrounding text while every secret-shaped span is replaced; standalone and repeated/adjacent token spans, URLs, structured secret keys, nesting, bounds, and malformed responses remain safe; named narrowing mutants prove removing or weakening span replacement leaks and fails; installed content-free live smoke proves surrounding synthetic references survive while raw token-shaped bytes do not.
