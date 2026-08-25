# Revision 3 rework contract: linear token-span scan

Keep the accepted confidentiality fixes from CR revision 2, but replace the
quadratic boundary-rescan algorithm with the reviewer-validated linear approach:
encode the left boundary in the pattern and use the token capture-group span
from `FindAllStringSubmatchIndex`.

Acceptance additions:

- production `Session.SlackRead` at the configured maximum response size stays
  comfortably within a bounded test deadline on ordinary CI hardware;
- the cost-bound test fails against CR revision 2's quadratic implementation;
- nested-token, 5-part JWE, overlap-union, request-guard, differential corpus,
  response-size/depth/node bounds, and all existing mutants remain green;
- no live Slack writes; live checks remain read-only and count-only.
