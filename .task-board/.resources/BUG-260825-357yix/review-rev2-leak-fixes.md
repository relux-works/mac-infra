# Focused review contract for CR revision 2

Review only the rework for the three findings from RUN-260825-2ab20b.

1. Attack nested valid Slack-token starts after an invalid left boundary. The
   production response sanitizer and request-side guard must not leak or admit
   `xox*` shapes hidden behind a prefix.
2. Attack compact JWT/JWE values with four or more segments. The whole token
   span must be replaced without leaving trailing segments.
3. Delete or narrow the overlap-union branch. A named production-path test must
   fail and the normal implementation must not panic on overlapping Bearer and
   Slack-token spans.
4. Run the focused packages, the differential corpus, vet, and diff checks.
5. Do not create Slack messages. Any live verification is read-only and
   count-only.
6. Publish an explicit accept or changes-requested verdict for CR revision 2.
