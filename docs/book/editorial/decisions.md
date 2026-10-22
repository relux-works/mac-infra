# Decisions

Numbered; a decision that changes the text cites its source.

1. **2026-10-23**: the book starts with Part 1 "Keys and Security" (owner job,
   via the meta-keeper). Other chapters follow later.
2. **2026-10-23**: chapter shape is problem → mechanism → limits, with explicit
   status marks (adopted from the swarma book practice, confirmed by Ivan's
   meta-keeper).
3. **2026-10-23**: English is the source language (mac-infra public-docs rule).
4. **2026-10-23**: diagrams live under the repository-root `diagrams/book/`
   (mac-infra diagram rule), not inside `docs/book/`.
5. **2026-10-23**: every change gets an independent claim-by-claim review against
   the pin (the meta-keeper's review lane) in addition to mac-infra's
   technical checks.
6. **2026-10-23**: installed-state facts of the reference host are never
   published; the book states only that installed builds can lag source.
