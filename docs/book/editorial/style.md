# Style

- **Audience**: engineers and agents who operate or extend mac-infra.
- **Shape of every chapter**:
  1. The problem.
  2. The mechanism, in mac-infra's own terms.
  3. Limits and transitional modes, stated explicitly.

  If practice diverges from the text, either a decision or the book changes, never neither.
- **Prose, not a reference**: explain why the design refuses what it refuses. Link
  the runbook for commands and options; use at most a few short examples.
- **Status marks**: every guarantee says what backs it:
  - *source*: implemented at the pinned revision;
  - *tested*: a test is named;
  - *installed*: only as a general statement; never host details;
  - *proposed*: defined but not live;
  - *unknown*.
  A passing test is evidence for that case, not a universal proof.
- **Negative guarantees are content**: say what is refused and what is not
  protected (for example, no isolation between processes of the same user).
- **Never in the book**: secrets, private keys, tokens, personal host
  inventories, paths under a user's home, raw diagnostics, installed
  digests or versions.
- **Citations**: repository-relative paths at the pin listed in `sources.md`;
  `[needs source]` marks a claim that still lacks one.
- English; one sentence per idea; no marketing words.
