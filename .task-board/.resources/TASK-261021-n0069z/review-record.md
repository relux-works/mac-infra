# PR #23 review record

- Keeper reviews 01 and 02: K1 to K9, fixed in producer reworks 01 and 02.
- Independent review round 1 (fd18d1c): CHANGES F1 to F12, fixed in 4997c1e.
- Round 2 (4997c1e): CHANGES (F1 continuation, F13 chmod symlink race, F11 residual), fixed in 72081af.
- Round 3 (72081af): CHANGES (F14 unbounded cleanup depth), fixed in e9d4c97.
- Round 4 (e9d4c97): ACCEPT. No required fixes; the note says the Darwin descriptor peak is 129.

Mutation controls: 10 by the producer and 6 more by the producer in rework 03. The keeper ran 01, 02/02b, 03b, 04 and 05; each fails on its assertion.
