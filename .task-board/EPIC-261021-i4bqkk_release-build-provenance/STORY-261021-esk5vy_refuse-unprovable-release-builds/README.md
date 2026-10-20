# STORY-261021-esk5vy: refuse-unprovable-release-builds

## Description
Go stamps buildinfo vcs only from a .git DIRECTORY; a git worktree nested under ~/src/mac-infra (.git FILE) makes go build stamp the main checkout (809e0338, vcs.modified=true). Found by meta-keeper 2026-10-21 on bin/mac-netnone; bin/mac-infra-core, mac-firewall, mac-keyvault had the same stamp. Meta decision 2026-10-21 ($W2thWnGl, item 4): fix at source.

## Scope
scripts/setup.sh build path (and any release build helper); README tools/build section; tests under scripts/.

## Acceptance Criteria
1) The mac-infra build path refuses to produce installed binaries when the source tree is a git worktree nested in another repo, or when git status --porcelain is non-empty, or builds from a clean clone of the requested commit instead. 2) After each build it asserts go version -m shows vcs.revision equal to the source HEAD and vcs.modified=false, and fails otherwise. 3) Negative controls: a nested-worktree build and a dirty-tree build are refused (or caught by the assertion) in tests; a clean tree passes. 4) FREEZE respected: the change must not rebuild bin/mac-keyvault as a side effect of tests; tests use temp output dirs.
