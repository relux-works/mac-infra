# Integrate accepted browser depersonalization change

This is an integration-only developer run for accepted `CR-BUG-260915-7elb3o-2`, revision 2.

- Do not edit product files and do not publish another Change Request.
- From the control root, run exactly:
  `task-board worktree integrate STORY-260803-5uvf7l --cr BUG-260915-7elb3o --revision 2 --commit-time 2026-09-14T22:15:00+03:00`
- Preserve the accepted candidate tree. Let the transaction own the Story/leaf done transitions and board-only commit; do not run handoff afterward.
- Verify the resulting product and board commits are cryptographically signed, retain the configured human author identity, and have the requested author/committer timestamp.
- Verify local `main` is the accepted integrated head and report both commit OIDs plus signature evidence.
- Do not push any branch or default ref in this run. The parent session owns the canonical GitHub PR and exact-head publication after integration.
