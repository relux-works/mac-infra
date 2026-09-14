# TASK-260915-2ny9kd — integration run RUN-260915-431f05

Assignment: refresh the CR rev 9 candidate base per orchestrator base-refresh note
(`task-board worktree refresh-candidate TASK-260915-2ny9kd`, follow resolution-template.json
for the LOGBOOK.md conflict).

## Commands run (worktree .temp/STORY-260915-3r0ys5/worktree, HEAD 6c25ca3, clean tree)

1. `task-board m 'set_status(TASK-260915-2ny9kd, status=integrating)'` — ok (already integrating).
2. `task-board --json worktree refresh-candidate TASK-260915-2ny9kd` — REFUSED, exit non-zero:

```
{"error":{"code":"INTERNAL_ERROR","message":"candidate refresh requires a rework revision; TASK-260915-2ny9kd is checkpointed","details":{}}}
```

No replay worktree / resolution-template.json was produced; nothing was modified.

## State observed

- origin/main = main = e326b5f (fetched fresh).
- Story tip 6c25ca3 NOT contained in origin/main.
- `git merge-tree --write-tree origin/main HEAD` → 3-way conflict on LOGBOOK.md only (stages 1/2/3).

## Why stopped

Orchestrator note: "If refresh-candidate refuses because the leaf is integrating rather than to-dev,
report the exact refusal text and stop." Refusal class matches: refresh-candidate only serves an
initial/rework revision; CR rev 9 is `checkpointed` at 6c25ca3, so the tool refuses. Per the standing
rule, no hand-commit / rebase / branch edit was done. Board left at `integrating`.

## Needed from orchestrator

Choose the base-refresh path for a *checkpointed* revision — options:
(a) `worktree invalidate-acceptance` to release rev 9 back to rework, then refresh-candidate
    (LOGBOOK.md resolution is purely additive), new CR revision, review, integrate; or
(b) an orchestrator-driven `worktree converge` / integrate path that accepts the additive LOGBOOK
    resolution without reopening the leaf.
