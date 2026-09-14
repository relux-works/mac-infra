# TASK-260915-2ny9kd integration run RUN-260915-92e69c — landing refused

Run: RUN-260915-92e69c (developer / implementer, claude). CR: CR-TASK-260915-2ny9kd-9 rev 9, state `checkpointed`.
Story branch tip: 6c25ca3 (checkpoint commit for this task; T1 1a150bd, T2 39131c7 below it).
Protected trunk: refs/heads/main @ e326b5f.

## Commands run (real exit codes)

| # | Command | Exit | Result |
|---|---------|-----:|--------|
| 1 | `task-board m 'set_status(TASK-260915-2ny9kd, status=integrating)'` | 0 | already integrating |
| 2 | `task-board worktree checkpoint TASK-260915-2ny9kd --json` | 1 | `change_request_final_leaf_checkpoint` — this is the last open child of STORY-260915-3r0ys5; a checkpoint may not close the Story; use `worktree integrate` |
| 3 | `task-board worktree integrate STORY-260915-3r0ys5 --cr TASK-260915-2ny9kd --revision 9 --json` | 1 | `integration_blocked` — version_control.confirm requires `--commit-time` (owner policy: previous day, after 20:00 MSK) |
| 4 | same + `--commit-time 2026-09-14T22:30:00+03:00` | 1 | **`integration_base_moved`**: trunk advanced with a change to LOGBOOK.md, which this CR also changes; no one has looked at the combination. Checkpoints retained, trunk unmoved, no transaction opened. |
| 5 | `git merge-tree --write-tree main HEAD` (dry run, no ref moved) | 1 | content CONFLICT in LOGBOOK.md (stages 1/2/3) |

## Cause

Trunk commit abc7b11 (`STORY-260803-5uvf7l: agent-document-sanitizer`) appended 13 lines to LOGBOOK.md after the story base f9ec756. The story branch appends 111 lines to LOGBOOK.md at the same location (T1/T2/T3 entries). Both sides append at the tail → three-way merge conflicts.

## Why this run cannot resolve it

- `worktree converge STORY-260915-3r0ys5` is the documented exit, but it is orchestrator-only: a tracked run (TASK_BOARD_RUN_ID set) is refused with `transaction_disposition_not_operator`. It would also refuse here on the LOGBOOK.md content conflict and name the path, without moving anything.
- `worktree invalidate-acceptance` needs the revision already stale; the refused integrate did not demote it (cr_state still `checkpointed`, classification `awaiting_landing`).
- Editing LOGBOOK.md in this worktree is producer rework of an accepted, checkpointed tree — outside an integration run's authority.

## Next step (orchestrator)

1. Resolve the LOGBOOK.md conflict on the story branch: rebase/merge trunk into `task-board/story/STORY-260915-3r0ys5` keeping both the abc7b11 entry and the T1–T3 entries (pure additive, ordering by date), via `worktree converge --reason ...` after the conflict is cleared by hand, or by demoting rev 9 and spawning a rework producer who re-publishes the CR against fresh trunk.
2. Refreshed review of the combination, then re-run this integration with `--commit-time <prev-day ≥20:00 MSK>`.

Board left at `integrating` per assignment; no status written by this run.
