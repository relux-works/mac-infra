# TASK-260519-dpdo1o Implementation Decomposition

Date: 2026-05-19
Epic: EPIC-260519-32t1eh
Story: STORY-260519-2xbf75

## Inputs Reviewed

- Research: cleanup utility and disk profiler feature map.
- Solution architecture: `mac-disk-profile` read-only profiler and `mac-cleanup` scan-first cleanup tool.
- Architect review: plan/apply, Trash, size accounting, resource controls, root safety, and artifact privacy gaps.
- Current board graph: stories and tasks under EPIC-260519-32t1eh.

## Board Changes Made

- Added `TASK-260519-2lvhmz add-disk-profile-type-summary`.
  - Closes the research gap for size by extension/type without expanding cleanup scope.
  - Blocks JSON artifacts so the schema can include these summaries once, not churn later.
- Added `TASK-260519-3m5108 implement-cleanup-apply-revalidation-guards`.
  - Splits non-mutating TOCTOU/revalidation logic from Trash execution.
  - Keeps destructive execution gated behind plan, manifest, Trash semantics, guard layer, and safety tests.
- Linked category implementation tasks to `TASK-260519-3ilnxy implement-cleanup-scan-cli`.
  - Category work now starts after the shared scanner/planning core exists.
- Linked manifest work to `TASK-260519-3ilnxy`.
  - Manifest consumes the saved Plan shape emitted by scan commands.
- Linked docs/integration story to `STORY-260519-yz0mqz`.
  - README/skill/global verification now wait for category behavior, not just disk and executor work.

## Implementation Phases

1. Disk foundation
   - `TASK-260519-3vfq4z`: disk scan model, accounting, schema, permissions.
   - `TASK-260519-1mlvet`: cancellation, retained-entry limits, excludes, benchmark fixture.
   - `TASK-260519-204kn4`: `mac-disk-profile scan/top/explain` text CLI.
   - `TASK-260519-2lvhmz`: by-extension/by-kind summaries.
   - `TASK-260519-i018bt`: JSON artifacts and read-back validation.
   - `TASK-260519-mw0wqd`: repo/home/synthetic verification logs.

2. Cleanup scanner foundation
   - `TASK-260519-4m0vph`: category policy and dangerous-root rules.
   - `TASK-260519-2cplpc`: plan/apply contract, Plan hash, stale-plan behavior.
   - `TASK-260519-3ilnxy`: read-only `mac-cleanup scan/target/xcode` and saved Plan JSON.
   - `TASK-260519-19vo5i`: safety guard tests around scanner/apply refusal cases.

3. Cleanup executor
   - `TASK-260519-1sjp9e`: Trash destination semantics and restore metadata.
   - `TASK-260519-3jvypc`: Manifest schema and manifest-first outcome recording.
   - `TASK-260519-3m5108`: non-mutating apply revalidation guard layer.
   - `TASK-260519-1g0cy0`: Trash-first execution that consumes manifest, Trash semantics, and guards.
   - `TASK-260519-1q0s32`: permanent delete friction.

4. Cleanup categories
   - `TASK-260519-2mxj1n`: Xcode GeneratedData safe/review-only split.
   - `TASK-260519-r7v7eg`: explicit target-folder generated dirs.
   - `TASK-260519-2mafct`: large/old files as review-only findings.

5. Integration and docs
   - `TASK-260519-15f9x6`: setup/deinit wiring.
   - `TASK-260519-2u5agy`: README and mac-infra skill workflow docs.
   - `TASK-260519-2q8yv3`: global install and smoke verification.

## Ownership Boundaries

- Disk model/resource control: `internal/diskprofile` only.
- Disk CLI rendering: `cmd/mac-disk-profile` plus diskprofile render helpers.
- Cleanup policy/planning: `internal/cleanup` policy, rule, candidate, Plan types.
- Cleanup CLI scanning: `cmd/mac-cleanup` and read-only planning paths only.
- Cleanup executor: `internal/cleanup` executor/manifest/trash helpers only after guard tasks are done.
- Setup/deinit: `scripts/setup.sh`, root `setup.sh`, `scripts/deinit.sh`, root `deinit.sh`.
- Docs/skill: `README.md` and `agents/skills/mac-infra/SKILL.md`.

Parallel implementation is safe when developers stay inside those boundaries. Active development tasks should not be rewritten by downstream workers; downstream tasks consume their contracts.

## Completeness Check

- Disk profiler: read-only scan, top files/dirs, errors/skips, resource controls, accounting, JSON artifacts, extension/type summaries, and live verification are covered.
- Cleanup scanner: allowlisted categories, plan JSON, risk/default selection, dangerous roots, symlink/containment policy, and scanner safety tests are covered.
- Cleanup executor: plan/apply contract, Trash semantics, manifest-first execution, TOCTOU guard layer, Trash-first apply, and permanent delete friction are covered.
- Categories: Xcode, explicit target folders, and review-only large/old files are covered.
- Integration: setup/deinit, docs/skill, and final smoke verification are covered.
- Destructive cleanup remains gated behind saved plan, validation, manifest, Trash semantics, safety tests, `--apply`, and permanent-delete friction.

## Residual Notes

- `TASK-260519-19vo5i` still has broad checklist wording. Treat `TASK-260519-3m5108` as the dedicated guard-layer implementation and use `TASK-260519-19vo5i` for safety test coverage around the contracts.
- No source code changes were made by this decomposition task.
