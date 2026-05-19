# Architect Review: cleanup and disk profiling

Date: 2026-05-19
Epic: EPIC-260519-32t1eh

## Summary

The proposed architecture is directionally sound and safe enough to proceed after tightening a few decisions. The strongest choice is the hard separation between `mac-disk-profile` as a read-only profiler and `mac-cleanup` as a narrow, allowlisted cleanup planner/executor. The main gap before implementation is that the cleanup plan/apply contract is not yet precise enough for a destructive tool.

## Key architecture strengths

- Clear safety boundary: profiling never mutates, cleanup is scan-first, and deletion requires an explicit `clean --apply`.
- Good product scoping: v1 excludes malware scanning, RAM cleanup, forced purgeable cleanup, binary/language stripping, generic app uninstall, and privileged arbitrary deletion.
- Conservative cleanup policy: generated data is separated from review-only user data; large/old files and Downloads are not auto-selected.
- Correct macOS posture: APFS/purgeable/hidden space is treated as explainable context, not as something v1 should forcibly reclaim.
- Package split matches the repo style: `internal/diskprofile`, `internal/cleanup`, and optional `internal/report` align with the existing `internal/loadprofile` and `internal/audioreset` pattern.
- Board sequencing is mostly right: disk profiling and cleanup scanner come before the cleanup executor, and docs/setup integration is blocked on implementation.

## Risks or missing decisions

- Cleanup apply semantics are underspecified. It is unclear whether `mac-cleanup clean --apply` re-scans current state, applies a previously saved plan, or deletes category defaults directly. That is the highest-risk missing decision.
- The manifest model says `PlanHash`, but there is no explicit saved plan schema, plan path, hash validation, or stale-plan behavior.
- Trash implementation is still an option list. Native macOS Trash vs `~/.Trash/mac-infra-<timestamp>` fallback affects reversibility, cross-volume behavior, collision handling, and user expectations.
- Size accounting needs a concrete v1 rule. Logical bytes, disk blocks, hard-link deduplication, APFS clones, sparse files, and package directories can produce surprising totals if not documented and tested.
- Broad scans can leak sensitive full paths into JSON artifacts. `.temp/` is gitignored, but the artifact format should still define permissions and maybe a future redaction option.
- Dangerous-root policy needs edge-case decisions: external volumes under `/Volumes/<name>`, `$HOME` as a cleanup target, symlinked roots, ownership checks, and writable-but-not-user-owned paths.
- Performance controls are not explicit enough for `$HOME` scans: cancellation, max retained entries, default excludes, progress behavior, and memory limits need a first-pass design.
- Xcode category boundaries are correct conceptually, but exact paths and defaults need to be locked before coding. DerivedData is safe-ish; Archives, DeviceSupport, simulators, docs, and iOS backups must stay review-only.

## Recommended changes before implementation

- Define the cleanup plan/apply contract before executor work:
  - `scan`, `target`, and `xcode` produce a versioned `Plan` JSON.
  - `clean --apply --plan PATH` applies that plan, verifies `PlanHash`, re-lstats every candidate, refuses changed symlinks/out-of-root paths, and writes a manifest before the first move/delete.
  - If direct category apply is kept, make it re-scan and print the exact candidate count/bytes before requiring confirmation or category flags.
- Pick one Trash v1 implementation. Recommended: implement collision-safe move into `~/.Trash/mac-infra-<timestamp>/...` with manifest restoration metadata, then add native Trash later only if needed.
- Add disk profiler v1 accounting rules:
  - use `lstat`;
  - do not follow symlinks;
  - compute logical bytes and best-effort `stat.Blocks * 512`;
  - dedupe hard links by `(device,inode)`;
  - document that APFS clone sharing is reported best-effort.
- Add explicit scan resource controls: context cancellation, max depth, max retained top entries, default excludes, and a synthetic large-tree benchmark/fixture.
- Make JSON artifacts versioned (`schemaVersion`) and write them with restrictive permissions (`0600` for files, `0700` for dirs) because path names can be sensitive.
- Add root safety rules as tests before executor implementation: dangerous roots, external volume root vs child path, symlink root, symlink candidate, path traversal, changed file between plan and apply, and non-user-owned candidate.
- Keep `mac-infra-core` out of cleanup v1. The current decision is correct; do not introduce privileged deletion until there is a separate threat model and review.

## Suggested task board changes

- Fill task-level `scope` and `acceptance criteria`; many tasks still contain placeholders. This should happen before moving tasks from backlog to development.
- Add or expand `TASK-260519-3vfq4z` to include the disk profiler schema/accounting decision: logical bytes, disk bytes, hard-link dedupe, APFS clone caveat, artifact permissions, and fixture requirements.
- Add a new blocker before `TASK-260519-1g0cy0`: define cleanup plan/apply contract and saved plan schema. This should produce the `Plan`/`Manifest` schema and stale-plan behavior.
- Move `TASK-260519-3jvypc` before `TASK-260519-1g0cy0` or split it. The manifest/plan schema should be designed before executor code, while outcome recording can remain part of executor implementation.
- Add a dedicated task for Trash semantics: destination layout, collision handling, cross-volume behavior, and restoration metadata.
- Add a dedicated task for scan performance/resource controls before `TASK-260519-mw0wqd`; verifying on `$HOME` without limits risks an expensive or noisy first implementation.
- Add checklist items to `TASK-260519-19vo5i` for TOCTOU, symlink swap, external volume child paths, and non-user-owned paths.

## Review outcome

Proceed after the plan/apply, Trash, and size-accounting decisions are captured in the board. The architecture is good, but destructive cleanup tooling needs those decisions written down before implementation starts. Board validation currently passes.
