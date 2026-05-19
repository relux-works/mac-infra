# Flight Logbook

> Institutional memory. Concise, factual, high-signal.
> Newest entries first. One block per insight.

## 2026-05-19

### 1600 - Cleanup Planner Test Roots
- FINDING: macOS `t.TempDir()` resolves under `/var/folders`, and cleanup root policy intentionally refuses `/var` descendants.
- DECISION: Cleanup planner/CLI tests use repo-local temporary directories under the checkout so fixtures exercise allowed user-owned child roots without weakening production safety rules.
- SCOPE: `internal/cleanup/planner_test.go`, `cmd/mac-cleanup/main_test.go`.

### 1557 - Disk Profile CLI Text Contract
- FIX: `internal/diskprofile/render.go` owns concise tabular text rendering for scan/top/explain output.
- FIX: `cmd/mac-disk-profile top` treats `--files` and `--dirs` as selectors; absent selectors renders both tables.
- ANOMALY: Sandboxed Go commands need task-scoped `GOCACHE/GOPATH`; default `~/Library/Caches/go-build` is not writable.
- STATUS: Verified with `go test ./...`, `go vet ./...`, `go build ./...`, and `gofmt -l cmd internal`.

### 1547 - Cleanup Plan Apply Contract
- DECISION: `internal/cleanup.Plan` schema v1 includes `categoryPolicyVersion`, `hashInputs`, `generatedAt`, `staleAfterSeconds`, root realpath, candidate identity, risk/default flags, sizes, apply contract, and `planHash`.
- DECISION: `clean --apply` v1 requires `--plan PATH`; direct category apply is explicitly unsupported until a future rescan-and-confirm flow exists.
- DECISION: Apply preflight refuses stale plans after 24h, hash mismatch, selected out-of-scope candidates, changed candidate identity, symlink swaps, out-of-root realpaths, and ownership mismatches before any deletion code can run.
- SCOPE: Contract and revalidation helpers only; no Trash/permanent deletion implementation.

### 1547 - Disk Scan Resource Controls
- DECISION: `internal/diskprofile` applies default generated-tree excludes by default; `--exclude` adds patterns; `--no-default-excludes` opts back into generated trees.
- DECISION: Top dirs/files are retained with bounded lists; JSON hierarchy retention is capped by `MaxRetainedEntries` without stopping byte accounting.
- FIX: Context cancellation now records `canceled` scan errors and returns a partial result with the context error.
- SCOPE: `internal/diskprofile` resource controls and `cmd/mac-disk-profile` flags.

### 1528 - Disk Profile Scan Model Contract
- DECISION: `internal/diskprofile` uses `os.Lstat` only, never follows symlinks, and records symlink skips as non-fatal `ScanError` entries.
- DECISION: Logical bytes are lstat apparent size; disk bytes are best-effort `st_blocks * 512`; hard links are de-duped by `(device,inode)`.
- DECISION: Scan JSON is schema-versioned and written with restrictive artifact permissions: created dirs `0700`, JSON files `0600`.
- SCOPE: Read-only disk profiler model and `cmd/mac-disk-profile`; cleanup executor/apply semantics unchanged.

### 1528 - Cleanup Category Policy Boundary
- DECISION: `internal/cleanup/policy.go` separates default-selected safe generated data from review-only user/risky data and v1 out-of-scope categories.
- DECISION: External volume roots are refused; child paths under `/Volumes/<name>/...` require explicit target selection plus ownership, symlink, and realpath containment checks.
- SCOPE: Category policy only; no deletion executor, scanner traversal, docs, setup, or disk profile changes.

### 1527 - Cleanup and Disk Work Package Decomposition
- FINDING: Board already captured architect-review blockers for plan/apply, Trash semantics, disk accounting, and resource controls.
- FINDING: Two implementation gaps remained: disk extension/type summaries and a non-mutating cleanup apply revalidation guard layer.
- DECISION: Added `TASK-260519-2lvhmz` for disk extension/type summaries before JSON artifacts.
- DECISION: Added `TASK-260519-3m5108` to split TOCTOU/revalidation guards from destructive Trash execution.
- DECISION: Linked docs/integration after category story so README/skill describe final category behavior, not just core CLIs.
