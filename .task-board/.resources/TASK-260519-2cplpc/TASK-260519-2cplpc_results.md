# TASK-260519-2cplpc Results

## Code

- Added `internal/cleanup/plan.go`.
- Added `internal/cleanup/plan_test.go`.
- Updated `internal/cleanup/policy.go` so `DefaultPolicy()` carries `CategoryPolicyVersion`.
- Added a cleanup plan/apply contract entry to `LOGBOOK.md`.

## Contract Decisions

- Plan schema is versioned with `schemaVersion = 1`.
- Category policy is versioned with `categoryPolicyVersion = cleanup-policy-v1`.
- Plan JSON records `hashInputs`, `generatedAt`, `staleAfterSeconds`, root realpath, candidate identity, risk/default/selected flags, logical and disk byte sizes, apply semantics, totals, and `planHash`.
- `planHash` is `sha256` over the canonical JSON plan with `planHash` blanked. The hash covers schema version, policy version, generated timestamp, stale window, source, root, categories, candidates, totals, apply contract, and `hashInputs`.
- Saved plans become stale after 24 hours by default.
- `clean --apply` v1 requires `--plan PATH`.
- Direct category apply is explicitly unsupported in v1. A future direct mode must rescan, materialize a plan, show exact count/bytes, require confirmation, and run the same preflight contract.

## Safety Rules Implemented

- Apply preflight refuses schema mismatch, category policy mismatch, missing/mismatched plan hash, stale plans, and selected out-of-scope candidates.
- Candidate revalidation performs fresh `lstat` checks before deletion code can run.
- Revalidation refuses root symlink swaps, root realpath changes, root device/inode changes, candidate symlink swaps, candidate out-of-root realpaths, ownership mismatches, and changed candidate identity/size/mtime/mode.
- Plan artifacts are written with restrictive permissions: parent dirs `0700`, JSON files `0600`.
- No Trash, move, permanent delete, or executor mutation path was added in this task.

## Verification

- `go test ./... -count=1` with task-local `GOCACHE` and `GOMODCACHE`: passed. Log: `.temp/TASK-260519-2cplpc/go-test-02.log`.
- `go vet ./...` with task-local `GOCACHE` and `GOMODCACHE`: passed. Log: `.temp/TASK-260519-2cplpc/go-vet-02.log`.
- `go build ./cmd/...` with task-local `GOCACHE` and `GOMODCACHE`: passed. Log: `.temp/TASK-260519-2cplpc/go-build-02.log`.
- `git diff --check`: passed. Log: `.temp/TASK-260519-2cplpc/git-diff-check-02.log`.
