# Solution Architecture: mac-infra cleanup and disk profiling

Date: 2026-05-19
Epic: EPIC-260519-32t1eh

## Product shape

The feature is split into two tools with different safety contracts:

- `mac-disk-profile`: read-only disk usage profiler. Its job is to explain where space is used.
- `mac-cleanup`: scan-first cleanup planner/executor. Its job is to remove only allowlisted generated data after explicit confirmation.

This separation is deliberate. Disk profilers can be broad and exploratory; cleanup tools must be narrow and conservative.

## CLI contracts

### `mac-disk-profile`

Commands:

```bash
mac-disk-profile scan [PATH] [--depth N] [--limit N] [--json PATH] [--exclude GLOB] [--one-file-system]
mac-disk-profile top [PATH] [--files] [--dirs] [--limit N]
mac-disk-profile explain [PATH] [--json PATH]
```

Contract:

- Never mutates files.
- Does not follow symlinks.
- Records permission errors instead of failing the whole scan.
- Emits text for quick triage and JSON for future TUI/visualization.
- Uses logical size and best-effort disk block size where available.
- Reports skipped/unreadable/unaccounted categories explicitly.

### `mac-cleanup`

Commands:

```bash
mac-cleanup scan [--category ID] [--json PATH]
mac-cleanup target PATH [--json PATH]
mac-cleanup xcode [--category ID] [--json PATH]
mac-cleanup clean --apply [--category ID] [--trash | --permanent --yes-i-know] [--manifest PATH]
```

Contract:

- `scan`, `target`, and `xcode` never delete.
- `clean` refuses to delete unless `--apply` is present.
- Default delete action is move-to-Trash.
- Permanent deletion requires both `--permanent` and `--yes-i-know`.
- Dangerous roots are refused: `/`, `$HOME`, `/System`, `/Library`, `/Applications`, `/bin`, `/sbin`, `/usr`, `/private`, `/var`, `/Volumes` root.
- Symlink candidates are refused for deletion.
- Candidate paths must remain contained within their configured root after realpath resolution.
- A manifest is written before deletion starts.

## Package boundaries

### `internal/diskprofile`

Responsibilities:

- Walk filesystem.
- Calculate per-entry logical size and best-effort disk size.
- Apply excludes and depth/limit constraints.
- Aggregate directory tree.
- Record scan errors.
- Render scan result to text and JSON-friendly structs.

Key types:

```go
type ScanOptions struct {
    Root string
    MaxDepth int
    Limit int
    Excludes []string
    OneFileSystem bool
}

type Entry struct {
    Path string
    Name string
    Kind EntryKind
    LogicalBytes int64
    DiskBytes int64
    ModTime time.Time
    Device uint64
    Children []Entry
    Err string
}

type ScanResult struct {
    Root string
    StartedAt time.Time
    FinishedAt time.Time
    LogicalBytes int64
    DiskBytes int64
    TopDirs []Entry
    TopFiles []Entry
    Errors []ScanError
}
```

### `internal/cleanup`

Responsibilities:

- Define cleanup categories.
- Build candidate sets from category rules.
- Score risk and default selection.
- Enforce path safety.
- Execute Trash/permanent actions.
- Write execution manifests.

Key types:

```go
type Risk string // safe, review, dangerous
type Action string // report, trash, delete

type Category struct {
    ID string
    Title string
    Risk Risk
    DefaultSelected bool
    Roots []RootSpec
    Rules []Rule
}

type Candidate struct {
    Path string
    CategoryID string
    Reason string
    Risk Risk
    DefaultSelected bool
    LogicalBytes int64
    ModTime time.Time
}

type Plan struct {
    GeneratedAt time.Time
    Candidates []Candidate
    Totals Totals
}

type Manifest struct {
    PlanHash string
    StartedAt time.Time
    Action Action
    Entries []ManifestEntry
}
```

### `internal/report`

Introduce only if duplication becomes noisy. For now, each CLI can render simple tables locally.

## Category policy

### Safe generated data

Safe categories may be default-selected for cleanup after `scan`, but still require `clean --apply`.

- Xcode DerivedData build products:
  - `~/Library/Developer/Xcode/DerivedData/*`
  - conservative default: delete entire project DerivedData directories, not Archives or DeviceSupport.
- Repo-local generated directories under explicit target:
  - `.temp`
  - `.build`
  - `build`
  - `dist`
  - `.dart_tool`
  - `node_modules/.cache`
  - `.pytest_cache`
  - `.mypy_cache`
  - `.ruff_cache`
  - `coverage`
  - `DerivedData` only inside target if target is not a system root.
- Logs:
  - rotated/compressed logs above age threshold in user-owned log directories.

### Review-only

Review-only categories are reported but not default-selected.

- Large files.
- Old files.
- Downloads.
- App caches under `~/Library/Caches`.
- iOS backups.
- Xcode Archives.
- Xcode DeviceSupport.
- Installed simulators.
- Mail/browser/chat attachments.

### Out of scope v1

- Malware scanning.
- App uninstall leftovers.
- Browser privacy cleanup.
- Mail attachment deletion.
- Language file deletion.
- Binary thinning.
- RAM cleaning.
- Forced purgeable-space cleanup.

## Safety model

Cleanup safety is enforced in several layers:

1. Category allowlist: only categories in code can produce candidates.
2. Root guard: roots must be user-owned and cannot be system roots.
3. Realpath containment: candidate real path must remain inside root real path.
4. Symlink refusal: symlink candidates are reported but not deleted.
5. Scan-first UX: deletion is unavailable from scan commands.
6. Apply gate: deletion requires `clean --apply`.
7. Trash-first default: reversible by default.
8. Manifest-first execution: write intended action before moving/deleting.
9. Permanent delete friction: `--permanent --yes-i-know`.

## Disk profiler design notes

Disk profiling should behave like the CLI version of DaisyDisk/OmniDiskSweeper:

- Scan one target at a time.
- Produce top directories/files.
- Group by extension/type later.
- Save JSON for diffing and future visualization.
- Report hidden/unaccounted hints:
  - permission errors
  - excluded dirs
  - symlinks skipped
  - possible APFS snapshots/purgeable space note

V1 does not need a graphical treemap, but the JSON should preserve enough hierarchy for future rendering.

## Execution phases

### Phase 1: Read-only foundation

- Design disk scan model.
- Implement `mac-disk-profile scan/top/explain`.
- Add JSON artifacts.
- Verify on `$HOME`, repo target, and a synthetic fixture.

### Phase 2: Cleanup scanner

- Define category policy.
- Implement `mac-cleanup scan/target/xcode` planning.
- Add safety guard tests.

### Phase 3: Cleanup executor

- Implement Trash-first executor.
- Add manifest.
- Add permanent delete friction.

### Phase 4: Categories and integration

- Add Xcode generated-data categories.
- Add target-folder build/log categories.
- Add review-only large/old file reporting.
- Wire setup/deinit.
- Update README and skill.
- Run global install and smoke verification.

## Review checklist

- No cleanup command deletes without `--apply`.
- No profiler command mutates anything.
- No implementation follows symlinks for deletion.
- Dangerous roots are refused in tests and live dry-runs.
- Permanent delete path is high-friction and tested.
- Artifacts and manifests are written under `.temp/` by default.
- README and skill explain read-only vs cleanup behavior clearly.
