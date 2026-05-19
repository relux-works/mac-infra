# Architecture: safe cleanup and disk profiling

Date: 2026-05-19

## Goals

- Provide practical cleanup and disk profiling workflows without black-box "optimizer" behavior.
- Keep profiling read-only.
- Keep cleanup safe, explicit, and reversible by default.
- Make all decisions inspectable in terminal output and JSON.

## Non-goals

- No malware scanning.
- No RAM cleaning.
- No hidden preference tweaking.
- No forced purgeable-space deletion in v1.
- No app uninstaller in v1.
- No generic privileged "delete anything" helper.

## Proposed CLIs

### `mac-disk-profile`

Read-only disk space profiler.

Commands:

- `mac-disk-profile scan [PATH]`
  - recursive filesystem scan
  - default path: `$HOME`
  - outputs top directories/files and aggregate totals
  - writes optional JSON artifact

- `mac-disk-profile top [PATH]`
  - convenience text output for largest directories/files

- `mac-disk-profile explain [PATH]`
  - compares scanned total with filesystem used/free stats where possible
  - reports permission-denied/skipped paths as "unaccounted candidates"
  - can later include APFS snapshot hints from `tmutil listlocalsnapshots /`

Core model:

```go
type Entry struct {
    Path string
    Kind EntryKind
    LogicalBytes int64
    DiskBytes int64
    ChildrenBytes int64
    ModTime time.Time
    Err string
}
```

Safety:

- No mutation commands.
- Do not follow symlinks.
- Bound recursion with excludes.
- Permission errors are recorded, not fatal by default.
- Support `--one-file-system` if device IDs are available.

### `mac-cleanup`

Safe allowlisted cleanup tool.

Commands:

- `mac-cleanup scan`
  - broad user-level cleanup candidates
  - no deletion

- `mac-cleanup clean --apply`
  - executes selected allowlisted categories
  - default action: move to Trash

- `mac-cleanup target PATH`
  - scan one target folder for build/log/generated artifacts
  - target must be below a user-controlled path, not `/`, `$HOME`, `/System`, `/Library`, `/Applications`, etc.

- `mac-cleanup xcode`
  - scan Xcode-specific generated data
  - categories must be explicit

Core model:

```go
type Category struct {
    ID string
    Name string
    DefaultSelected bool
    Risk RiskLevel
    Roots []RootSpec
    Rules []Rule
}

type Candidate struct {
    Path string
    CategoryID string
    Bytes int64
    Age time.Duration
    Reason string
    Action Action
    Risk RiskLevel
}
```

Category policy:

- Safe generated data:
  - Xcode DerivedData build products
  - repo-local `.temp`, `build`, `dist`, `.build`, `.dart_tool`, `node_modules/.cache`, common log dirs
  - old rotated logs
  - empty trash summary

- Review-only:
  - Downloads
  - large files
  - old files
  - app caches
  - iOS backups
  - Xcode Archives, DeviceSupport, simulators

- Out of scope v1:
  - language stripping
  - binary thinning
  - app leftovers
  - browser/mail/private data

Deletion engine:

- `--apply` required for deletion.
- Default is move-to-Trash.
- `--permanent` allowed only with `--apply --yes-i-know`.
- Refuse dangerous roots and symlinks.
- Use path containment checks after resolving real paths.
- Create a manifest before deletion:
  - timestamp
  - paths
  - sizes
  - category/reason
  - action
  - errors

Trash implementation options:

- Prefer native macOS trash operation if available.
- Fallback can move to `~/.Trash/mac-infra-<timestamp>/...` while preserving relative paths and avoiding collisions.
- Direct permanent delete is only for explicit high-friction flags.

## Shared packages

- `internal/diskprofile`
  - filesystem traversal
  - size aggregation
  - excludes
  - output models

- `internal/cleanup`
  - category definitions
  - candidate planner
  - safety guards
  - trash/delete executor

- `internal/report`
  - table rendering and JSON output, if duplication grows

## Architecture decisions

- Keep cleanup and disk profiling separate. Profiling explains where space is; cleanup removes only known safe generated data.
- First release is CLI-only; JSON output keeps future TUI/web/Figma visualization possible.
- Do not use `mac-infra-core` for cleanup v1. User-owned cleanup should run as the user. Privileged deletion is too risky.
- Store artifacts under `.temp/mac-disk-profile` and `.temp/mac-cleanup` by default.

## Delivery plan

1. Build read-only disk profiler first.
2. Build cleanup scanner second.
3. Add deletion executor with Trash-first behavior after scanner output is proven.
4. Add Xcode and repo target categories.
5. Later: app leftovers with review-only confidence scoring.
