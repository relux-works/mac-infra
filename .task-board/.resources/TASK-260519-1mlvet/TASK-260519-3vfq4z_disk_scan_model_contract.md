# Disk Scan Model Contract

Task: `TASK-260519-3vfq4z`
Package: `internal/diskprofile`
CLI: `cmd/mac-disk-profile`
Schema version: `1`

## Types

### ScanOptions

- `Root`: target path. Empty means user home. Normalized to an absolute clean path.
- `MaxDepth`: traversal depth relative to `Root`; `0` scans root only, `1` includes direct children, negative means unlimited.
- `Limit`: retained `TopDirs` and `TopFiles` length. Non-positive values use `DefaultLimit`.
- `Excludes`: slash-separated glob patterns matched against root-relative path and base name. Excluded entries are not counted.
- `OneFileSystem`: skips entries on devices different from the root device when `lstat` exposes device IDs.

### Entry

- `Path`, `Name`: absolute path and base name.
- `Kind`: `directory`, `file`, `symlink`, or `other`.
- `LogicalBytes`: `lstat` apparent bytes for this path only.
- `DiskBytes`: best-effort disk bytes for this path only, using `st_blocks * 512` when available.
- `ChildrenLogicalBytes`, `ChildrenDiskBytes`: counted recursive child totals.
- `SubtreeLogicalBytes`, `SubtreeDiskBytes`: counted self plus children after hard-link de-dupe.
- `ModTime`: UTC modification time from `lstat`.
- `Device`, `Inode`, `LinkCount`: filesystem identity fields when available.
- `HardLinkDuplicate`: true when a regular file's `(device,inode)` was already counted.
- `Children`: JSON-ready hierarchy for future visualization.
- `Err`: non-fatal issue attached to this entry, such as symlink skip, max depth, or unreadable directory.

### ScanResult

- `SchemaVersion`: artifact schema version, currently `1`.
- `Root`, `StartedAt`, `FinishedAt`, `Options`: scan identity and normalized options.
- `LogicalBytes`, `DiskBytes`: aggregate counted root totals.
- `RootEntry`: full tree root.
- `TopDirs`, `TopFiles`: retained top entries without children.
- `Errors`: non-fatal traversal errors/skips.
- `Explain`: user-facing caveats for hidden/unaccounted space and APFS accounting.

### ScanError

- `Path`: path affected by the skip/error.
- `Op`: operation such as `lstat`, `readdir`, or `skip`.
- `Kind`: `permission_denied`, `excluded`, `max_depth`, `symlink_skipped`, `one_file_system`, `lstat_error`, or `readdir_error`.
- `Err`: human-readable reason.
- `Pattern`: exclude pattern when applicable.
- `Depth`: depth where the issue occurred.

## Traversal Rules

- Uses `os.Lstat`, never `os.Stat`.
- Symlink targets are never followed. The symlink path can appear as an `Entry`, but no target bytes or children are traversed.
- Permission errors are recorded in `Errors` and, when tied to an entry, in `Entry.Err`; they do not fail the whole scan.
- Excluded entries are skipped before `lstat` and do not contribute to totals.
- Depth cutoffs record `max_depth` and leave child traversal empty.
- `OneFileSystem` records `one_file_system` skips when device IDs differ from the root device.

## Size Accounting

- Logical bytes come from `lstat.Size()`.
- Disk bytes come from `st_blocks * 512` when available; fallback is logical bytes.
- Regular-file hard links are counted once by `(device,inode)`.
- Duplicate hard-link entries remain visible but contribute `0` subtree bytes and set `HardLinkDuplicate`.
- APFS clone/shared extent accounting is best-effort. `st_blocks` may overstate uniquely reclaimable bytes across cloned files.

## Explain Output Requirements

`explain` output and JSON `Explain` notes include:

- logical vs disk byte distinction;
- APFS clone caveat;
- APFS hidden-space caveat for restricted paths, other users' homes, metadata, and unscannable areas;
- APFS purgeable-space caveat for caches, swap, sleep images, and temporary files;
- local Time Machine snapshot caveat;
- permission-denied/excluded/one-file-system notes when those events occur.

V1 does not force purgeable-space cleanup.

## Artifact Permissions

- JSON artifacts are versioned with `schemaVersion`.
- `WriteJSONArtifact` creates artifact directories with `0700`.
- JSON files are written and chmodded to `0600`.
- Artifacts are read-only scan outputs and have no cleanup executor coupling.
