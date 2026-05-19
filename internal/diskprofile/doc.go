// Package diskprofile defines the read-only filesystem scan model used by
// mac-disk-profile.
//
// # Model contract
//
// ScanOptions controls one scan. Root is scanned with os.Lstat and is never
// excluded by Excludes. MaxDepth is relative to Root: 0 means only Root, 1 means
// Root plus direct children, and a negative value means unlimited traversal.
// Limit controls retained TopDirs and TopFiles; non-positive values use the
// package default and very large values are capped by MaxRetainedTopEntries.
// MaxRetainedEntries limits the retained JSON hierarchy so large trees can be
// counted without storing every visited path in memory. Excludes are
// slash-separated glob patterns matched against an entry path relative to Root
// and, separately, against the entry base name. DefaultExcludes skip noisy
// generated trees unless DisableDefaultExcludes is set. OneFileSystem keeps
// traversal on Root's device when device IDs are available.
//
// Entry is JSON-friendly and keeps per-path bytes separate from recursive
// totals. LogicalBytes and DiskBytes are the lstat apparent bytes and best-effort
// st_blocks*512 bytes for the entry itself. SubtreeLogicalBytes and
// SubtreeDiskBytes are the counted recursive totals after hard-link de-dupe by
// (device,inode). Directories store child totals in ChildrenLogicalBytes and
// ChildrenDiskBytes so a future treemap/TUI can render hierarchy without
// coupling to cleanup code. When MaxRetainedEntries is reached, later entries
// are omitted from Children but still contribute to aggregate bytes and retained
// top lists. Symlinks are represented as entries but are never followed.
//
// ScanResult is versioned with SchemaVersion and contains the root entry,
// aggregate totals, retained top lists, non-fatal traversal errors/skips, and
// explain notes. JSON artifacts can contain sensitive paths, so WriteJSONArtifact
// writes files as 0600 and creates artifact directories as 0700.
//
// ScanError records non-fatal traversal issues: permission denied, excluded
// paths, depth cutoffs, skipped symlinks, one-file-system boundaries, retention
// cutoffs, cancellation, and stat or read errors. Permission errors are reported
// and do not fail the whole scan. Context cancellation returns the context error
// with a partial result.
//
// # Size-accounting caveats
//
// mac-disk-profile uses os.Lstat, never Stat, so symlink targets do not affect
// size. Logical bytes come from lstat size. Disk bytes come from stat blocks when
// the platform exposes them, otherwise they fall back to logical bytes. Hard
// links are counted once per device/inode. APFS clones and sparse files can still
// surprise users: st_blocks is best-effort and may not fully express shared clone
// extents across files.
//
// Explain output must stay honest about hidden/unaccounted space. On APFS, used
// space can include restricted paths, other users' homes, filesystem metadata,
// local Time Machine snapshots, purgeable caches, swap/sleep images, and other
// data outside a normal user-level scan. V1 reports these as caveats only; it
// does not force purgeable-space cleanup.
package diskprofile
