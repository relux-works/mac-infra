package diskprofile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type inodeKey struct {
	device uint64
	inode  uint64
}

type scanner struct {
	opts                   ScanOptions
	rootDev                uint64
	hardLinks              map[inodeKey]bool
	errors                 []ScanError
	topDirs                []Entry
	topFiles               []Entry
	deviceInfo             bool
	visitedEntries         int
	retainedEntries        int
	omittedEntries         int
	retentionLimitRecorded bool
	canceledRecorded       bool
}

func Scan(ctx context.Context, opts ScanOptions) (ScanResult, error) {
	opts = normalizeOptions(opts)
	started := time.Now().UTC()
	if err := ctx.Err(); err != nil {
		result := ScanResult{
			SchemaVersion: SchemaVersion,
			Root:          opts.Root,
			StartedAt:     started,
			FinishedAt:    time.Now().UTC(),
			Options:       opts,
			Errors: []ScanError{{
				Path: opts.Root,
				Op:   "scan",
				Kind: ScanErrorCanceled,
				Err:  err.Error(),
			}},
			Explain: defaultExplainNotes(nil),
		}
		result.Explain = defaultExplainNotes(result.Errors)
		return result, err
	}

	rootInfo, err := os.Lstat(opts.Root)
	if err != nil {
		return ScanResult{
			SchemaVersion: SchemaVersion,
			Root:          opts.Root,
			StartedAt:     started,
			FinishedAt:    time.Now().UTC(),
			Options:       opts,
			Errors: []ScanError{{
				Path: opts.Root,
				Op:   "lstat",
				Kind: classifyStatError(err),
				Err:  err.Error(),
			}},
			Explain: defaultExplainNotes(nil),
		}, fmt.Errorf("scan root: %w", err)
	}

	rootDev, _, _, _, hasDevice := statFields(rootInfo)
	s := scanner{
		opts:       opts,
		rootDev:    rootDev,
		hardLinks:  make(map[inodeKey]bool),
		deviceInfo: hasDevice,
	}
	s.reserveRetainedEntry()

	rootEntry := s.walk(ctx, opts.Root, rootInfo, 0, true)
	result := ScanResult{
		SchemaVersion:   SchemaVersion,
		Root:            opts.Root,
		StartedAt:       started,
		FinishedAt:      time.Now().UTC(),
		Options:         opts,
		LogicalBytes:    rootEntry.SubtreeLogicalBytes,
		DiskBytes:       rootEntry.SubtreeDiskBytes,
		VisitedEntries:  s.visitedEntries,
		RetainedEntries: s.retainedEntries,
		OmittedEntries:  s.omittedEntries,
		RootEntry:       rootEntry,
		TopDirs:         limitEntries(s.topDirs, opts.Limit),
		TopFiles:        limitEntries(s.topFiles, opts.Limit),
		Errors:          s.errors,
	}
	result.Explain = defaultExplainNotes(result.Errors)
	return result, ctx.Err()
}

func normalizeOptions(opts ScanOptions) ScanOptions {
	if strings.TrimSpace(opts.Root) == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			opts.Root = home
		} else {
			opts.Root = "."
		}
	}
	if abs, err := filepath.Abs(opts.Root); err == nil {
		opts.Root = abs
	} else {
		opts.Root = filepath.Clean(opts.Root)
	}
	if opts.Limit <= 0 {
		opts.Limit = DefaultLimit
	}
	if opts.Limit > MaxRetainedTopEntries {
		opts.Limit = MaxRetainedTopEntries
	}
	if opts.MaxRetainedEntries <= 0 {
		opts.MaxRetainedEntries = DefaultMaxRetainedEntries
	}
	if opts.MaxRetainedEntries > MaxRetainedEntriesLimit {
		opts.MaxRetainedEntries = MaxRetainedEntriesLimit
	}
	opts.Excludes = effectiveExcludes(opts.Excludes, opts.DisableDefaultExcludes)
	return opts
}

func effectiveExcludes(explicit []string, disableDefaults bool) []string {
	var out []string
	if !disableDefaults {
		out = append(out, DefaultExcludes...)
	}
	for _, patternText := range explicit {
		patternText = strings.TrimSpace(patternText)
		if patternText == "" {
			continue
		}
		out = append(out, patternText)
	}
	return append([]string(nil), out...)
}

func (s *scanner) walk(ctx context.Context, pathName string, info os.FileInfo, depth int, retainTree bool) Entry {
	s.visitedEntries++
	if !retainTree {
		s.omittedEntries++
	}

	entry := entryFromInfo(pathName, info)
	if err := ctx.Err(); err != nil {
		entry.Err = err.Error()
		s.recordCanceled(pathName, depth, err)
		return entry
	}
	if depth > 0 && s.opts.OneFileSystem && s.deviceInfo && entry.Device != 0 && entry.Device != s.rootDev {
		entry.Err = "outside root filesystem"
		entry.SubtreeLogicalBytes = 0
		entry.SubtreeDiskBytes = 0
		s.record(ScanError{
			Path:  pathName,
			Op:    "skip",
			Kind:  ScanErrorOneFileSystem,
			Err:   "outside root filesystem",
			Depth: depth,
		})
		return entry
	}

	entry.SubtreeLogicalBytes = entry.LogicalBytes
	entry.SubtreeDiskBytes = entry.DiskBytes
	if entry.Kind == EntryKindFile && entry.LinkCount > 1 && entry.Device != 0 && entry.Inode != 0 {
		key := inodeKey{device: entry.Device, inode: entry.Inode}
		if s.hardLinks[key] {
			entry.HardLinkDuplicate = true
			entry.SubtreeLogicalBytes = 0
			entry.SubtreeDiskBytes = 0
		} else {
			s.hardLinks[key] = true
		}
	}

	switch entry.Kind {
	case EntryKindSymlink:
		entry.Err = "symlink not followed"
		s.record(ScanError{
			Path:  pathName,
			Op:    "skip",
			Kind:  ScanErrorSymlinkSkipped,
			Err:   "symlink not followed",
			Depth: depth,
		})
	case EntryKindDirectory:
		if s.opts.MaxDepth >= 0 && depth >= s.opts.MaxDepth {
			entry.Err = "max depth reached"
			s.record(ScanError{
				Path:  pathName,
				Op:    "skip",
				Kind:  ScanErrorMaxDepth,
				Err:   "max depth reached",
				Depth: depth,
			})
			break
		}
		if err := ctx.Err(); err != nil {
			entry.Err = err.Error()
			s.recordCanceled(pathName, depth, err)
			break
		}
		children, err := os.ReadDir(pathName)
		if err != nil {
			entry.Err = err.Error()
			s.record(ScanError{
				Path:  pathName,
				Op:    "readdir",
				Kind:  classifyReadDirError(err),
				Err:   err.Error(),
				Depth: depth,
			})
			break
		}
		for _, child := range children {
			if err := ctx.Err(); err != nil {
				entry.Err = err.Error()
				s.recordCanceled(pathName, depth, err)
				break
			}
			childPath := filepath.Join(pathName, child.Name())
			if pattern, ok := matchesExclude(s.opts.Root, childPath, child.Name(), s.opts.Excludes); ok {
				s.record(ScanError{
					Path:    childPath,
					Op:      "skip",
					Kind:    ScanErrorExcluded,
					Err:     "excluded by pattern",
					Pattern: pattern,
					Depth:   depth + 1,
				})
				continue
			}
			if err := ctx.Err(); err != nil {
				entry.Err = err.Error()
				s.recordCanceled(childPath, depth+1, err)
				break
			}
			childInfo, err := os.Lstat(childPath)
			if err != nil {
				s.record(ScanError{
					Path:  childPath,
					Op:    "lstat",
					Kind:  classifyStatError(err),
					Err:   err.Error(),
					Depth: depth + 1,
				})
				continue
			}
			retainChild := retainTree && s.reserveRetainedEntry()
			if retainTree && !retainChild {
				entry.ChildrenOmitted++
				s.recordRetentionLimit(childPath, depth+1)
			}
			childEntry := s.walk(ctx, childPath, childInfo, depth+1, retainChild)
			if retainChild {
				entry.Children = append(entry.Children, childEntry)
			}
			entry.ChildrenLogicalBytes += childEntry.SubtreeLogicalBytes
			entry.ChildrenDiskBytes += childEntry.SubtreeDiskBytes
			if ctx.Err() != nil {
				break
			}
		}
		entry.SubtreeLogicalBytes += entry.ChildrenLogicalBytes
		entry.SubtreeDiskBytes += entry.ChildrenDiskBytes
	}

	if depth > 0 {
		switch entry.Kind {
		case EntryKindDirectory:
			s.topDirs = retainTopEntry(s.topDirs, entryWithoutChildren(entry), s.opts.Limit)
		case EntryKindFile:
			s.topFiles = retainTopEntry(s.topFiles, entryWithoutChildren(entry), s.opts.Limit)
		}
	}
	return entry
}

func entryFromInfo(pathName string, info os.FileInfo) Entry {
	device, inode, linkCount, diskBytes, _ := statFields(info)
	kind := EntryKindOther
	mode := info.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		kind = EntryKindSymlink
	case mode.IsDir():
		kind = EntryKindDirectory
	case mode.IsRegular():
		kind = EntryKindFile
	}
	return Entry{
		Path:         pathName,
		Name:         filepath.Base(pathName),
		Kind:         kind,
		LogicalBytes: info.Size(),
		DiskBytes:    diskBytes,
		ModTime:      info.ModTime().UTC(),
		Device:       device,
		Inode:        inode,
		LinkCount:    linkCount,
	}
}

func statFields(info os.FileInfo) (device uint64, inode uint64, linkCount uint64, diskBytes int64, ok bool) {
	diskBytes = info.Size()
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, 0, diskBytes, false
	}
	if stat.Blocks > 0 {
		diskBytes = stat.Blocks * 512
	}
	return uint64(stat.Dev), uint64(stat.Ino), uint64(stat.Nlink), diskBytes, true
}

func matchesExclude(root, pathName, name string, patterns []string) (string, bool) {
	if len(patterns) == 0 {
		return "", false
	}
	rel, err := filepath.Rel(root, pathName)
	if err != nil {
		rel = pathName
	}
	rel = filepath.ToSlash(rel)
	for _, patternText := range patterns {
		patternText = strings.TrimSpace(patternText)
		if patternText == "" {
			continue
		}
		slashPattern := filepath.ToSlash(patternText)
		if ok, _ := path.Match(slashPattern, rel); ok {
			return patternText, true
		}
		if ok, _ := path.Match(slashPattern, filepath.ToSlash(name)); ok {
			return patternText, true
		}
		if slashPattern == rel || slashPattern == filepath.ToSlash(name) {
			return patternText, true
		}
	}
	return "", false
}

func classifyStatError(err error) ScanErrorKind {
	if errors.Is(err, os.ErrPermission) {
		return ScanErrorPermissionDenied
	}
	return ScanErrorLstat
}

func classifyReadDirError(err error) ScanErrorKind {
	if errors.Is(err, os.ErrPermission) {
		return ScanErrorPermissionDenied
	}
	return ScanErrorReadDir
}

func (s *scanner) record(err ScanError) {
	s.errors = append(s.errors, err)
}

func (s *scanner) reserveRetainedEntry() bool {
	if s.retainedEntries >= s.opts.MaxRetainedEntries {
		return false
	}
	s.retainedEntries++
	return true
}

func (s *scanner) recordCanceled(pathName string, depth int, err error) {
	if s.canceledRecorded {
		return
	}
	s.canceledRecorded = true
	s.record(ScanError{
		Path:  pathName,
		Op:    "scan",
		Kind:  ScanErrorCanceled,
		Err:   err.Error(),
		Depth: depth,
	})
}

func (s *scanner) recordRetentionLimit(pathName string, depth int) {
	if s.retentionLimitRecorded {
		return
	}
	s.retentionLimitRecorded = true
	s.record(ScanError{
		Path:  pathName,
		Op:    "retain",
		Kind:  ScanErrorRetentionLimit,
		Err:   "retained entry limit reached",
		Depth: depth,
	})
}

func entryWithoutChildren(entry Entry) Entry {
	entry.Children = nil
	return entry
}

func limitEntries(entries []Entry, limit int) []Entry {
	if limit <= 0 {
		limit = DefaultLimit
	}
	out := append([]Entry(nil), entries...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SubtreeLogicalBytes == out[j].SubtreeLogicalBytes {
			return out[i].Path < out[j].Path
		}
		return out[i].SubtreeLogicalBytes > out[j].SubtreeLogicalBytes
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func retainTopEntry(entries []Entry, entry Entry, limit int) []Entry {
	if limit <= 0 {
		limit = DefaultLimit
	}
	entries = append(entries, entry)
	if len(entries) <= limit*2 {
		return entries
	}
	return limitEntries(entries, limit)
}
