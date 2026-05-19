package diskprofile

import "time"

const (
	SchemaVersion             = 1
	DefaultLimit              = 20
	MaxRetainedTopEntries     = 1000
	DefaultMaxRetainedEntries = 10000
	MaxRetainedEntriesLimit   = 50000
)

var DefaultExcludes = []string{
	".git",
	".hg",
	".svn",
	".temp",
	".build",
	"build",
	"dist",
	"node_modules",
	".dart_tool",
	".pytest_cache",
	".mypy_cache",
	".ruff_cache",
	"coverage",
	"DerivedData",
}

type EntryKind string

const (
	EntryKindDirectory EntryKind = "directory"
	EntryKindFile      EntryKind = "file"
	EntryKindSymlink   EntryKind = "symlink"
	EntryKindOther     EntryKind = "other"
)

type ScanErrorKind string

const (
	ScanErrorPermissionDenied ScanErrorKind = "permission_denied"
	ScanErrorExcluded         ScanErrorKind = "excluded"
	ScanErrorMaxDepth         ScanErrorKind = "max_depth"
	ScanErrorSymlinkSkipped   ScanErrorKind = "symlink_skipped"
	ScanErrorOneFileSystem    ScanErrorKind = "one_file_system"
	ScanErrorLstat            ScanErrorKind = "lstat_error"
	ScanErrorReadDir          ScanErrorKind = "readdir_error"
	ScanErrorCanceled         ScanErrorKind = "canceled"
	ScanErrorRetentionLimit   ScanErrorKind = "retention_limit"
)

type ExplainNote struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ScanOptions struct {
	Root                   string   `json:"root"`
	MaxDepth               int      `json:"maxDepth"`
	Limit                  int      `json:"limit"`
	MaxRetainedEntries     int      `json:"maxRetainedEntries"`
	Excludes               []string `json:"excludes,omitempty"`
	DisableDefaultExcludes bool     `json:"disableDefaultExcludes,omitempty"`
	OneFileSystem          bool     `json:"oneFileSystem"`
}

type Entry struct {
	Path                 string    `json:"path"`
	Name                 string    `json:"name"`
	Kind                 EntryKind `json:"kind"`
	LogicalBytes         int64     `json:"logicalBytes"`
	DiskBytes            int64     `json:"diskBytes"`
	ChildrenLogicalBytes int64     `json:"childrenLogicalBytes"`
	ChildrenDiskBytes    int64     `json:"childrenDiskBytes"`
	SubtreeLogicalBytes  int64     `json:"subtreeLogicalBytes"`
	SubtreeDiskBytes     int64     `json:"subtreeDiskBytes"`
	ModTime              time.Time `json:"modTime"`
	Device               uint64    `json:"device,omitempty"`
	Inode                uint64    `json:"inode,omitempty"`
	LinkCount            uint64    `json:"linkCount,omitempty"`
	HardLinkDuplicate    bool      `json:"hardLinkDuplicate,omitempty"`
	Children             []Entry   `json:"children,omitempty"`
	ChildrenOmitted      int       `json:"childrenOmitted,omitempty"`
	Err                  string    `json:"err,omitempty"`
}

type ScanError struct {
	Path    string        `json:"path"`
	Op      string        `json:"op"`
	Kind    ScanErrorKind `json:"kind"`
	Err     string        `json:"err"`
	Pattern string        `json:"pattern,omitempty"`
	Depth   int           `json:"depth,omitempty"`
}

type ScanResult struct {
	SchemaVersion   int           `json:"schemaVersion"`
	Root            string        `json:"root"`
	StartedAt       time.Time     `json:"startedAt"`
	FinishedAt      time.Time     `json:"finishedAt"`
	Options         ScanOptions   `json:"options"`
	LogicalBytes    int64         `json:"logicalBytes"`
	DiskBytes       int64         `json:"diskBytes"`
	VisitedEntries  int           `json:"visitedEntries"`
	RetainedEntries int           `json:"retainedEntries"`
	OmittedEntries  int           `json:"omittedEntries"`
	RootEntry       Entry         `json:"rootEntry"`
	TopDirs         []Entry       `json:"topDirs,omitempty"`
	TopFiles        []Entry       `json:"topFiles,omitempty"`
	Errors          []ScanError   `json:"errors,omitempty"`
	Explain         []ExplainNote `json:"explain,omitempty"`
}
