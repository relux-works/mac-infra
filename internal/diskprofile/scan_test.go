package diskprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScanAggregatesFixtureTreeAndRanksTopEntries(t *testing.T) {
	root := t.TempDir()
	fixture := scanFixture{
		dirs: []string{
			"Applications",
			"Logs",
			"Logs/archive",
		},
		files: []fixtureFile{
			{path: "Applications/xcode-cache.bin", size: 16 * 1024},
			{path: "Applications/simulator-cache.bin", size: 8 * 1024},
			{path: "Logs/archive/old.log", size: 2 * 1024},
			{path: "Logs/current.log", size: 1024},
			{path: "notes.txt", size: 512},
		},
	}
	fixture.write(t, root)

	result, err := Scan(context.Background(), ScanOptions{
		Root:                   root,
		MaxDepth:               -1,
		Limit:                  10,
		DisableDefaultExcludes: true,
	})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	apps := childByName(t, result.RootEntry, "Applications")
	logs := childByName(t, result.RootEntry, "Logs")
	xcodeCache := childByName(t, apps, "xcode-cache.bin")
	simulatorCache := childByName(t, apps, "simulator-cache.bin")
	if apps.ChildrenLogicalBytes != xcodeCache.SubtreeLogicalBytes+simulatorCache.SubtreeLogicalBytes {
		t.Fatalf("Applications children logical = %d, want child sum %d", apps.ChildrenLogicalBytes, xcodeCache.SubtreeLogicalBytes+simulatorCache.SubtreeLogicalBytes)
	}

	archive := childByName(t, logs, "archive")
	currentLog := childByName(t, logs, "current.log")
	if logs.ChildrenLogicalBytes != archive.SubtreeLogicalBytes+currentLog.SubtreeLogicalBytes {
		t.Fatalf("Logs children logical = %d, want child sum %d", logs.ChildrenLogicalBytes, archive.SubtreeLogicalBytes+currentLog.SubtreeLogicalBytes)
	}

	var rootChildTotal int64
	for _, child := range result.RootEntry.Children {
		rootChildTotal += child.SubtreeLogicalBytes
	}
	if result.RootEntry.ChildrenLogicalBytes != rootChildTotal {
		t.Fatalf("root children logical = %d, want child sum %d", result.RootEntry.ChildrenLogicalBytes, rootChildTotal)
	}
	if result.RootEntry.SubtreeLogicalBytes != result.RootEntry.LogicalBytes+result.RootEntry.ChildrenLogicalBytes {
		t.Fatalf("root subtree logical = %d, want own + children %d", result.RootEntry.SubtreeLogicalBytes, result.RootEntry.LogicalBytes+result.RootEntry.ChildrenLogicalBytes)
	}

	if len(result.TopFiles) < 3 {
		t.Fatalf("top files = %#v, want at least 3 entries", result.TopFiles)
	}
	if result.TopFiles[0].Name != "xcode-cache.bin" || result.TopFiles[1].Name != "simulator-cache.bin" || result.TopFiles[2].Name != "old.log" {
		t.Fatalf("top files order = %#v, want xcode-cache.bin, simulator-cache.bin, old.log", namesOf(result.TopFiles))
	}
	if len(result.TopDirs) == 0 || result.TopDirs[0].Name != "Applications" {
		t.Fatalf("top dirs order = %#v, want Applications first", namesOf(result.TopDirs))
	}
}

func TestRenderTopTextPrintsConciseTable(t *testing.T) {
	result := ScanResult{
		TopDirs: []Entry{{
			Path:                "/tmp/profile/Applications",
			Kind:                EntryKindDirectory,
			SubtreeLogicalBytes: 2048,
			SubtreeDiskBytes:    4096,
		}},
		TopFiles: []Entry{{
			Path:                "/tmp/profile/Applications/cache.bin",
			Kind:                EntryKindFile,
			SubtreeLogicalBytes: 1024,
			SubtreeDiskBytes:    4096,
		}},
	}

	var out bytes.Buffer
	RenderTopText(&out, result, true, false)
	text := out.String()
	for _, want := range []string{"== top directories ==", "LOGICAL", "DISK", "PATH", "2.0KB", "/tmp/profile/Applications"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered table missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "top files") {
		t.Fatalf("rendered table unexpectedly includes files:\n%s", text)
	}
}

func TestScanSkipsSymlinksWithoutFollowingTargets(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "target-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	result, err := Scan(context.Background(), ScanOptions{Root: root, MaxDepth: -1, Limit: 10})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	entry := childByName(t, result.RootEntry, "target-link")
	if entry.Kind != EntryKindSymlink {
		t.Fatalf("symlink kind = %s, want %s", entry.Kind, EntryKindSymlink)
	}
	if entry.Err != "symlink not followed" {
		t.Fatalf("symlink err = %q, want not followed", entry.Err)
	}
	if len(entry.Children) != 0 {
		t.Fatalf("symlink children = %d, want 0", len(entry.Children))
	}
	if !hasScanError(result.Errors, ScanErrorSymlinkSkipped, link) {
		t.Fatalf("missing symlink skipped error in %#v", result.Errors)
	}
}

func TestScanRecordsExcludedPathsAndLeavesThemOutOfTree(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "keep.txt"), "keep")
	mustMkdir(t, filepath.Join(root, "skip"))
	mustWriteFile(t, filepath.Join(root, "skip", "hidden.txt"), "hidden")

	result, err := Scan(context.Background(), ScanOptions{
		Root:     root,
		MaxDepth: -1,
		Limit:    10,
		Excludes: []string{"skip"},
	})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	if childExists(result.RootEntry, "skip") {
		t.Fatalf("excluded directory is present in root children: %#v", result.RootEntry.Children)
	}
	if !hasScanError(result.Errors, ScanErrorExcluded, filepath.Join(root, "skip")) {
		t.Fatalf("missing excluded error in %#v", result.Errors)
	}
	if !hasExplainCode(result.Explain, "excluded_paths") {
		t.Fatalf("missing excluded_paths explain note in %#v", result.Explain)
	}
}

func TestScanAppliesDefaultExcludes(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWriteFile(t, filepath.Join(root, "node_modules", "dep.js"), "generated")
	mustWriteFile(t, filepath.Join(root, "keep.txt"), "keep")

	result, err := Scan(context.Background(), ScanOptions{Root: root, MaxDepth: -1, Limit: 10})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	if childExists(result.RootEntry, "node_modules") {
		t.Fatalf("default-excluded directory is present in root children: %#v", result.RootEntry.Children)
	}
	if !hasScanError(result.Errors, ScanErrorExcluded, filepath.Join(root, "node_modules")) {
		t.Fatalf("missing default excluded error in %#v", result.Errors)
	}
	if !hasExplainCode(result.Explain, "excluded_paths") {
		t.Fatalf("missing excluded_paths explain note in %#v", result.Explain)
	}
}

func TestScanCanDisableDefaultExcludes(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWriteFile(t, filepath.Join(root, "node_modules", "dep.js"), "generated")

	result, err := Scan(context.Background(), ScanOptions{
		Root:                   root,
		MaxDepth:               -1,
		Limit:                  10,
		DisableDefaultExcludes: true,
	})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	if !childExists(result.RootEntry, "node_modules") {
		t.Fatalf("node_modules missing with default excludes disabled: %#v", result.RootEntry.Children)
	}
	if hasScanError(result.Errors, ScanErrorExcluded, filepath.Join(root, "node_modules")) {
		t.Fatalf("unexpected excluded error with default excludes disabled: %#v", result.Errors)
	}
}

func TestScanAppliesDepthLimitBeforeReadingChildren(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "level1"))
	mustWriteFile(t, filepath.Join(root, "level1", "level2.txt"), "hidden by depth")

	result, err := Scan(context.Background(), ScanOptions{Root: root, MaxDepth: 1, Limit: 10})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	level1 := childByName(t, result.RootEntry, "level1")
	if len(level1.Children) != 0 {
		t.Fatalf("depth-limited child count = %d, want 0", len(level1.Children))
	}
	if !hasScanError(result.Errors, ScanErrorMaxDepth, filepath.Join(root, "level1")) {
		t.Fatalf("missing max depth error in %#v", result.Errors)
	}
}

func TestScanDedupesHardLinksByDeviceAndInode(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original.txt")
	linked := filepath.Join(root, "linked.txt")
	mustWriteFile(t, original, "12345")
	if err := os.Link(original, linked); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}

	result, err := Scan(context.Background(), ScanOptions{Root: root, MaxDepth: -1, Limit: 10})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	originalEntry := childByName(t, result.RootEntry, "original.txt")
	linkedEntry := childByName(t, result.RootEntry, "linked.txt")
	if originalEntry.Inode == 0 || linkedEntry.Inode == 0 || originalEntry.Inode != linkedEntry.Inode {
		t.Fatalf("hard-link inode mismatch: original=%#v linked=%#v", originalEntry, linkedEntry)
	}
	counted := []Entry{originalEntry, linkedEntry}
	var countedTotal int64
	var duplicateCount int
	for _, entry := range counted {
		countedTotal += entry.SubtreeLogicalBytes
		if entry.HardLinkDuplicate {
			duplicateCount++
		}
	}
	if countedTotal != 5 {
		t.Fatalf("counted hard-link logical bytes = %d, want 5", countedTotal)
	}
	if duplicateCount != 1 {
		t.Fatalf("hard-link duplicate count = %d, want 1", duplicateCount)
	}
}

func TestScanStopsOnContextCancellationDuringWalk(t *testing.T) {
	root := t.TempDir()
	const dirCount = 25
	const filesPerDir = 4
	populateSyntheticTree(t, root, dirCount, filesPerDir)
	ctx := &cancelAfterContext{after: 20}

	result, err := Scan(ctx, ScanOptions{
		Root:                   root,
		MaxDepth:               -1,
		Limit:                  10,
		DisableDefaultExcludes: true,
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scan error = %v, want context.Canceled", err)
	}
	if !hasScanErrorKind(result.Errors, ScanErrorCanceled) {
		t.Fatalf("missing canceled error in %#v", result.Errors)
	}
	if !hasExplainCode(result.Explain, "scan_canceled") {
		t.Fatalf("missing scan_canceled explain note in %#v", result.Explain)
	}
	fullEntryCount := 1 + dirCount + dirCount*filesPerDir
	if result.VisitedEntries >= fullEntryCount {
		t.Fatalf("visited entries = %d, want less than full tree %d after cancellation", result.VisitedEntries, fullEntryCount)
	}
}

func TestScanRetainsBoundedTreeAndTopLists(t *testing.T) {
	root := t.TempDir()
	populateSyntheticTree(t, root, 30, 3)

	result, err := Scan(context.Background(), ScanOptions{
		Root:                   root,
		MaxDepth:               -1,
		Limit:                  5,
		MaxRetainedEntries:     12,
		DisableDefaultExcludes: true,
	})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	if result.RetainedEntries > 12 {
		t.Fatalf("retained entries = %d, want <= 12", result.RetainedEntries)
	}
	if result.OmittedEntries == 0 {
		t.Fatalf("omitted entries = 0, want retention limit to omit tree entries")
	}
	if result.VisitedEntries <= result.RetainedEntries {
		t.Fatalf("visited entries = %d, retained = %d; want more visited than retained", result.VisitedEntries, result.RetainedEntries)
	}
	if result.RootEntry.ChildrenOmitted == 0 {
		t.Fatalf("root children omitted = 0, want retained tree cutoff")
	}
	if len(result.TopDirs) > 5 {
		t.Fatalf("top dirs = %d, want <= 5", len(result.TopDirs))
	}
	if len(result.TopFiles) > 5 {
		t.Fatalf("top files = %d, want <= 5", len(result.TopFiles))
	}
	if !hasScanErrorKind(result.Errors, ScanErrorRetentionLimit) {
		t.Fatalf("missing retention limit error in %#v", result.Errors)
	}
	if result.LogicalBytes == 0 {
		t.Fatalf("logical bytes = 0, want counted bytes despite retained tree cutoff")
	}
}

func TestScanRecordsUnreadableDirectories(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "private")
	mustMkdir(t, privateDir)
	if err := os.Chmod(privateDir, 0); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chmod(privateDir, 0o700); err != nil {
			t.Logf("restore private dir mode: %v", err)
		}
	}()

	result, err := Scan(context.Background(), ScanOptions{Root: root, MaxDepth: -1, Limit: 10})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}
	if !hasScanError(result.Errors, ScanErrorPermissionDenied, privateDir) {
		if _, readErr := os.ReadDir(privateDir); readErr == nil {
			t.Skip("permission mode did not make directory unreadable for this test process")
		}
		t.Fatalf("missing permission denied error in %#v", result.Errors)
	}
	if !hasExplainCode(result.Explain, "permission_denied") {
		t.Fatalf("missing permission_denied explain note in %#v", result.Explain)
	}
}

func TestWriteJSONArtifactUsesRestrictivePermissionsAndSchemaVersion(t *testing.T) {
	root := t.TempDir()
	mustWriteFile(t, filepath.Join(root, "file.txt"), "data")
	result, err := Scan(context.Background(), ScanOptions{Root: root, MaxDepth: -1, Limit: 10})
	if err != nil {
		t.Fatalf("Scan error = %v", err)
	}

	artifactDir := filepath.Join(t.TempDir(), "artifacts")
	artifactPath := filepath.Join(artifactDir, "scan.json")
	if err := WriteJSONArtifact(artifactPath, result); err != nil {
		t.Fatalf("WriteJSONArtifact error = %v", err)
	}

	dirInfo, err := os.Stat(artifactDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("artifact dir mode = %#o, want 0700", got)
	}
	fileInfo, err := os.Stat(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("artifact file mode = %#o, want 0600", got)
	}

	data, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("artifact json: %v", err)
	}
	if decoded.SchemaVersion != SchemaVersion {
		t.Fatalf("schemaVersion = %d, want %d", decoded.SchemaVersion, SchemaVersion)
	}
	if !hasExplainCode(decoded.Explain, "apfs_clone_caveat") || !hasExplainCode(decoded.Explain, "time_machine_snapshots") {
		t.Fatalf("missing APFS explain caveats: %#v", decoded.Explain)
	}
}

func BenchmarkScanSyntheticLargeTree(b *testing.B) {
	root := b.TempDir()
	populateSyntheticTree(b, root, 80, 20)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := Scan(context.Background(), ScanOptions{
			Root:                   root,
			MaxDepth:               -1,
			Limit:                  20,
			MaxRetainedEntries:     128,
			DisableDefaultExcludes: true,
		})
		if err != nil {
			b.Fatalf("Scan error = %v", err)
		}
		if result.RetainedEntries > 128 {
			b.Fatalf("retained entries = %d, want <= 128", result.RetainedEntries)
		}
	}
}

func mustMkdir(t testing.TB, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t testing.TB, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func populateSyntheticTree(t testing.TB, root string, dirCount, filesPerDir int) {
	t.Helper()
	for i := 0; i < dirCount; i++ {
		dir := filepath.Join(root, fmt.Sprintf("dir-%03d", i))
		mustMkdir(t, dir)
		for j := 0; j < filesPerDir; j++ {
			mustWriteFile(t, filepath.Join(dir, fmt.Sprintf("file-%03d.dat", j)), fmt.Sprintf("payload-%03d-%03d", i, j))
		}
	}
}

type scanFixture struct {
	dirs  []string
	files []fixtureFile
}

type fixtureFile struct {
	path string
	size int
}

func (f scanFixture) write(t testing.TB, root string) {
	t.Helper()
	for _, dir := range f.dirs {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range f.files {
		path := filepath.Join(root, file.path)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, file.size), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func childByName(t *testing.T, parent Entry, name string) Entry {
	t.Helper()
	for _, child := range parent.Children {
		if child.Name == name {
			return child
		}
	}
	t.Fatalf("missing child %q in %#v", name, parent.Children)
	return Entry{}
}

func childExists(parent Entry, name string) bool {
	for _, child := range parent.Children {
		if child.Name == name {
			return true
		}
	}
	return false
}

func namesOf(entries []Entry) []string {
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name)
	}
	return names
}

func hasScanError(errors []ScanError, kind ScanErrorKind, path string) bool {
	for _, scanErr := range errors {
		if scanErr.Kind == kind && scanErr.Path == path {
			return true
		}
	}
	return false
}

func hasScanErrorKind(errors []ScanError, kind ScanErrorKind) bool {
	for _, scanErr := range errors {
		if scanErr.Kind == kind {
			return true
		}
	}
	return false
}

func hasExplainCode(notes []ExplainNote, code string) bool {
	for _, note := range notes {
		if note.Code == code {
			return true
		}
	}
	return false
}

type cancelAfterContext struct {
	after  int
	checks int
}

func (c *cancelAfterContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (c *cancelAfterContext) Done() <-chan struct{} {
	return nil
}

func (c *cancelAfterContext) Err() error {
	c.checks++
	if c.checks > c.after {
		return context.Canceled
	}
	return nil
}

func (c *cancelAfterContext) Value(any) any {
	return nil
}
