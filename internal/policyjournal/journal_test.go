package policyjournal

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func put(t *testing.T, p, s string) {
	t.Helper()
	if e := os.WriteFile(p, []byte(s), 0600); e != nil {
		t.Fatal(e)
	}
}
func home(t *testing.T, root string) string {
	t.Helper()
	p := filepath.Join(root, ".claude")
	if e := os.Mkdir(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}

func privateRoot(t *testing.T) string {
	t.Helper()
	p, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	return p
}

// Proves metadata transitions and exact schema with content sentinels: production
// observation has only Lstat/ReadDir capability and neither prints nor reads bytes.
func TestMetadataOnlyTransitions(t *testing.T) {
	r := t.TempDir()
	h := home(t, r)
	p := filepath.Join(h, Names[0])
	var b bytes.Buffer
	o := Observer{FS: OSMetadata{}, Writer: &b}
	now := time.Now()
	scan := func() {
		t.Helper()
		if _, e := o.Scan(now, []string{h}, nil); e != nil {
			t.Fatal(e)
		}
	}
	scan()
	put(t, p, "SECRET_SENTINEL_NEVER_JOURNAL_1")
	scan()
	put(t, p, "SECRET_SENTINEL_NEVER_JOURNAL_2_LONGER")
	scan()
	tmp := filepath.Join(h, "replacement")
	put(t, tmp, "SECRET_REPLACEMENT")
	if e := os.Rename(tmp, p); e != nil {
		t.Fatal(e)
	}
	scan()
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	scan()
	if strings.Contains(b.String(), "SECRET") {
		t.Fatal("policy bytes escaped")
	}
	var states []string
	dec := json.NewDecoder(&b)
	for dec.More() {
		var m map[string]any
		if e := dec.Decode(&m); e != nil {
			t.Fatal(e)
		}
		for k := range m {
			switch k {
			case "at", "kind", "home", "file", "state", "size", "mtime", "inode":
			default:
				t.Fatalf("forbidden key %s", k)
			}
		}
		if m["file"] == Names[0] {
			states = append(states, m["state"].(string))
		}
	}
	if strings.Join(states, ",") != "absent,present,present,present,absent" {
		t.Fatal(states)
	}
}

// Proves a notification is retained even when the allowed sampled fields match.
func TestSameMetadataFileEvent(t *testing.T) {
	r := t.TempDir()
	h := home(t, r)
	p := filepath.Join(h, Names[0])
	put(t, p, "one")
	var b bytes.Buffer
	o := Observer{FS: OSMetadata{}, Writer: &b}
	_, _ = o.Scan(time.Now(), []string{h}, nil)
	b.Reset()
	_, e := o.Scan(time.Now(), []string{h}, map[string]bool{p: true})
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b.String(), `"kind":"file_event"`) {
		t.Fatal(b.String())
	}
}

// Proves only the supported home topology is enumerated, new managed homes are
// found, and private sessions/projects/unrelated contents are never traversed.
type tracedFS struct {
	OSMetadata
	dirs  []string
	stats []string
}

func (f *tracedFS) ReadDir(p string) ([]fs.DirEntry, error) {
	f.dirs = append(f.dirs, p)
	return f.OSMetadata.ReadDir(p)
}
func (f *tracedFS) Lstat(p string) (fs.FileInfo, error) {
	f.stats = append(f.stats, p)
	return f.OSMetadata.Lstat(p)
}
func TestDiscoveryScope(t *testing.T) {
	r := privateRoot(t)
	h := home(t, r)
	managed := filepath.Join(r, ".curator", "environments", "own", "claude_code")
	if e := os.MkdirAll(filepath.Join(managed, "projects"), 0700); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(h, "credentials.json"), "SECRET")
	f := &tracedFS{}
	homes, _, _, gap := Discover(f, r, nil)
	if gap || len(homes) != 2 {
		t.Fatalf("%v %v", homes, gap)
	}
	if len(f.dirs) != 1 || f.dirs[0] != filepath.Join(r, ".curator", "environments") {
		t.Fatal(f.dirs)
	}
	for _, p := range f.stats {
		if strings.Contains(p, "projects") || strings.Contains(p, "credentials") {
			t.Fatal(p)
		}
	}
	newHome := filepath.Join(r, ".curator", "environments", "new", "claude_code")
	_ = os.MkdirAll(newHome, 0700)
	homes, _, _, gap = Discover(f, r, nil)
	if gap || len(homes) != 3 {
		t.Fatalf("%v %v", homes, gap)
	}
}

// Proves explicit extra homes are supported while directory aliases never
// redirect discovery, including a symlink in an ancestor component.
func TestDiscoveryExtraAndSymlink(t *testing.T) {
	r := privateRoot(t)
	h := home(t, r)
	extra := filepath.Join(r, "custom")
	_ = os.Mkdir(extra, 0700)
	homes, _, _, gap := Discover(OSMetadata{}, r, []string{extra})
	if gap || len(homes) != 2 {
		t.Fatalf("%v %v", homes, gap)
	}
	alias := filepath.Join(r, "alias")
	_ = os.Symlink(r, alias)
	homes, _, _, gap = Discover(OSMetadata{}, r, []string{filepath.Join(alias, "custom")})
	if !gap || len(homes) != 1 || homes[0] != h {
		t.Fatalf("%v %v", homes, gap)
	}
}

// Proves exact policy symlinks and special nodes never become regular metadata
// observations. The symlink target's metadata/content is not followed.
func TestPolicySymlinkRejected(t *testing.T) {
	r := t.TempDir()
	h := home(t, r)
	secret := filepath.Join(r, "secret")
	put(t, secret, "SECRET")
	p := filepath.Join(h, Names[0])
	if e := os.Symlink(secret, p); e != nil {
		t.Fatal(e)
	}
	if s := Inspect(OSMetadata{}, p); s.State != "unsupported" || s.Size != 0 || s.Inode != 0 {
		t.Fatal(s)
	}
}

// Proves zero-byte regular files retain a numeric zero size, while absent files
// have no invented size or inode metadata.
func TestEmptyAndAbsentFields(t *testing.T) {
	r := t.TempDir()
	h := home(t, r)
	put(t, filepath.Join(h, Names[0]), "")
	var b bytes.Buffer
	o := Observer{FS: OSMetadata{}, Writer: &b}
	_, e := o.Scan(time.Now(), []string{h}, nil)
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(&b)
	for d.More() {
		var m map[string]any
		if e = d.Decode(&m); e != nil {
			t.Fatal(e)
		}
		if m["state"] == "present" {
			if m["size"] != float64(0) || m["inode"] == nil {
				t.Fatal(m)
			}
		} else {
			if _, ok := m["size"]; ok {
				t.Fatal(m)
			}
		}
	}
}

// Proves declared-home visibility: an explicitly requested home that is absent
// below a valid parent is returned as missing with its parent watched, while a
// present one is a home, a regular file or symlink in its place is a coverage
// gap (not missing), and absent optional default homes stay silent.
func TestDeclaredHomeVisibility(t *testing.T) {
	r := privateRoot(t)
	declared := filepath.Join(r, "explicit-home")
	homes, dirs, missing, gap := Discover(OSMetadata{}, r, []string{declared})
	if gap || len(homes) != 0 || len(missing) != 1 || missing[0] != declared {
		t.Fatalf("absent: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
	watched := false
	for _, d := range dirs {
		watched = watched || d == r
	}
	if !watched {
		t.Fatalf("parent of a missing declared home is not watched: %v", dirs)
	}
	if e := os.Mkdir(declared, 0700); e != nil {
		t.Fatal(e)
	}
	homes, _, missing, gap = Discover(OSMetadata{}, r, []string{declared})
	if gap || len(homes) != 1 || homes[0] != declared || len(missing) != 0 {
		t.Fatalf("present: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
	_ = os.Remove(declared)
	put(t, declared, "not a directory")
	homes, _, missing, gap = Discover(OSMetadata{}, r, []string{declared})
	if !gap || len(homes) != 0 || len(missing) != 0 {
		t.Fatalf("regular file: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
	_ = os.Remove(declared)
	target := filepath.Join(r, "target")
	_ = os.Mkdir(target, 0700)
	if e := os.Symlink(target, declared); e != nil {
		t.Fatal(e)
	}
	homes, _, missing, gap = Discover(OSMetadata{}, r, []string{declared})
	if !gap || len(homes) != 0 || len(missing) != 0 {
		t.Fatalf("symlink: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
	// No declared home and no default directories: silent, not missing.
	empty := privateRoot(t)
	homes, _, missing, gap = Discover(OSMetadata{}, empty, nil)
	if gap || len(homes) != 0 || len(missing) != 0 {
		t.Fatalf("defaults: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
	// A missing parent is a gap, not a missing home: its path cannot be watched.
	homes, _, missing, gap = Discover(OSMetadata{}, r, []string{filepath.Join(r, "no-parent", "home")})
	if !gap || len(missing) != 0 {
		t.Fatalf("missing parent: missing=%v gap=%v", missing, gap)
	}
}

// Proves home_absent is emitted once per absence, not on every rescan, and
// again after the home was created (and baselined) and then removed.
func TestReportMissingLifecycle(t *testing.T) {
	r := privateRoot(t)
	declared := filepath.Join(r, "explicit-home")
	var out bytes.Buffer
	o := &Observer{FS: OSMetadata{}, Writer: &out}
	count := func() int { return strings.Count(out.String(), `"kind":"home_absent"`) }
	step := func() {
		t.Helper()
		homes, _, missing, _ := Discover(o.FS, r, []string{declared})
		if e := o.ReportMissing(time.Now(), missing); e != nil {
			t.Fatal(e)
		}
		if _, e := o.Scan(time.Now(), homes, nil); e != nil {
			t.Fatal(e)
		}
	}
	step()
	step()
	if count() != 1 || !strings.Contains(out.String(), `"home":"`+declared+`"`) {
		t.Fatalf("first absence: %s", out.String())
	}
	if e := os.Mkdir(declared, 0700); e != nil {
		t.Fatal(e)
	}
	step()
	if count() != 1 || !strings.Contains(out.String(), `"kind":"baseline"`) {
		t.Fatalf("creation not baselined: %s", out.String())
	}
	_ = os.Remove(declared)
	step()
	if count() != 2 {
		t.Fatalf("second absence not reported: %s", out.String())
	}
}

// Proves an unreadable declared home stays visible: a home whose directory
// denies search is still a home and each policy file is recorded as
// unavailable, and a declared home below an unreadable parent is a coverage gap,
// never a silent omission or a missing home. Restoring permissions recovers the
// normal absent baseline.
func TestDeclaredHomeUnreadable(t *testing.T) {
	r := privateRoot(t)
	declared := filepath.Join(r, "locked-home")
	if e := os.Mkdir(declared, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(declared, 0); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(declared, 0700)
	homes, _, missing, gap := Discover(OSMetadata{}, r, []string{declared})
	if gap || len(homes) != 1 || homes[0] != declared || len(missing) != 0 {
		t.Fatalf("unreadable home: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
	var out bytes.Buffer
	o := &Observer{FS: OSMetadata{}, Writer: &out}
	if _, e := o.Scan(time.Now(), homes, nil); e != nil {
		t.Fatal(e)
	}
	if strings.Count(out.String(), `"state":"unavailable"`) != len(Names) {
		t.Fatalf("unreadable home files not unavailable: %s", out.String())
	}
	_ = os.Chmod(declared, 0700)
	out.Reset()
	if _, e := o.Scan(time.Now(), homes, nil); e != nil {
		t.Fatal(e)
	}
	if strings.Count(out.String(), `"state":"absent"`) != len(Names) {
		t.Fatalf("recovery not recorded: %s", out.String())
	}
	parent := filepath.Join(r, "locked-parent")
	_ = os.Mkdir(parent, 0700)
	_ = os.Mkdir(filepath.Join(parent, "home"), 0700)
	if e := os.Chmod(parent, 0); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(parent, 0700)
	homes, _, missing, gap = Discover(OSMetadata{}, r, []string{filepath.Join(parent, "home")})
	if !gap || len(homes) != 0 || len(missing) != 0 {
		t.Fatalf("unreadable parent: homes=%v missing=%v gap=%v", homes, missing, gap)
	}
}
