// Package policyjournal observes policy-file metadata without opening policy files
// for reading. Filesystem notifications may coalesce; this is not a lossless audit.
package policyjournal

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

var Names = [...]string{"remote-settings.json", "policy-limits.json"}

// MetadataFS deliberately has no content-reading or file-opening operation.
type MetadataFS interface {
	Lstat(string) (fs.FileInfo, error)
	ReadDir(string) ([]fs.DirEntry, error)
}

type OSMetadata struct{}

func (OSMetadata) Lstat(p string) (fs.FileInfo, error)     { return os.Lstat(p) }
func (OSMetadata) ReadDir(p string) ([]fs.DirEntry, error) { return os.ReadDir(p) }

func inode(i fs.FileInfo) uint64 { return i.Sys().(*syscall.Stat_t).Ino }

type Record struct {
	At    string  `json:"at"`
	Kind  string  `json:"kind"`
	Home  string  `json:"home,omitempty"`
	File  string  `json:"file,omitempty"`
	State string  `json:"state,omitempty"`
	Size  *int64  `json:"size,omitempty"`
	Mtime string  `json:"mtime,omitempty"`
	Inode *uint64 `json:"inode,omitempty"`
}

type Snapshot struct {
	State string
	Size  int64
	Mtime time.Time
	Inode uint64
}

func Inspect(f MetadataFS, p string) Snapshot {
	i, err := f.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return Snapshot{State: "absent"}
	}
	if err != nil {
		return Snapshot{State: "unavailable"}
	}
	if !i.Mode().IsRegular() {
		return Snapshot{State: "unsupported"}
	}
	return Snapshot{State: "present", Size: i.Size(), Mtime: i.ModTime(), Inode: inode(i)}
}

// Discover reads directory entries only at the declared home locations. It never
// traverses projects, sessions or other native-home contents. Extra homes must be
// declared explicitly for arbitrary CLAUDE_CONFIG_DIR layouts.
func Discover(f MetadataFS, user string, extra []string) (homes, dirs []string, gaps bool) {
	seenH, seenD := map[string]bool{}, map[string]bool{}
	addDir := func(p string) bool {
		// Reject directory symlinks at every component, including an extra home's
		// ancestors; never traverse a link into another native home.
		for parent := filepath.Dir(p); ; parent = filepath.Dir(parent) {
			i, e := f.Lstat(parent)
			if e != nil || !i.IsDir() || i.Mode()&fs.ModeSymlink != 0 {
				gaps = true
				return false
			}
			if parent == filepath.Dir(parent) {
				break
			}
		}
		i, e := f.Lstat(p)
		if errors.Is(e, fs.ErrNotExist) {
			return false
		}
		if e != nil || !i.IsDir() || i.Mode()&fs.ModeSymlink != 0 {
			gaps = true
			return false
		}
		if !seenD[p] {
			dirs = append(dirs, p)
			seenD[p] = true
		}
		return true
	}
	addHome := func(p string) {
		if addDir(p) && !seenH[p] {
			homes = append(homes, p)
			seenH[p] = true
		}
	}
	addDir(user)
	addHome(filepath.Join(user, ".claude"))
	curator := filepath.Join(user, ".curator")
	root := filepath.Join(curator, "environments")
	if addDir(curator) && addDir(root) {
		entries, e := f.ReadDir(root)
		if e != nil {
			gaps = true
		} else {
			for _, ent := range entries {
				if !ent.IsDir() {
					if ent.Type()&fs.ModeSymlink != 0 {
						gaps = true
					}
					continue
				}
				p := filepath.Join(root, ent.Name())
				if addDir(p) {
					addHome(filepath.Join(p, "claude_code"))
				}
			}
		}
	}
	for _, p := range extra {
		addHome(p)
	}
	sort.Strings(homes)
	sort.Strings(dirs)
	return
}

type Observer struct {
	FS       MetadataFS
	Writer   io.Writer
	previous map[string]Snapshot
}

func (o *Observer) Emit(r Record) error { return json.NewEncoder(o.Writer).Encode(r) }

// Scan records baselines, metadata deltas, and file notifications even if the
// sampled fields compare equal (e.g. same-size writes with restored mtime).
func (o *Observer) Scan(at time.Time, homes []string, notified map[string]bool) ([]string, error) {
	if o.previous == nil {
		o.previous = map[string]Snapshot{}
	}
	current := map[string]Snapshot{}
	var files []string
	for _, home := range homes {
		for _, name := range Names {
			p := filepath.Join(home, name)
			s := Inspect(o.FS, p)
			current[p] = s
			old, ok := o.previous[p]
			kind := "baseline"
			if ok {
				kind = "metadata_change"
			}
			if ok && old == s {
				if !notified[p] {
					continue
				}
				kind = "file_event"
			}
			r := Record{At: at.UTC().Format(time.RFC3339Nano), Kind: kind, Home: home, File: name, State: s.State}
			if s.State == "present" {
				size, ino := s.Size, s.Inode
				r.Size = &size
				r.Inode = &ino
			}
			if !s.Mtime.IsZero() {
				r.Mtime = s.Mtime.UTC().Format(time.RFC3339Nano)
			}
			if e := o.Emit(r); e != nil {
				return nil, e
			}
		}
	}
	for p := range o.previous {
		if _, ok := current[p]; !ok {
			if e := o.Emit(Record{At: at.UTC().Format(time.RFC3339Nano), Kind: "home_unavailable", Home: filepath.Dir(p), File: filepath.Base(p), State: "unavailable"}); e != nil {
				return nil, e
			}
		}
	}
	o.previous = current
	for p, s := range current {
		if s.State == "present" {
			files = append(files, p)
		}
	}
	sort.Strings(files)
	return files, nil
}
