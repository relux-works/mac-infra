package security

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Entry struct {
	Source string `json:"source"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Mode   uint32 `json:"mode"`
}
type Coverage struct {
	Source string `json:"source"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type Snapshot struct {
	Schema     int        `json:"schema"`
	CapturedAt time.Time  `json:"captured_at"`
	Evidence   *Check     `json:"evidence,omitempty"`
	Entries    []Entry    `json:"entries"`
	Coverage   []Coverage `json:"coverage"`
}
type Drift struct {
	Schema     int       `json:"schema"`
	ComparedAt time.Time `json:"compared_at"`
	Added      []Entry   `json:"added"`
	Changed    []Entry   `json:"changed"`
	Removed    []Entry   `json:"removed"`
	Unknown    []string  `json:"unknown"`
}
type source struct{ name, path string }

func Persistence(ctx context.Context, r Runner, home string) (Snapshot, Check) {
	sources := []source{{"system-daemons", "/Library/LaunchDaemons"}, {"system-agents", "/Library/LaunchAgents"}, {"apple-daemons", "/System/Library/LaunchDaemons"}, {"apple-agents", "/System/Library/LaunchAgents"}, {"user-agents", filepath.Join(home, "Library/LaunchAgents")}, {"periodic", "/private/etc/periodic"}, {"cron-files", "/private/var/at/tabs"}, {"privileged-helpers", "/Library/PrivilegedHelperTools"}}
	snap := snapshotFiles(ctx, sources)
	for _, s := range []struct {
		name, path string
		args       []string
	}{{"login-items", "/usr/bin/sfltool", []string{"dumpbtm"}}, {"profiles", "/usr/bin/profiles", []string{"list", "-output", "stdout-xml"}}, {"system-extensions", "/usr/bin/systemextensionsctl", []string{"list"}}, {"user-cron", "/usr/bin/crontab", []string{"-l"}}} {
		data, err := r.Run(ctx, s.path, s.args...)
		if err != nil || len(strings.TrimSpace(string(data))) == 0 {
			snap.Coverage = append(snap.Coverage, Coverage{s.name, "unavailable", "Command unavailable, denied, empty or unsuccessful; absence is not established."})
			continue
		}
		// Only stable current-user crontab bytes are fingerprinted. The other
		// inventory commands have volatile or unprojected fields; do not manufacture
		// stable drift evidence from their raw output.
		if s.name == "user-cron" {
			snap.Entries = append(snap.Entries, Entry{s.name, "inventory", digest(data), 0})
			snap.Coverage = append(snap.Coverage, Coverage{s.name, "ok", "Current-user crontab content fingerprint only."})
		} else {
			snap.Coverage = append(snap.Coverage, Coverage{s.name, "partial", "Inventory command responded; stable identity projection is not yet supported, so volatile/raw data is excluded from drift."})
		}
	}
	c := Check{Name: "persistence", Status: "ok", Findings: []Finding{}, Data: map[string]any{"entries": len(snap.Entries), "coverage": snap.Coverage}}
	for _, v := range snap.Coverage {
		if v.Status != "ok" {
			c.Status = "partial"
			c.RequiresRoot = true
		}
	}
	c.Findings = append(c.Findings, finding(c.Name, "info", "scope", "Fixed system and current-user sources only; other users, loaded kernel extensions and non-system setuid scans are outside coverage. com.bsim entries excluded."))
	return snap, c
}
func snapshotFiles(ctx context.Context, sources []source) Snapshot {
	snap := Snapshot{Schema: 1, CapturedAt: time.Now().UTC(), Entries: []Entry{}, Coverage: []Coverage{}}
	for _, s := range sources {
		coverage := Coverage{s.name, "ok", ""}
		count := 0
		if !safeParents(filepath.Join(s.path, "child")) {
			if _, err := os.Lstat(s.path); os.IsNotExist(err) && safeParents(s.path) {
				coverage.Detail = "Source absent at collection time."
			} else {
				coverage.Status = "unavailable"
				coverage.Detail = "Source inaccessible or symlinked."
				if _, e := os.Lstat(s.path); os.IsPermission(e) {
					coverage.Detail = "permission_denied"
				}
			}
			snap.Coverage = append(snap.Coverage, coverage)
			continue
		}
		var walk func(string, int) error
		walk = func(dir string, depth int) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if depth > 32 {
				return errors.New("depth limit")
			}
			if !safeParents(filepath.Join(dir, "child")) {
				coverage.Status = "partial"
				return nil
			}
			f, e := os.Open(dir)
			if e != nil {
				coverage.Status = "partial"
				return nil
			}
			defer f.Close()
			for {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				entries, e := f.ReadDir(128)
				for _, d := range entries {
					count++
					if count > maxEntries {
						return errors.New("entry limit")
					}
					path := filepath.Join(dir, d.Name())
					if excluded(path) {
						continue
					}
					if d.Type()&os.ModeSymlink != 0 {
						coverage.Status = "partial"
						continue
					}
					if d.IsDir() {
						if err := walk(path, depth+1); err != nil {
							return err
						}
						continue
					}
					data, err := readFile(path)
					if err != nil {
						coverage.Status = "partial"
						continue
					}
					info, err := d.Info()
					if err != nil {
						coverage.Status = "partial"
						continue
					}
					rel, _ := filepath.Rel(s.path, path)
					snap.Entries = append(snap.Entries, Entry{s.name, rel, digest(data), uint32(info.Mode().Perm())})
				}
				if e == io.EOF {
					return nil
				}
				if e != nil {
					coverage.Status = "partial"
					return nil
				}
			}
		}
		err := walk(s.path, 0)
		if err != nil {
			coverage.Status = "partial"
		}
		if coverage.Status != "ok" && coverage.Detail == "" {
			coverage.Detail = "One or more entries inaccessible, unsupported, excluded by limits, or interrupted."
		}
		snap.Coverage = append(snap.Coverage, coverage)
	}
	sort.Slice(snap.Entries, func(i, j int) bool { return entryKey(snap.Entries[i]) < entryKey(snap.Entries[j]) })
	return snap
}
func entryKey(e Entry) string { return e.Source + "/" + e.Path }
func validateSnapshot(s Snapshot) error {
	if s.Schema != 1 || s.Coverage == nil || s.Entries == nil {
		return errors.New("invalid baseline schema")
	}
	cov := map[string]bool{}
	keys := map[string]bool{}
	for _, c := range s.Coverage {
		if c.Source == "" || cov[c.Source] || (c.Status != "ok" && c.Status != "partial" && c.Status != "unavailable") {
			return errors.New("invalid baseline coverage")
		}
		cov[c.Source] = true
	}
	for _, e := range s.Entries {
		k := entryKey(e)
		if !cov[e.Source] || keys[k] || e.Path == "" || filepath.IsAbs(e.Path) || filepath.Clean(e.Path) != e.Path || e.Path == ".." || strings.HasPrefix(e.Path, "../") || len(e.SHA256) != 64 || strings.Trim(e.SHA256, "0123456789abcdef") != "" || e.Mode > 0777 {
			return errors.New("invalid baseline entry")
		}
		keys[k] = true
	}
	return nil
}

// Compare never reports deletion or a clean source when either snapshot lacks
// complete coverage of that source. Visible additions/changes remain useful.
func Compare(old, current Snapshot) (Drift, error) {
	d := Drift{Schema: 1, ComparedAt: time.Now().UTC(), Added: []Entry{}, Changed: []Entry{}, Removed: []Entry{}, Unknown: []string{}}
	if err := validateSnapshot(old); err != nil {
		return d, err
	}
	if err := validateSnapshot(current); err != nil {
		return d, err
	}
	covOld := map[string]string{}
	covNew := map[string]string{}
	for _, c := range old.Coverage {
		covOld[c.Source] = c.Status
	}
	for _, c := range current.Coverage {
		covNew[c.Source] = c.Status
	}
	sources := map[string]bool{}
	for k := range covOld {
		sources[k] = true
	}
	for k := range covNew {
		sources[k] = true
	}
	for k := range sources {
		if covOld[k] != "ok" || covNew[k] != "ok" {
			d.Unknown = append(d.Unknown, k)
		}
	}
	prev := map[string]Entry{}
	now := map[string]Entry{}
	for _, e := range old.Entries {
		prev[entryKey(e)] = e
	}
	for _, e := range current.Entries {
		now[entryKey(e)] = e
		if p, ok := prev[entryKey(e)]; !ok {
			d.Added = append(d.Added, e)
		} else if p.SHA256 != e.SHA256 || p.Mode != e.Mode {
			d.Changed = append(d.Changed, e)
		}
	}
	for _, e := range old.Entries {
		if _, ok := now[entryKey(e)]; !ok && covOld[e.Source] == "ok" && covNew[e.Source] == "ok" {
			d.Removed = append(d.Removed, e)
		}
	}
	sort.Strings(d.Unknown)
	return d, nil
}
func LoadBaseline(path string) (Snapshot, error) {
	var s Snapshot
	data, err := readFile(path)
	if err != nil {
		return s, errors.New("cannot read baseline")
	}
	if strictJSON(data) != nil || requiredSnapshot(data) != nil {
		return s, errors.New("invalid baseline members")
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return s, errors.New("invalid baseline JSON")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return s, errors.New("trailing baseline data")
	}
	return s, validateSnapshot(s)
}
func SaveBaseline(path string, s Snapshot) error {
	if err := validateSnapshot(s); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if len(data) > maxFile {
		return errors.New("baseline too large")
	}
	if !safeParents(path) {
		return errors.New("baseline parent must exist without symlinks")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create baseline; destination must not exist")
	}
	_, writeErr := f.Write(append(data, '\n'))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		os.Remove(path)
		return fmt.Errorf("cannot write baseline")
	}
	return nil
}
