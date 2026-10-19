package firewallwatch

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func intp(n int) *int { return &n }
func ruleClassify(it Item) Decision {
	d, ok := Rules(it)
	if !ok {
		return Decision{Label: "digest", Reason: "test"}
	}
	return d
}

// Repeats only update counters; ports distinguish keys; crossing the deny
// boundary produces one extra spike, with another possible in the next window.
func TestDedupSpike(t *testing.T) {
	c := testConfig(t)
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	it := Item{Source: "alf", App: "/a", Verdict: "deny", Remote: "lan", LocalPort: intp(80)}
	if got := s.Observe(it, now, ruleClassify); len(got) != 1 || got[0].Reason != "hard_non_allow" {
		t.Fatal(got)
	}
	if got := s.Observe(it, now.Add(time.Second), ruleClassify); len(got) != 0 {
		t.Fatal("threshold-1", got)
	}
	if got := s.Observe(it, now.Add(2*time.Second), ruleClassify); len(got) != 1 || got[0].Reason != "hard_deny_spike" || got[0].Counts != 3 {
		t.Fatal("threshold", got)
	}
	if got := s.Observe(it, now.Add(3*time.Second), ruleClassify); len(got) != 0 {
		t.Fatal("spike duplicated", got)
	}
	for i := 0; i < 3; i++ {
		got := s.Observe(it, now.Add(time.Minute+time.Duration(i)*time.Second), ruleClassify)
		if len(got) != map[bool]int{true: 1, false: 0}[i == 2] {
			t.Fatal(got)
		}
	}
	it.LocalPort = intp(81)
	if got := s.Observe(it, now.Add(2*time.Minute), ruleClassify); len(got) != 1 {
		t.Fatal(got)
	}
	entry := s.State.Entries[key(it)]
	if entry.Count != 1 || len(s.State.Entries) != 2 {
		t.Fatal(s.State)
	}
}

// State and daily events remain private, bounded and reloadable; replacement
// changes inode atomically, leaves old readers intact and leaves no temp files.
func TestStorePersistence(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 2
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		s.Observe(Item{Source: "nettop", App: "app", Verdict: "observed", Remote: "lan", RemotePort: intp(80 + i)}, now.Add(time.Duration(i)*time.Second), ruleClassify)
	}
	if len(s.State.Entries) != 2 || len(s.State.Events) != 2 {
		t.Fatal(s.State)
	}
	if e = s.Save(now); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(c.StateDir, "state.json")
	reader, e := os.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer reader.Close()
	old, _ := reader.Stat()
	flagBefore, _ := os.Stat(filepath.Join(c.StateDir, "new-events.flag"))
	s.State.BackendHealthy = true
	if e = s.Save(now); e != nil {
		t.Fatal(e)
	}
	flagAfter, _ := os.Stat(filepath.Join(c.StateDir, "new-events.flag"))
	if !os.SameFile(flagBefore, flagAfter) {
		t.Fatal("unchanged timestamp rewrote wake flag")
	}
	newInfo, _ := os.Stat(path)
	if os.SameFile(old, newInfo) {
		t.Fatal("no atomic replacement")
	}
	var oldState State
	if e = json.NewDecoder(reader).Decode(&oldState); e != nil || oldState.BackendHealthy {
		t.Fatal("old reader changed", e)
	}
	files, _ := os.ReadDir(c.StateDir)
	for _, f := range files {
		info, _ := f.Info()
		if info.Mode().Perm() != 0600 || strings.HasPrefix(f.Name(), ".watch-") {
			t.Fatal(f.Name(), info.Mode())
		}
	}
	dir, _ := os.Stat(c.StateDir)
	if dir.Mode().Perm() != 0700 {
		t.Fatal(dir.Mode())
	}
	loaded, e := OpenStore(c)
	if e != nil || len(loaded.State.Events) != 2 || !loaded.State.BackendHealthy {
		t.Fatal(e)
	}
	if e = s.Save(now.Add(8 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if len(s.State.Events) != 0 || len(s.State.Entries) != 0 {
		t.Fatal("age retention")
	}
	matches, _ := filepath.Glob(filepath.Join(c.StateDir, "events-*"))
	if len(matches) != 0 {
		t.Fatal("old files retained")
	}
}

// Directory symlinks, writable directories and linked state/flag targets fail
// without modifying their target; valid private directories remain accepted.
func TestUnsafeStore(t *testing.T) {
	for _, kind := range []string{"symlink_dir", "writable_dir", "state_symlink", "flag_symlink", "writable_file"} {
		t.Run(kind, func(t *testing.T) {
			c := testConfig(t)
			outside := filepath.Join(t.TempDir(), "protected")
			_ = os.WriteFile(outside, []byte("keep"), 0600)
			if kind == "symlink_dir" {
				target := t.TempDir()
				_ = os.Symlink(target, c.StateDir)
			} else {
				_ = os.Mkdir(c.StateDir, 0700)
			}
			switch kind {
			case "writable_dir":
				_ = os.Chmod(c.StateDir, 0720)
			case "state_symlink":
				_ = os.Symlink(outside, filepath.Join(c.StateDir, "state.json"))
			case "writable_file":
				_ = os.WriteFile(filepath.Join(c.StateDir, "state.json"), []byte(`{}`), 0620)
				_ = os.Chmod(filepath.Join(c.StateDir, "state.json"), 0620)
			}
			s, e := OpenStore(c)
			if kind == "flag_symlink" {
				if e != nil {
					t.Fatal(e)
				}
				_ = os.Symlink(outside, filepath.Join(c.StateDir, "new-events.flag"))
				s.State.LastEvent = time.Now()
				e = s.Save(time.Now())
			}
			if e == nil {
				t.Fatal("unsafe store accepted")
			}
			b, _ := os.ReadFile(outside)
			if string(b) != "keep" {
				t.Fatal("linked target changed")
			}
		})
	}
}

// Concurrent watchers are refused while read-only status/digest remain usable.
func TestStoreLockDigestPrivacy(t *testing.T) {
	s, e := OpenStore(testConfig(t))
	if e != nil {
		t.Fatal(e)
	}
	unlock, e := s.Lock()
	if e != nil {
		t.Fatal(e)
	}
	if u, e := s.Lock(); e == nil {
		u()
		t.Fatal("second lock acquired")
	}
	unlock()
	u, e := s.Lock()
	if e != nil {
		t.Fatal(e)
	}
	u()
	now := time.Now()
	s.Observe(Item{App: "app 93.184.216.34", Signer: "dev fd7a:115c:a1e0:abcd::67", Source: "nettop", Verdict: "observed", Remote: "lan"}, now, ruleClassify)
	if e = s.Save(now); e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(s.Digest(now.Add(-time.Minute)))
	state, _ := os.ReadFile(filepath.Join(s.Config.StateDir, "state.json"))
	for _, raw := range []string{"93.184.216.34", "fd7a:115c:a1e0:abcd::67"} {
		if strings.Contains(string(b)+string(state), raw) {
			t.Fatal("IP leaked")
		}
	}
	if s.Digest(now.Add(time.Second))["digest"].Count != 0 {
		t.Fatal("since ignored")
	}
}

// Oldest-seen eviction covers signature metadata as well as dedup entries;
// timestamp order, rather than append order, controls retained event eviction.
func TestOldestEviction(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 2
	s, e := OpenStore(c)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	s.State.Signers = map[string]SignerEntry{"z": {Value: "old", LastSeen: now.Add(-time.Hour)}, "a": {Value: "new", LastSeen: now}, "b": {Value: "new", LastSeen: now}}
	s.State.Events = []Event{{TS: now, App: "new1"}, {TS: now.Add(-time.Hour), App: "old"}, {TS: now.Add(time.Second), App: "new2"}}
	s.prune(now)
	if _, ok := s.State.Signers["z"]; ok {
		t.Fatal("oldest signer retained")
	}
	if len(s.State.Events) != 2 || s.State.Events[0].App != "new1" {
		t.Fatal("event eviction ignored timestamps")
	}
}

// kNN event reasons persist neighbour IDs and similarities and survive reload;
// the keeper need not infer the proposal from an opaque classifier label.
func TestNeighbourReasonRoundTrip(t *testing.T) {
	s, e := OpenStore(testConfig(t))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	s.Observe(Item{App: "app", Source: "nettop", Verdict: "observed", Remote: "lan"}, now, func(Item) Decision {
		return Decision{Label: "digest", Reason: "knn", Neighbours: []Neighbour{{ID: "pool1", Similarity: .9}}}
	})
	if e = s.Save(now); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(s.Config.StateDir, "events-"+now.UTC().Format("2006-01-02")+".jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), `"reason":{"kind":"knn","neighbours":[{"id":"pool1","similarity":0.9}]}`) {
		t.Fatal(string(raw))
	}
	loaded, e := OpenStore(s.Config)
	if e != nil || len(loaded.State.Events) != 1 {
		t.Fatal(e)
	}
}
