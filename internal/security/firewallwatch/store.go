package firewallwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type Entry struct {
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Count        uint64    `json:"count"`
	WindowStart  time.Time `json:"window_start"`
	Denies       int       `json:"denies"`
	SpikeEmitted bool      `json:"spike_emitted"`
}
type SignerEntry struct {
	Value    string    `json:"value"`
	LastSeen time.Time `json:"last_seen"`
}

type State struct {
	Entries            map[string]*Entry      `json:"entries"`
	Events             []Event                `json:"events"`
	Signers            map[string]SignerEntry `json:"signers"`
	Parser             ALFParser              `json:"alf"`
	NettopUnrecognized uint64                 `json:"nettop_unrecognized"`
	LastEvent          time.Time              `json:"last_event"`
	BackendHealthy     bool                   `json:"backend_healthy"`
	Updated            time.Time              `json:"updated"`
	NettopError        string                 `json:"nettop_error,omitempty"`
}
type Store struct {
	Config Config
	State  State
}

func safeDir(dir string) error {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	s, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !s.IsDir() || s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm() != 0700 || !ok || int(st.Uid) != os.Getuid() {
		return errors.New("state dir must be owned by caller, non-symlink and mode 0700")
	}
	return nil
}
func safeExisting(path string) error {
	s, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !s.Mode().IsRegular() || s.Mode().Perm() != 0600 || !ok || int(st.Uid) != os.Getuid() || st.Nlink != 1 {
		return errors.New("state artifacts must be private regular files, without links")
	}
	return nil
}
func OpenStore(c Config) (*Store, error) {
	if e := safeDir(c.StateDir); e != nil {
		return nil, e
	}
	s := &Store{Config: c}
	path := filepath.Join(c.StateDir, "state.json")
	if e := safeExisting(path); e != nil {
		return nil, e
	}
	raw, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(raw, &s.State); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	if s.State.Entries == nil {
		s.State.Entries = map[string]*Entry{}
	}
	if s.State.Signers == nil {
		s.State.Signers = map[string]SignerEntry{}
	}
	s.prune(time.Now())
	return s, nil
}
func atomicWrite(path string, data []byte) error {
	if e := safeExisting(path); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".watch-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func (s *Store) Lock() (func(), error) {
	path := filepath.Join(s.Config.StateDir, "watch.lock")
	if e := safeExisting(path); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("watcher already running")
	}
	return func() { f.Close() }, nil
}
func key(it Item) string {
	p := 0
	if port(it) != nil {
		p = *port(it)
	}
	raw, _ := json.Marshal([]any{it.Source, it.App, it.Verdict, p, it.Remote})
	return string(raw)
}
func cleanItem(it Item) Item { it.App = Sanitize(it.App); it.Signer = Sanitize(it.Signer); return it }

// Observe counts repeats and emits at most one spike per fixed per-key window.
func (s *Store) Observe(it Item, now time.Time, classify func(Item) Decision) []Event {
	it = cleanItem(it)
	s.prune(now)
	k := key(it)
	entry, exists := s.State.Entries[k]
	if !exists {
		entry = &Entry{FirstSeen: now, WindowStart: now}
		s.State.Entries[k] = entry
	}
	entry.LastSeen = now
	entry.Count++
	spike := false
	if it.Verdict != "allow" && it.Verdict != "observed" && it.Verdict != "unknown" {
		if !now.Before(entry.WindowStart.Add(duration(s.Config.DenySpikeWindow))) {
			entry.WindowStart = now
			entry.Denies = 0
			entry.SpikeEmitted = false
		}
		entry.Denies++
		if entry.Denies >= s.Config.DenySpikeCount && !entry.SpikeEmitted {
			entry.SpikeEmitted = true
			spike = true
		}
	}
	var events []Event
	add := func(item Item) {
		d := classify(item)
		event := Event{TS: now, Source: it.Source, App: it.App, Signer: it.Signer, Verdict: it.Verdict, Port: port(it), RemoteClass: it.Remote, Bucket: it.Bucket, Counts: entry.Count, Label: d.Label, Reason: d.Reason, Mode: "shadow"}
		if d.Reason == "knn" {
			event.Reason = struct {
				Kind       string      `json:"kind"`
				Neighbours []Neighbour `json:"neighbours"`
			}{Kind: d.Reason, Neighbours: d.Neighbours}
		}
		events = append(events, event)
		s.State.Events = append(s.State.Events, event)
		s.State.LastEvent = now
	}
	if !exists {
		add(it)
	}
	if spike {
		it.Spike = true
		add(it)
	}
	s.prune(now)
	return events
}
func (s *Store) prune(now time.Time) {
	cutoff := now.Add(-time.Duration(s.Config.RetentionDays) * 24 * time.Hour)
	for k, v := range s.State.Entries {
		if v.LastSeen.Before(cutoff) {
			delete(s.State.Entries, k)
		}
	}
	if len(s.State.Entries) > s.Config.MaxEntries {
		keys := make([]string, 0, len(s.State.Entries))
		for k := range s.State.Entries {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := s.State.Entries[keys[i]], s.State.Entries[keys[j]]
			if a.LastSeen.Equal(b.LastSeen) {
				return keys[i] < keys[j]
			}
			return a.LastSeen.Before(b.LastSeen)
		})
		for _, k := range keys[:len(keys)-s.Config.MaxEntries] {
			delete(s.State.Entries, k)
		}
	}
	events := s.State.Events[:0]
	for _, e := range s.State.Events {
		if !e.TS.Before(cutoff) {
			events = append(events, e)
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	if len(events) > s.Config.MaxEntries {
		events = events[len(events)-s.Config.MaxEntries:]
	}
	s.State.Events = append([]Event(nil), events...)
	// Keep executable signature cache bounded as well; evicted paths may be inspected again.
	if len(s.State.Signers) > s.Config.MaxEntries {
		keys := make([]string, 0, len(s.State.Signers))
		for k := range s.State.Signers {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			a, b := s.State.Signers[keys[i]], s.State.Signers[keys[j]]
			if a.LastSeen.Equal(b.LastSeen) {
				return keys[i] < keys[j]
			}
			return a.LastSeen.Before(b.LastSeen)
		})
		for _, k := range keys[:len(keys)-s.Config.MaxEntries] {
			delete(s.State.Signers, k)
		}
	}
}
func (s *Store) Save(now time.Time) error {
	if e := safeDir(s.Config.StateDir); e != nil {
		return e
	}
	s.prune(now)
	s.State.Updated = now
	data, e := json.Marshal(s.State)
	if e != nil {
		return e
	}
	if e = atomicWrite(filepath.Join(s.Config.StateDir, "state.json"), data); e != nil {
		return e
	}
	// Daily files are atomic projections of authoritative state: crash/retry cannot
	// append duplicates. Retention also caps the total event count across days.
	days := map[string][]byte{}
	for _, event := range s.State.Events {
		day := event.TS.UTC().Format("2006-01-02")
		line, e := json.Marshal(event)
		if e != nil {
			return e
		}
		days[day] = append(days[day], append(line, '\n')...)
	}
	for day, data := range days {
		if e = atomicWrite(filepath.Join(s.Config.StateDir, "events-"+day+".jsonl"), data); e != nil {
			return e
		}
	}
	files, e := filepath.Glob(filepath.Join(s.Config.StateDir, "events-*.jsonl"))
	if e != nil {
		return e
	}
	for _, path := range files {
		day := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), "events-"), ".jsonl")
		if _, ok := days[day]; !ok {
			if e = safeExisting(path); e != nil {
				return e
			}
			if e = os.Remove(path); e != nil {
				return e
			}
		}
	}
	if !s.State.LastEvent.IsZero() {
		flagPath := filepath.Join(s.Config.StateDir, "new-events.flag")
		if e = safeExisting(flagPath); e != nil {
			return e
		}
		stamp := []byte(s.State.LastEvent.Format(time.RFC3339Nano) + "\n")
		existing, readErr := os.ReadFile(flagPath)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return readErr
		}
		if bytes.Equal(existing, stamp) {
			return nil
		}
		return atomicWrite(flagPath, stamp)
	}
	return nil
}

type DigestGroup struct {
	Count int      `json:"count"`
	Apps  []string `json:"apps"`
}

func (s *Store) Digest(since time.Time) map[string]DigestGroup {
	result := map[string]DigestGroup{}
	for _, label := range []string{"noise", "digest", "decide"} {
		seen := map[string]bool{}
		g := DigestGroup{Apps: []string{}}
		for _, e := range s.State.Events {
			if !e.TS.Before(since) && e.Label == label {
				g.Count++
				seen[e.App] = true
			}
		}
		for app := range seen {
			g.Apps = append(g.Apps, app)
		}
		sort.Strings(g.Apps)
		result[label] = g
	}
	return result
}
func (s *Store) Status() map[string]any {
	return map[string]any{"entries": len(s.State.Entries), "events": len(s.State.Events), "signer_cache": len(s.State.Signers), "last_event": s.State.LastEvent, "backend_healthy": s.State.BackendHealthy, "health_as_of": s.State.Updated, "unrecognized": s.State.Parser.Unrecognized + s.State.NettopUnrecognized, "invalid_json": s.State.Parser.Invalid, "unrecognized_samples": s.State.Parser.Samples, "nettop_error": s.State.NettopError, "mode": "shadow"}
}
func (s *Store) String() string {
	return fmt.Sprintf("%d entries, %d retained events", len(s.State.Entries), len(s.State.Events))
}
