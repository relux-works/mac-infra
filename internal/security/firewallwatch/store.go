package firewallwatch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
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
	Escalated    []string  `json:"escalated,omitempty"`
}
type SignerEntry struct {
	Value     string    `json:"value"`
	Identity  string    `json:"identity"`
	Failed    bool      `json:"failed"`
	Inspected time.Time `json:"inspected"`
	LastSeen  time.Time `json:"last_seen"`
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
	// Coverage records when a watcher was running: a span opens at run start
	// and its end advances on every save, so a stop or crash leaves a gap.
	Coverage []CoverageSpan `json:"coverage"`
	// EvictedThrough is the newest timestamp of any event pruned from Events.
	EvictedThrough time.Time `json:"evicted_through"`
}

// CoverageSpan is one interval in which a watcher ran and saved state.
type CoverageSpan struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}
type Store struct {
	Config        Config
	State         State
	dirty         bool
	covering      bool
	collectionEnd atomic.Int64
	lastSave      time.Time
	dayHashes     map[string][32]byte
	atomicWrite   func(string, []byte) error
	inspectSigner func(context.Context, string) (string, error)
	clock         func() time.Time
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
	f, e := os.Open(path)
	if e == nil {
		raw, readErr := io.ReadAll(io.LimitReader(f, c.MaxStateBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if int64(len(raw)) > c.MaxStateBytes {
			return nil, errors.New("corrupt state: max_state_bytes exceeded")
		}
		if e = json.Unmarshal(raw, &s.State); e != nil {
			return nil, fmt.Errorf("corrupt state: %w", e)
		}
		if e = s.validateState(); e != nil {
			return nil, fmt.Errorf("corrupt state: %w", e)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	} else {
		s.State.Entries = map[string]*Entry{}
		s.State.Signers = map[string]SignerEntry{}
	}
	s.prune(time.Now())
	return s, nil
}

// validateState runs before pruning or dereferencing any loaded entry.
func (s *Store) validateState() error {
	st := s.State
	bad := func() error { return errors.New("invalid structure, count or field") }
	if st.Entries == nil || st.Signers == nil || len(st.Entries) > s.Config.MaxEntries || len(st.Events) > s.Config.MaxEntries || len(st.Signers) > s.Config.MaxEntries || len(st.Coverage) > s.Config.MaxEntries || len(st.Parser.Samples) > SampleLimit {
		return bad()
	}
	for k, v := range st.Entries {
		if len(k) == 0 || len(k) > 8192 || v == nil || v.Count == 0 || v.Count > math.MaxInt64 || v.Denies < 0 || uint64(v.Denies) > v.Count || v.FirstSeen.IsZero() || v.LastSeen.Before(v.FirstSeen) || v.WindowStart.IsZero() || v.WindowStart.After(v.LastSeen) || len(v.Escalated) > 32 {
			return bad()
		}
		seen := map[string]bool{}
		for _, r := range v.Escalated {
			if len(r) == 0 || len(r) > 128 || seen[r] {
				return bad()
			}
			seen[r] = true
		}
	}
	for k, v := range st.Signers {
		if len(k) == 0 || len(k) > 1024 || len(v.Value) > 1024 || len(v.Identity) > 1024 || v.LastSeen.IsZero() {
			return bad()
		}
	}
	for _, v := range st.Parser.Samples {
		if !persistedText(v, 256) {
			return bad()
		}
	}
	if len(st.NettopError) > 1024 {
		return bad()
	}
	for _, v := range st.Coverage {
		if v.Start.IsZero() || v.End.Before(v.Start) {
			return bad()
		}
	}
	for _, v := range st.Events {
		if v.TS.IsZero() || !validLabel(v.Label) || v.Mode != "shadow" || (v.Source != "alf" && v.Source != "nettop") || !persistedText(v.App, 1024) || !persistedText(v.Signer, 1024) || len(v.Verdict) > 128 || len(v.RemoteClass) > 128 || len(v.Bucket) > 128 || v.Counts == 0 || v.Counts > math.MaxInt64 || (v.Port != nil && (*v.Port < 1 || *v.Port > 65535)) {
			return bad()
		}
		b, e := json.Marshal(v.Reason)
		if e != nil || len(b) > 65536 || v.Reason == nil {
			return bad()
		}
	}
	return nil
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
	s.dirty = true
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
	add := func(item Item, d Decision) {
		if d.Label == "decide" && !item.Spike {
			found := false
			for _, r := range entry.Escalated {
				if r == d.Reason {
					found = true
				}
			}
			if !found {
				entry.Escalated = append(entry.Escalated, d.Reason)
			}
		}
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
		add(it, classify(it))
	} else if d, ok := Rules(it); ok && d.Label == "decide" {
		found := false
		for _, r := range entry.Escalated {
			if r == d.Reason {
				found = true
			}
		}
		if !found {
			add(it, d)
		}
	}
	if spike {
		it.Spike = true
		add(it, classify(it))
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
	evicted := func(e Event) {
		if e.TS.After(s.State.EvictedThrough) {
			s.State.EvictedThrough = e.TS
		}
	}
	events := s.State.Events[:0]
	for _, e := range s.State.Events {
		if !e.TS.Before(cutoff) {
			events = append(events, e)
		} else {
			evicted(e)
		}
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].TS.Before(events[j].TS) })
	if len(events) > s.Config.MaxEntries {
		for _, e := range events[:len(events)-s.Config.MaxEntries] {
			evicted(e)
		}
		events = events[len(events)-s.Config.MaxEntries:]
	}
	s.State.Events = append([]Event(nil), events...)
	// Dropping old coverage only widens reported gaps, never hides one.
	spans := s.State.Coverage[:0]
	for _, v := range s.State.Coverage {
		if !v.End.Before(cutoff) {
			spans = append(spans, v)
		}
	}
	if len(spans) > s.Config.MaxEntries {
		spans = spans[len(spans)-s.Config.MaxEntries:]
	}
	s.State.Coverage = append([]CoverageSpan(nil), spans...)
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
func (s *Store) write(path string, data []byte) error {
	if s.atomicWrite != nil {
		return s.atomicWrite(path, data)
	}
	return atomicWrite(path, data)
}

// Flush saves emitted events immediately; silent updates wait for an interval,
// a nettop tick, or shutdown. Failed writes retain dirty state for a retry.
func (s *Store) Flush(now time.Time, emitted, force bool) error {
	if !s.dirty && !force {
		return nil
	}
	if !emitted && !force && !s.lastSave.IsZero() && now.Before(s.lastSave.Add(duration(s.Config.SaveInterval))) {
		return nil
	}
	return s.Save(now)
}

// BeginCoverage opens a coverage span for a running watcher; every later Save
// extends it to the save time until EndCoverage.
func (s *Store) BeginCoverage(now time.Time) {
	s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: now, End: now})
	s.covering = true
}

// EndCoverage records when collection stopped. It may be called from the
// collector goroutine while the run loop is still busy; the next Save caps
// the span there and no later Save extends it. The first call wins.
func (s *Store) EndCoverage(at time.Time) {
	s.collectionEnd.CompareAndSwap(0, at.UnixNano())
}
func (s *Store) Save(now time.Time) error {
	if e := safeDir(s.Config.StateDir); e != nil {
		return e
	}
	if n := len(s.State.Coverage); s.covering && n > 0 {
		end := now
		if ended := s.collectionEnd.Load(); ended != 0 {
			if at := time.Unix(0, ended); at.Before(end) {
				end = at
			}
			s.covering = false
		}
		if end.After(s.State.Coverage[n-1].End) {
			s.State.Coverage[n-1].End = end
		}
	}
	s.prune(now)
	s.State.Updated = now
	if e := s.validateState(); e != nil {
		return fmt.Errorf("refusing invalid state save: %w", e)
	}
	data, e := json.Marshal(s.State)
	if e != nil {
		return e
	}
	if int64(len(data)) > s.Config.MaxStateBytes {
		return errors.New("state exceeds max_state_bytes")
	}
	if e = s.write(filepath.Join(s.Config.StateDir, "state.json"), data); e != nil {
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
	if s.dayHashes == nil {
		s.dayHashes = map[string][32]byte{}
	}
	for day, data := range days {
		path := filepath.Join(s.Config.StateDir, "events-"+day+".jsonl")
		if e = safeExisting(path); e != nil {
			return e
		}
		h := sha256.Sum256(data)
		previous, ok := s.dayHashes[day]
		if !ok {
			if f, err := os.Open(path); err == nil {
				b, err := io.ReadAll(io.LimitReader(f, s.Config.MaxStateBytes+1))
				f.Close()
				if err != nil {
					return err
				}
				previous = sha256.Sum256(b)
				ok = true
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if !ok || h != previous {
			if e = s.write(path, data); e != nil {
				return e
			}
		}
		s.dayHashes[day] = h
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
			delete(s.dayHashes, day)
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
		if !bytes.Equal(existing, stamp) {
			if e = s.write(flagPath, stamp); e != nil {
				return e
			}
		}
	}
	s.dirty = false
	s.lastSave = now
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
