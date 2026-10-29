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
	"sync"
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
	Netfilter          NetfilterParser        `json:"netfilter"`
	NetfilterError     string                 `json:"netfilter_error,omitempty"`
	NettopUnrecognized uint64                 `json:"nettop_unrecognized"`
	LastEvent          time.Time              `json:"last_event"`
	BackendHealthy     bool                   `json:"backend_healthy"`
	Updated            time.Time              `json:"updated"`
	NettopError        string                 `json:"nettop_error,omitempty"`
	// Coverage records when a watcher was running: a span opens at run start
	// and its end advances on every save, so a stop or crash leaves a gap.
	Coverage []CoverageSpan `json:"coverage"`
	// CoverageVersion distinguishes migrated history from spans whose gaps
	// record stall causes. Zero is the pre-marker format.
	CoverageVersion int `json:"coverage_version"`
	// EvictedThrough is the newest timestamp of any event pruned from Events.
	EvictedThrough         time.Time `json:"evicted_through"`
	CoverageEvictedThrough time.Time `json:"coverage_evicted_through"`
	Health                 RunHealth `json:"health"`
}

// CoverageSpan is one interval in which a watcher collected one source and
// saved state. Source is empty for the ALF log (the original source) and
// "netfilter" for the content-filter stream. Under count pressure, short
// stalls within the interval may be represented by counters instead of gaps.
type CoverageSpan struct {
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Source string    `json:"source,omitempty"`
	// Legacy marks history loaded before coverage_version was recorded.
	// Compacted spans retain it if either input contains legacy history.
	Legacy bool `json:"legacy,omitempty"`
	// StallAfter records the exact unavailable interval following this span.
	StallAfter     *CoverageStall `json:"stall_after,omitempty"`
	ShortStalls    uint64         `json:"short_stalls,omitempty"`
	ShortStalledNS int64          `json:"short_stalled_ns,omitempty"`
}

type CoverageStall struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Short stalls retain exact intervals until the span bound requires compaction.
const shortStallThreshold = time.Second

const coverageVersion = 1

type pendingStall struct {
	Start, End     time.Time
	ShortStalls    uint64
	ShortStalledNS int64
}

// SourceCoverage tracks the open coverage span of one collector source. The
// feeder goroutine reports stalls and the stream's end; Save applies them.
type SourceCoverage struct {
	source   string
	covering bool
	// evictedSpan is owned by the run loop, like covering. Feeders only write
	// observations protected by mu; they never access this recovery snapshot.
	evictedSpan      *CoverageSpan
	mu               sync.Mutex
	stalls           []pendingStall
	stalledAt        time.Time
	endedAt          time.Time
	limit            int
	evictedThrough   time.Time
	queueHighWater   int
	queueHighWaterAt *time.Time
	droppedLines     uint64
}

type Store struct {
	Config        Config
	State         State
	dirty         bool
	coverage      map[string]*SourceCoverage
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
	if s.State.CoverageVersion == 0 {
		for i := range s.State.Coverage {
			s.State.Coverage[i].Legacy = true
		}
		s.State.CoverageVersion = coverageVersion
	}
	s.prune(time.Now())
	return s, nil
}

// validateState runs before pruning or dereferencing any loaded entry.
func (s *Store) validateState() error {
	st := s.State
	bad := func() error { return errors.New("invalid structure, count or field") }
	if st.CoverageVersion < 0 || st.CoverageVersion > coverageVersion {
		return bad()
	}
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
	if len(st.NettopError) > 1024 || len(st.NetfilterError) > 1024 {
		return bad()
	}
	h := st.Health
	if h.LineQueueHighWater.ALF < 0 || h.LineQueueHighWater.ALF > 64 || h.LineQueueHighWater.Netfilter < 0 || h.LineQueueHighWater.Netfilter > 64 || !h.Save.valid() || !h.Classification.valid() {
		return bad()
	}
	for _, v := range st.Coverage {
		if v.ShortStalledNS < 0 || (v.ShortStalls == 0 && v.ShortStalledNS != 0) {
			return bad()
		}
		if stall := v.StallAfter; stall != nil && (!stall.From.Equal(v.End) || stall.To.Before(stall.From)) {
			return bad()
		}
		if v.Start.IsZero() || v.End.Before(v.Start) || (v.Source != "" && v.Source != SourceNetfilter) {
			return bad()
		}
	}
	for _, v := range st.Events {
		if v.TS.IsZero() || !validLabel(v.Label) || v.Mode != "shadow" || (v.Source != "alf" && v.Source != "nettop" && v.Source != SourceNetfilter) || !persistedText(v.App, 1024) || !persistedText(v.Signer, 1024) || len(v.Verdict) > 128 || len(v.RemoteClass) > 128 || len(v.Bucket) > 128 || len(v.Kind) > 16 || len(v.Host) > 253 || (v.Host != "" && !hostnamePattern.MatchString(v.Host)) || v.Counts == 0 || v.Counts > math.MaxInt64 || (v.Port != nil && (*v.Port < 1 || *v.Port > 65535)) {
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
	parts := []any{it.Source, it.App, it.Verdict, p, it.Remote}
	// A netfilter flow's destination is part of its identity, so a new
	// destination for an app is a new item (novelty), not a repeat.
	if it.Source == SourceNetfilter {
		parts = append(parts, it.Kind, it.Bucket)
	}
	raw, _ := json.Marshal(parts)
	return string(raw)
}
func cleanItem(it Item) Item { it.App = Sanitize(it.App); it.Signer = Sanitize(it.Signer); return it }

// Observe counts repeats and emits at most one spike per fixed per-key window.
func (s *Store) Observe(it Item, now time.Time, classify func(Item) Decision) []Event {
	return s.observe(it, now, classify, nil)
}

// observe is Observe with the run loop's shutdown predicate. A repeat
// escalation is decided by the rules alone, without the classifier, so it
// needs the predicate to record backend_shutdown during shutdown (PR63
// review r1). nil means never shutting down.
func (s *Store) observe(it Item, now time.Time, classify func(Item) Decision, shuttingDown func() bool) []Event {
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
		event := Event{TS: now, Source: it.Source, App: it.App, Signer: it.Signer, Verdict: it.Verdict, Port: port(it), RemoteClass: it.Remote, Bucket: it.Bucket, Host: it.Host, Counts: entry.Count, Label: d.Label, Reason: d.Reason, Mode: "shadow"}
		if it.Source == SourceNetfilter {
			event.Kind = it.Kind
		}
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
		add(it, s.classify(it, classify))
	} else if d, ok := Rules(it); ok && d.Label == "decide" {
		found := false
		for _, r := range entry.Escalated {
			if r == d.Reason {
				found = true
			}
		}
		if !found {
			if shuttingDown != nil && shuttingDown() {
				d = Decision{Label: "digest", Reason: "backend_shutdown"}
			}
			add(it, d)
		}
	}
	if spike {
		it.Spike = true
		add(it, s.classify(it, classify))
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
	s.pruneCoverage(cutoff)
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

// Coverage returns the coverage tracker of one source ("" is the ALF log).
func (s *Store) Coverage(source string) *SourceCoverage {
	if s.coverage == nil {
		s.coverage = map[string]*SourceCoverage{}
	}
	c, ok := s.coverage[source]
	if !ok {
		c = &SourceCoverage{source: source, limit: s.Config.MaxEntries}
		s.coverage[source] = c
	}
	return c
}

// BeginCoverage opens a coverage span for the ALF source; every later Save
// extends it to the save time until EndCoverage.
func (s *Store) BeginCoverage(now time.Time) { s.BeginSourceCoverage("", now) }

// StallCoverage, ResumeCoverage and EndCoverage report the ALF collector's
// state; see the SourceCoverage methods.
func (s *Store) StallCoverage(at time.Time)  { s.Coverage("").StallCoverage(at) }
func (s *Store) ResumeCoverage(at time.Time) { s.Coverage("").ResumeCoverage(at) }
func (s *Store) EndCoverage(at time.Time)    { s.Coverage("").EndCoverage(at) }

// BeginSourceCoverage opens a coverage span for one source.
func (s *Store) BeginSourceCoverage(source string, now time.Time) {
	s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: now, End: now, Source: source})
	s.Coverage(source).covering = true
}

// StallCoverage records that the collector's line queue is full from at: the
// run loop is behind and the collector may block or drop lines, so the stall
// is not coverage. Called from the feeder goroutine; the first open stall wins.
func (c *SourceCoverage) StallCoverage(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stalledAt.IsZero() {
		c.stalledAt = at
	}
}

// ResumeCoverage closes an open stall; the next Save ends the span at the
// stall's start and opens a new span at at. Under count pressure, short stalls
// are coalesced; long-stall history that must be dropped advances a watermark.
func (c *SourceCoverage) ResumeCoverage(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.stalledAt.IsZero() {
		c.stalls = append(c.stalls, pendingStall{Start: c.stalledAt, End: at})
		if len(c.stalls) > c.limit {
			c.stalls = compactPending(c.stalls)
			if len(c.stalls) > c.limit {
				for _, stall := range c.stalls[:len(c.stalls)-c.limit] {
					if stall.End.After(c.evictedThrough) {
						c.evictedThrough = stall.End
					}
				}
				c.stalls = append([]pendingStall(nil), c.stalls[len(c.stalls)-c.limit:]...)
			}
		}
		c.stalledAt = time.Time{}
	}
}

// EndCoverage records when collection stopped. It may be called from the
// feeder goroutine while the run loop is still busy; the next Save caps the
// span there and no later Save extends it. The first call wins.
func (c *SourceCoverage) EndCoverage(at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.endedAt.IsZero() {
		c.endedAt = at
	}
}

// extendCoverage applies one source's collector observations to its open span
// (the source's last span) at a save: each closed stall ends the span at its
// start and opens a new one at its end; the span then reaches now, but never
// past an open stall or the collector's end.
func (s *Store) extendCoverage(c *SourceCoverage, now time.Time) {
	if c.evictedSpan != nil {
		s.State.Coverage = append(s.State.Coverage, *c.evictedSpan)
		c.evictedSpan = nil
	}
	c.mu.Lock()
	stalls, stalledAt, endedAt := c.stalls, c.stalledAt, c.endedAt
	evicted, highWater, highWaterAt := c.evictedThrough, c.queueHighWater, c.queueHighWaterAt
	c.stalls = nil
	c.mu.Unlock()
	s.coverageEvicted(evicted)
	high := &s.State.Health.LineQueueHighWater.ALF
	highAt := &s.State.Health.LineQueueHighWater.MaxAt.ALF
	if c.source == SourceNetfilter {
		high = &s.State.Health.LineQueueHighWater.Netfilter
		highAt = &s.State.Health.LineQueueHighWater.MaxAt.Netfilter
	}
	if highWater > *high {
		*high = highWater
		*highAt = highWaterAt
	}
	open := -1
	for i := len(s.State.Coverage) - 1; i >= 0; i-- {
		if s.State.Coverage[i].Source == c.source {
			open = i
			break
		}
	}
	if open < 0 {
		return
	}
	extend := func(to time.Time) {
		if last := &s.State.Coverage[open]; to.After(last.End) {
			last.End = to
		}
	}
	setStall := func(from, to time.Time) {
		last := &s.State.Coverage[open]
		// A feeder may timestamp a stall just before a save snapshots its
		// mutex. Correct the previous optimistic end when that report arrives.
		if from.Before(last.End) {
			last.End = from
		}
		last.StallAfter = &CoverageStall{From: from, To: to}
	}
	// Any previously saved open stall is replaced by this snapshot's exact
	// closed interval, or by a coalesced counter if compaction was required.
	s.State.Coverage[open].StallAfter = nil
	for _, stall := range stalls {
		if stall.ShortStalls > 0 {
			last := &s.State.Coverage[open]
			last.ShortStalls = addCount(last.ShortStalls, stall.ShortStalls)
			last.ShortStalledNS = addNS(last.ShortStalledNS, stall.ShortStalledNS)
			// Seal the counters at the batch's last resume, correcting any
			// optimistic saved end if the feeder reported the batch late.
			last.End = stall.End
			s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: stall.End, End: stall.End, Source: c.source})
			open = len(s.State.Coverage) - 1
			continue
		}
		extend(stall.Start)
		setStall(stall.Start, stall.End)
		s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: stall.End, End: stall.End, Source: c.source})
		open = len(s.State.Coverage) - 1
	}
	end := now
	if !endedAt.IsZero() && endedAt.Before(end) {
		end = endedAt
	}
	if !stalledAt.IsZero() && stalledAt.Before(end) {
		setStall(stalledAt, end)
		end = stalledAt
	}
	if !endedAt.IsZero() {
		c.covering = false
	}
	extend(end)
}

func (s *Store) Save(now time.Time) error {
	start := time.Now()
	// A save cannot persist its own completed duration without another write.
	// The next save persists this result, including failed attempts.
	defer func() { s.State.Health.Save.observe(time.Since(start), time.Now()) }()
	if e := safeDir(s.Config.StateDir); e != nil {
		return e
	}
	for _, source := range sortedCoverageSources(s.coverage) {
		c := s.coverage[source]
		c.mu.Lock()
		dropped := c.droppedLines
		c.droppedLines = 0
		c.mu.Unlock()
		drops := &s.State.Health.ShutdownDroppedLines.ALF
		if source == SourceNetfilter {
			drops = &s.State.Health.ShutdownDroppedLines.Netfilter
		}
		*drops = addCount(*drops, dropped)
		if c.covering {
			s.extendCoverage(c, now)
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
	return map[string]any{
		"entries":                   len(s.State.Entries),
		"events":                    len(s.State.Events),
		"signer_cache":              len(s.State.Signers),
		"last_event":                s.State.LastEvent,
		"backend_healthy":           s.State.BackendHealthy,
		"health_as_of":              s.State.Updated,
		"unrecognized":              s.State.Parser.Unrecognized + s.State.NettopUnrecognized,
		"invalid_json":              s.State.Parser.Invalid,
		"unrecognized_samples":      s.State.Parser.Samples,
		"nettop_error":              s.State.NettopError,
		"netfilter_invalid":         s.State.Netfilter.Invalid,
		"netfilter_rejected_sender": s.State.Netfilter.RejectedSender,
		"netfilter_error":           s.State.NetfilterError,
		"mode":                      "shadow",
		"line_queue_high_water":     s.State.Health.LineQueueHighWater,
		"shutdown_dropped_lines":    s.State.Health.ShutdownDroppedLines,
		"run_loop_timing": map[string]TimingSummary{"save": s.State.Health.Save,
			"classification": s.State.Health.Classification},
	}
}
func (s *Store) String() string {
	return fmt.Sprintf("%d entries, %d retained events", len(s.State.Entries), len(s.State.Events))
}

func sortedCoverageSources(m map[string]*SourceCoverage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
