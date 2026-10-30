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
	// JournalSeq is the last state-journal record folded into this snapshot.
	JournalSeq uint64 `json:"journal_seq"`
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
	evictedSpan *CoverageSpan
	// openStart identifies the source's open span by its start, once
	// collection began (hasOpen). The open span is not always the source's
	// last span: snapshots order spans by start, and after a backward clock
	// step across a restart a historical span can sort after it (PR69
	// review r6). Owned by the run loop, like covering.
	openStart        time.Time
	hasOpen          bool
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
	// refs are the retention references of the observations since the last
	// backward wall step. The expiry they decided is applied lazily: by the
	// observed key's own check, an over-cap prune, or the next Save.
	refs expiryRefs
	// State journal (journal.go): the last seq written or replayed, records
	// not yet appended, and the journal since the last snapshot.
	seq            uint64
	delta          journalDelta
	lastSnapshot   time.Time
	journalRecords int
	journalBytes   int64
	journalBroken  bool
	// snapLen and snapOpen describe the snapshot on disk: its coverage span
	// count and each source's open span position (markSnapshot).
	snapLen  int
	snapOpen map[string]int
	// snapshotBytes is the size of the snapshot on disk (journalLimit).
	snapshotBytes int64
	// replayDrop collects the event removals of the records replayed so far;
	// replayIDs counts the identities replay computed (a cost test reads it).
	replayDrop map[string]int
	replayIDs  int
	// journalWrite replaces the append's single write in tests.
	journalWrite func(*os.File, []byte) error
}

// checkDir applies safeDir's checks to an existing state dir without
// creating it; a missing dir is os.ErrNotExist.
func checkDir(dir string) error {
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

// openPrivate opens an existing state artifact for reading, without following
// a symlink, and checks the opened file: a private regular file of the
// caller with at most one link. It returns nil, nil if the file does not
// exist. Checking the open file, not the path, keeps a reader consistent
// while the watcher renames state.json or unlinks the journal: the reader
// holds the file it opened, which may have just lost its last link (PR69,
// a reader racing a rotation failed the path check).
func openPrivate(path string) (*os.File, error) {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || int(st.Uid) != os.Getuid() || st.Nlink > 1 {
		f.Close()
		return nil, errors.New("state artifacts must be private regular files, without links")
	}
	return f, nil
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

// afterJournalOpen runs in OpenStore between opening the journal and reading
// state.json; tests use it to rotate at that point.
var afterJournalOpen func()

func OpenStore(c Config) (*Store, error) {
	// Opening never creates the state dir: status and digest only read
	// (PR69 review r1). The watcher creates it before opening.
	if e := checkDir(c.StateDir); e != nil {
		if !errors.Is(e, os.ErrNotExist) {
			return nil, e
		}
		s := &Store{Config: c}
		s.State.Entries, s.State.Signers = map[string]*Entry{}, map[string]SignerEntry{}
		s.State.CoverageVersion = coverageVersion
		s.markSnapshot()
		return s, nil
	}
	s := &Store{Config: c}
	// The journal is opened before state.json is read: see openJournal.
	journal, e := openJournal(s.journalPath())
	if e != nil {
		return nil, e
	}
	if journal != nil {
		defer journal.Close()
	}
	if afterJournalOpen != nil {
		afterJournalOpen()
	}
	f, e := openPrivate(filepath.Join(c.StateDir, "state.json"))
	if e == nil && f == nil {
		e = os.ErrNotExist
	}
	if e == nil {
		raw, readErr := io.ReadAll(io.LimitReader(f, c.MaxStateBytes+1))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil {
			return nil, errors.Join(readErr, closeErr)
		}
		if int64(len(raw)) > c.MaxStateBytes {
			return nil, errors.New("corrupt state: max_state_bytes exceeded")
		}
		s.snapshotBytes = int64(len(raw))
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
	// The heartbeats in the journal describe coverage relative to this
	// snapshot, so its shape is taken before replay.
	s.markSnapshot()
	s.seq = s.State.JournalSeq
	if journal != nil {
		// Readers replay read-only; only the watcher's startup snapshot
		// removes a torn tail together with the folded journal.
		torn, e := s.replayJournal(journal)
		if e != nil {
			return nil, fmt.Errorf("corrupt state journal: %w", e)
		}
		// Bounds hold only after the prune below: coverage may have grown
		// past max_entries since the snapshot.
		if e = s.validateShape(false, 0); e != nil {
			return nil, fmt.Errorf("corrupt state journal: %w", e)
		}
		if torn {
			s.State.Health.JournalTornTail = addCount(s.State.Health.JournalTornTail, 1)
		}
	}
	if s.State.CoverageVersion == 0 {
		for i := range s.State.Coverage {
			s.State.Coverage[i].Legacy = true
		}
		s.State.CoverageVersion = coverageVersion
	}
	// Readers prune entries, events and signers but never coverage: the
	// watcher leaves coverage exact between snapshots, and a reader must see
	// the same spans, gaps and truncated verdicts (PR69 review r3). Replayed
	// coverage can exceed max_entries by at most one heartbeat tail.
	s.pruneItems(expiryRefs{}.with(time.Now()))
	if e := s.validateShape(true, journalMaxTailSpans); e != nil {
		return nil, fmt.Errorf("corrupt state journal: %w", e)
	}
	return s, nil
}

// validateState runs before pruning or dereferencing any loaded entry.
func (s *Store) validateState() error { return s.validateShape(true, 0) }

// validateShape checks structure and fields, and the max_entries bounds when
// bounded; coverage may exceed its bound by coverageSlack spans. A replayed
// journal is first checked unbounded: between snapshots the watcher grows
// coverage without pruning it, and OpenStore prunes the other items after
// replay, then checks the bounds.
func (s *Store) validateShape(bounded bool, coverageSlack int) error {
	st := s.State
	bad := func() error { return errors.New("invalid structure, count or field") }
	if st.CoverageVersion < 0 || st.CoverageVersion > coverageVersion {
		return bad()
	}
	if st.Entries == nil || st.Signers == nil || len(st.Parser.Samples) > SampleLimit {
		return bad()
	}
	if bounded && (len(st.Entries) > s.Config.MaxEntries || len(st.Events) > s.Config.MaxEntries || len(st.Signers) > s.Config.MaxEntries || len(st.Coverage) > s.Config.MaxEntries+coverageSlack) {
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
	if h.LineQueueHighWater.ALF < 0 || h.LineQueueHighWater.ALF > 64 || h.LineQueueHighWater.Netfilter < 0 || h.LineQueueHighWater.Netfilter > 64 || !h.Save.valid() || !h.Classification.valid() || !h.Maintenance.valid() || !h.Journal.valid() || !h.slowOpsValid() {
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
	if e := safeDir(s.Config.StateDir); e != nil {
		return nil, e
	}
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
	k := key(it)
	// A full prune walks every entry, event and span, which at the max_entries
	// cap cost the live watcher most of its CPU (BUG-261029-do8v1i). Expiry is
	// decided here only for the observed key: an expired entry counts as new
	// again. Other items expire lazily, by the same reference times, when a
	// bound is exceeded below or at the next Save. A backward wall step would
	// lower the cutoff, so it first applies what the later readings already
	// decided, once per step (PR66 review r1).
	if !s.refs.wallAll.IsZero() && now.Round(0).Before(s.refs.wallAll) {
		s.pruneItems(s.refs.with(now))
		s.refs = expiryRefs{}
	}
	s.refs.add(now)
	if entry, ok := s.State.Entries[k]; ok && s.expired(entry.LastSeen, s.refs) {
		delete(s.State.Entries, k)
	}
	entry, exists := s.State.Entries[k]
	if !exists {
		entry = &Entry{FirstSeen: now, WindowStart: now}
		s.State.Entries[k] = entry
	}
	s.dirty = true
	entry.LastSeen = now
	entry.Count++
	spike := false
	denied := it.Verdict != "allow" && it.Verdict != "observed" && it.Verdict != "unknown"
	if denied {
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
		s.delta.events = append(s.delta.events, event)
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
	// Every entry change goes into the next journal append. Emitted events
	// and deny-window state make that append due at once; other changes
	// (last_seen, count) wait for the next heartbeat.
	s.entryChanged(k)
	if len(events) > 0 || denied {
		s.delta.urgent = true
	}
	if len(s.State.Entries) > s.Config.MaxEntries || len(s.State.Events) > s.Config.MaxEntries || len(s.State.Signers) > s.Config.MaxEntries {
		s.pruneItems(s.refs)
	}
	return events
}

// expiryRefs stand for a set of reference times: an item expires when it is
// before the retention cutoff of any of them. Go compares two times by their
// monotonic readings when both have one, otherwise by wall readings. So the
// latest monotonic reference decides for in-run times against references
// with a monotonic reading, the latest wall-only reference against the rest,
// and the latest wall reading of any reference decides for loaded times,
// which have none (PR66 review r2).
type expiryRefs struct {
	mono, wall, wallAll time.Time
}

func hasMonotonic(t time.Time) bool { return t != t.Round(0) }

func (r *expiryRefs) add(t time.Time) {
	if t.IsZero() {
		return
	}
	if hasMonotonic(t) {
		if r.mono.IsZero() || r.mono.Before(t) {
			r.mono = t
		}
	} else if r.wall.IsZero() || r.wall.Before(t) {
		r.wall = t
	}
	if w := t.Round(0); r.wallAll.IsZero() || r.wallAll.Before(w) {
		r.wallAll = w
	}
}

func (r expiryRefs) with(t time.Time) expiryRefs { r.add(t); return r }

func (s *Store) expired(t time.Time, r expiryRefs) bool {
	before := func(ref time.Time) bool {
		return !ref.IsZero() && t.Before(ref.Add(-time.Duration(s.Config.RetentionDays)*24*time.Hour))
	}
	if hasMonotonic(t) {
		return before(r.mono) || before(r.wall)
	}
	return before(r.wallAll)
}

func (s *Store) prune(now time.Time) { s.pruneAt(expiryRefs{}.with(now)) }

// pruneAt applies retention for every reference time, and the bounds, to
// entries, events, signers and coverage.
func (s *Store) pruneAt(refs expiryRefs) {
	s.pruneItems(refs)
	s.pruneCoverageBy(func(t time.Time) bool { return s.expired(t, refs) })
}

// pruneItems is pruneAt without coverage. Observations use it: between
// snapshots coverage only grows at its tail, which keeps the journal's
// heartbeat tail exact (PR69 review r1); snapshots prune coverage.
func (s *Store) pruneItems(refs expiryRefs) {
	expired := func(t time.Time) bool { return s.expired(t, refs) }
	for k, v := range s.State.Entries {
		if expired(v.LastSeen) {
			delete(s.State.Entries, k)
			s.entryRemoved(k)
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
			s.entryRemoved(k)
		}
	}
	evicted := func(e Event) {
		if e.TS.After(s.State.EvictedThrough) {
			s.State.EvictedThrough = e.TS
		}
		s.eventRemoved(e)
	}
	events := s.State.Events[:0]
	for _, e := range s.State.Events {
		if !expired(e.TS) {
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
			s.signerRemoved(k)
		}
	}
}
func (s *Store) write(path string, data []byte) error {
	if s.atomicWrite != nil {
		return s.atomicWrite(path, data)
	}
	return atomicWrite(path, data)
}

// Flush makes urgent changes (emitted events, deny-window state, new signer
// results) durable at once, with every other change since the last append;
// emitted is kept for callers, the urgent mark decides. Silent state follows in a heartbeat once
// save_interval has passed since the last durable write, and a snapshot
// replaces both when one is due or forced. A failed append falls back to a
// snapshot. Failed writes retain dirty state for a retry.
func (s *Store) Flush(now time.Time, emitted, force bool) error {
	if force || (s.snapshotDue(now) && (s.dirty || s.delta.urgent)) {
		return s.Save(now)
	}
	beat := s.dirty && (s.lastSave.IsZero() || !now.Before(s.lastSave.Add(duration(s.Config.SaveInterval))))
	if !s.delta.urgent && !beat {
		return nil
	}
	return s.journalOrSnapshot(now, beat)
}

// Checkpoint makes every change and the silent state durable now, as a
// heartbeat, or takes a snapshot when one is due. The run loop calls it on the
// nettop tick and when the netfilter stream ends.
func (s *Store) Checkpoint(now time.Time) error {
	if s.snapshotDue(now) {
		return s.Save(now)
	}
	return s.journalOrSnapshot(now, true)
}

func (s *Store) journalOrSnapshot(now time.Time, beat bool) error {
	e := s.appendJournal(now, beat)
	if e == nil {
		return nil
	}
	if se := s.Save(now); se != nil {
		return errors.Join(e, se)
	}
	return nil
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
	c := s.Coverage(source)
	c.covering, c.openStart, c.hasOpen = true, now, true
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

// openIndex finds the source's open span: the latest span of the source that
// starts at openStart, or before collection began the source's last span.
// It returns -1 when there is none.
func (c *SourceCoverage) openIndex(spans []CoverageSpan) int {
	for i := len(spans) - 1; i >= 0; i-- {
		if spans[i].Source == c.source && (!c.hasOpen || spans[i].Start.Equal(c.openStart)) {
			return i
		}
	}
	return -1
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
	open := c.openIndex(s.State.Coverage)
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
			c.openStart = stall.End
			continue
		}
		extend(stall.Start)
		setStall(stall.Start, stall.End)
		s.State.Coverage = append(s.State.Coverage, CoverageSpan{Start: stall.End, End: stall.End, Source: c.source})
		open = len(s.State.Coverage) - 1
		c.openStart = stall.End
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

func (s *Store) Save(now time.Time) (err error) {
	start := time.Now()
	// A failed snapshot may already have pruned and reordered coverage in
	// memory, so journal positions no longer match the snapshot on disk:
	// nothing more is appended until a snapshot succeeds.
	defer func() {
		if err != nil {
			s.journalBroken = true
		}
	}()
	// A save cannot persist its own completed duration without another write.
	// The next save persists this result, including failed attempts.
	defer func() {
		d, now := time.Since(start), time.Now()
		s.State.Health.Save.observe(d, now)
		s.State.Health.recordSlow(SlowSave, d, now, 0)
	}()
	if e := safeDir(s.Config.StateDir); e != nil {
		return e
	}
	s.applyCollectors(now)
	s.pruneAt(s.refs.with(now))
	s.State.Updated = now
	s.State.JournalSeq = s.seq
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
	s.snapshotBytes = int64(len(data))
	return s.saveProjections(now, start)
}

// applyCollectors moves the feeders' observations (dropped lines, stalls,
// queue depth, collector end) into state and extends each covering source's
// open span to now. Snapshots and heartbeats both run it.
func (s *Store) applyCollectors(now time.Time) {
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
}

// saveProjections finishes a snapshot after state.json is written: the day
// files and the flag, then the journal rotation.
func (s *Store) saveProjections(now, start time.Time) (e error) {
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
		if e = s.writeFlag(); e != nil {
			return e
		}
	}
	if e = s.rotateJournal(); e != nil {
		return e
	}
	s.markSnapshot()
	s.lastSnapshot = now.Add(time.Since(start))
	s.dirty = false
	// The save interval runs from completion: a save slower than the interval
	// must not make the next silent flush save again at once (BUG-261030-v6ahj5).
	s.lastSave = now.Add(time.Since(start))
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
			"classification": s.State.Health.Classification, "maintenance": s.State.Health.Maintenance, "journal": s.State.Health.Journal},
		"journal_torn_tail": s.State.Health.JournalTornTail,
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

// writeFlag stamps new-events.flag with the latest event time, if it changed.
func (s *Store) writeFlag() error {
	flagPath := filepath.Join(s.Config.StateDir, "new-events.flag")
	if e := safeExisting(flagPath); e != nil {
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
	return s.write(flagPath, stamp)
}
