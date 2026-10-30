package firewallwatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"
)

// The state journal keeps state durable without rewriting the whole snapshot
// for each change (BUG-261029-kpyw8s; sysadmin decisions 2026-10-29). Each
// append is one JSON record on its own line in state-journal.jsonl, followed
// by a full sync. A record carries every entry and signer that changed or was
// removed since the previous append, the events added and the identities of
// the events its prunes removed, so replay reproduces exactly what the watcher
// held at that append.
// A snapshot (Save) folds the journal into state.json, records the last
// folded seq as journal_seq, and only then removes the journal.
const (
	journalFile = "state-journal.jsonl"
	// A snapshot runs this long after the previous one, or after this many
	// records since it, whichever comes first.
	journalSnapshotInterval = 5 * time.Minute
	journalSnapshotRecords  = 500
	// The journal never grows past this many bytes, nor past max_state_bytes,
	// the reader's limit: a record that would cross either takes a snapshot.
	journalSnapshotBytes = 8 << 20
	// A heartbeat whose coverage tail exceeds this many spans takes a
	// snapshot instead.
	journalMaxTailSpans = 256
)

const recordDelta = "delta"

// journalRecord is one journal line: the state changes since the previous
// append, and the silent state when it is also a heartbeat.
type journalRecord struct {
	Seq            uint64                 `json:"seq"`
	Type           string                 `json:"type"`
	Entries        map[string]*Entry      `json:"entries,omitempty"`
	RemovedEntries []string               `json:"removed_entries,omitempty"`
	Signers        map[string]SignerEntry `json:"signers,omitempty"`
	RemovedSigners []string               `json:"removed_signers,omitempty"`
	// Events were added since the previous append. RemovedEvents identify,
	// by eventID, the events the watcher's prunes dropped since then: replay
	// adds, then removes. Retention compares monotonic and wall readings
	// (PR66), so the dropped events are not always the oldest by wall time
	// (PR69 review r2).
	Events         []Event    `json:"events,omitempty"`
	RemovedEvents  []string   `json:"removed_events,omitempty"`
	LastEvent      time.Time  `json:"last_event"`
	EvictedThrough time.Time  `json:"evicted_through"`
	Heartbeat      *heartbeat `json:"heartbeat,omitempty"`
}

// heartbeat is the silent state: every State field that no delta field, the
// snapshot boundary or the coverage delta carries. Replay applies the latest
// heartbeat.
// TestHeartbeatRoundTrip and TestHeartbeatCoversState keep this complete.
type heartbeat struct {
	Parser                 ALFParser       `json:"alf"`
	Netfilter              NetfilterParser `json:"netfilter"`
	NetfilterError         string          `json:"netfilter_error,omitempty"`
	NettopUnrecognized     uint64          `json:"nettop_unrecognized"`
	BackendHealthy         bool            `json:"backend_healthy"`
	Updated                time.Time       `json:"updated"`
	NettopError            string          `json:"nettop_error,omitempty"`
	CoverageVersion        int             `json:"coverage_version"`
	CoverageEvictedThrough time.Time       `json:"coverage_evicted_through"`
	Health                 RunHealth       `json:"health"`
	Coverage               coverageDelta   `json:"coverage"`
}

// coverageDelta is the coverage changed since the last snapshot, by position.
// Snapshots alone prune and reorder coverage, so between snapshots only two
// kinds of span change: each source's open span at the snapshot (its last
// span there), which collection extends, and the spans appended after the
// snapshot. Base is the snapshot's span count. Positions do not depend on
// span times, so a clock step across a restart cannot hide a new run's span
// (PR69 review r5).
type coverageDelta struct {
	Base     int            `json:"base"`
	Open     []openSpan     `json:"open,omitempty"`
	Appended []CoverageSpan `json:"appended,omitempty"`
}

// openSpan is the current value of the span at a snapshot position.
type openSpan struct {
	Index int          `json:"index"`
	Span  CoverageSpan `json:"span"`
}

// journalDelta tracks the changes since the last append or snapshot. urgent
// marks changes that must be durable at once: emitted events, deny-window
// state and new or changed signer results.
type journalDelta struct {
	entries, removedEntries map[string]bool
	signers, removedSigners map[string]bool
	events                  []Event
	removedEvents           []string
	urgent                  bool
}

// eventID identifies an event by the fields that survive a JSON round trip
// unchanged: time, key fields, count, label and reason kind. Two events with
// the same identity are interchangeable for removal.
func eventID(e Event) string {
	kind, _ := e.Reason.(string)
	if kind == "" {
		raw, _ := json.Marshal(e.Reason)
		var v struct {
			Kind string `json:"kind"`
		}
		_ = json.Unmarshal(raw, &v)
		kind = v.Kind
	}
	port := -1
	if e.Port != nil {
		port = *e.Port
	}
	parts := []any{e.TS.UTC().Format(time.RFC3339Nano), e.Source, e.App, e.Signer, e.Verdict, port, e.RemoteClass, e.Bucket, e.Kind, e.Host, e.Counts, e.Label, kind, e.Mode}
	// A nettop event's path is part of its identity; an event without one
	// keeps the identity it always had, so stored removals still match.
	if e.Path != "" {
		parts = append(parts, e.Path)
	}
	raw, _ := json.Marshal(parts)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:12])
}

func (s *Store) eventRemoved(e Event) {
	s.delta.removedEvents = append(s.delta.removedEvents, eventID(e))
}

func mark(set *map[string]bool, k string) {
	if *set == nil {
		*set = map[string]bool{}
	}
	(*set)[k] = true
}

func (s *Store) entryChanged(k string) {
	mark(&s.delta.entries, k)
	delete(s.delta.removedEntries, k)
}

func (s *Store) entryRemoved(k string) {
	mark(&s.delta.removedEntries, k)
	delete(s.delta.entries, k)
}

func (s *Store) signerChanged(k string) {
	mark(&s.delta.signers, k)
	delete(s.delta.removedSigners, k)
}

func (s *Store) signerRemoved(k string) {
	mark(&s.delta.removedSigners, k)
	delete(s.delta.signers, k)
}

func (s *Store) journalPath() string { return filepath.Join(s.Config.StateDir, journalFile) }

// heartbeat applies the collectors' observations to coverage, as a snapshot
// does, and captures the silent state. It reports false when the coverage
// tail is too long for a journal record.
func (s *Store) heartbeat(now time.Time) (*heartbeat, bool) {
	s.applyCollectors(now)
	st := &s.State
	st.Updated = now
	h := &heartbeat{Parser: st.Parser, Netfilter: st.Netfilter, NetfilterError: st.NetfilterError, NettopUnrecognized: st.NettopUnrecognized, BackendHealthy: st.BackendHealthy, Updated: st.Updated, NettopError: st.NettopError, CoverageVersion: st.CoverageVersion, CoverageEvictedThrough: st.CoverageEvictedThrough, Health: st.Health}
	h.Coverage = coverageDelta{Base: s.snapLen, Appended: slices.Clone(st.Coverage[s.snapLen:])}
	for _, i := range s.snapOpen {
		h.Coverage.Open = append(h.Coverage.Open, openSpan{Index: i, Span: st.Coverage[i]})
	}
	sort.Slice(h.Coverage.Open, func(i, j int) bool { return h.Coverage.Open[i].Index < h.Coverage.Open[j].Index })
	return h, len(h.Coverage.Open)+len(h.Coverage.Appended) <= journalMaxTailSpans
}

// markSnapshot records the coverage of the snapshot on disk: its span count
// and the position of each collecting source's open span. Only those spans,
// and spans appended later, change before the next snapshot, so later
// heartbeats carry the changes from there. The open span is found by its
// tracker, not as the source's last span (PR69 review r6).
func (s *Store) markSnapshot() {
	s.snapLen = len(s.State.Coverage)
	s.snapOpen = map[string]int{}
	for source, c := range s.coverage {
		if c.covering {
			if i := c.openIndex(s.State.Coverage); i >= 0 {
				s.snapOpen[source] = i
			}
		}
	}
}

// snapshotDue reports whether the next durable write must be a snapshot.
func (s *Store) snapshotDue(now time.Time) bool {
	return s.journalBroken || s.journalRecords >= journalSnapshotRecords ||
		(!s.lastSnapshot.IsZero() && !now.Before(s.lastSnapshot.Add(journalSnapshotInterval)))
}

// journalLimit is the most bytes the journal may hold: the writer's own bound,
// and no more than max_state_bytes minus the snapshot's size. Every record
// carries each value it changes, so the state replay rebuilds is never larger
// than snapshot plus journal, and the watcher's startup snapshot can always
// write it (PR69 review r6).
func (s *Store) journalLimit() int64 {
	return min(journalSnapshotBytes, s.Config.MaxStateBytes-s.snapshotBytes)
}

// validateRecord applies the reader's per-item checks to a record before it is
// appended, so an append never acknowledges what OpenStore would refuse.
func (s *Store) validateRecord(r journalRecord) error {
	v := &Store{Config: s.Config}
	v.State = State{Entries: map[string]*Entry{}, Signers: map[string]SignerEntry{}, Events: r.Events, CoverageVersion: s.State.CoverageVersion, Parser: s.State.Parser, Netfilter: s.State.Netfilter, Health: s.State.Health}
	for k, e := range r.Entries {
		v.State.Entries[k] = e
	}
	for k, e := range r.Signers {
		v.State.Signers[k] = e
	}
	if h := r.Heartbeat; h != nil {
		v.State.Parser, v.State.Netfilter, v.State.NetfilterError, v.State.NettopError, v.State.Health = h.Parser, h.Netfilter, h.NetfilterError, h.NettopError, h.Health
		for _, o := range h.Coverage.Open {
			v.State.Coverage = append(v.State.Coverage, o.Span)
		}
		v.State.Coverage = append(v.State.Coverage, h.Coverage.Appended...)
	}
	return v.validateShape(false, 0)
}

var (
	errJournalFull = errors.New("journal record does not fit the journal limit")
	errJournalTail = errors.New("coverage tail too long for a heartbeat")
)

// appendJournal appends the changes since the previous append, with the
// silent state when withHeartbeat, as one record and syncs it. The record's
// seq is reserved before the write: a fallback snapshot after a failure then
// covers whatever part of it reached the disk. After a failed append nothing
// more is appended until a snapshot has replaced the journal, so a torn write
// can only be the journal's last line.
func (s *Store) appendJournal(now time.Time, withHeartbeat bool) (err error) {
	start := time.Now()
	defer func() {
		if err != nil {
			s.journalBroken = true
		}
		d, at := time.Since(start), time.Now()
		s.State.Health.Journal.observe(d, at)
		s.State.Health.recordSlow(SlowJournal, d, at, 0)
	}()
	st := &s.State
	r := journalRecord{Seq: s.seq + 1, Type: recordDelta, Events: s.delta.events, RemovedEvents: s.delta.removedEvents, LastEvent: st.LastEvent, EvictedThrough: st.EvictedThrough}
	for k := range s.delta.entries {
		if r.Entries == nil {
			r.Entries = map[string]*Entry{}
		}
		r.Entries[k] = st.Entries[k]
	}
	for k := range s.delta.removedEntries {
		r.RemovedEntries = append(r.RemovedEntries, k)
	}
	for k := range s.delta.signers {
		if r.Signers == nil {
			r.Signers = map[string]SignerEntry{}
		}
		r.Signers[k] = st.Signers[k]
	}
	for k := range s.delta.removedSigners {
		r.RemovedSigners = append(r.RemovedSigners, k)
	}
	sort.Strings(r.RemovedEntries)
	sort.Strings(r.RemovedSigners)
	if withHeartbeat {
		h, ok := s.heartbeat(now)
		if !ok {
			return errJournalTail
		}
		r.Heartbeat = h
	}
	if e := s.validateRecord(r); e != nil {
		return fmt.Errorf("%w: %w", errRefusedRecord, e)
	}
	line, e := json.Marshal(r)
	if e != nil {
		return e
	}
	line = append(line, '\n')
	s.seq = r.Seq // reserved: see above
	if s.journalBytes+int64(len(line)) > s.journalLimit() {
		return errJournalFull
	}
	if e := safeDir(s.Config.StateDir); e != nil {
		return e
	}
	path := s.journalPath()
	if e := safeExisting(path); e != nil {
		return writeFailed(path, e)
	}
	_, statErr := os.Lstat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return writeFailed(path, e)
	}
	if s.journalWrite != nil {
		e = s.journalWrite(f, line)
	} else {
		_, e = f.Write(line)
	}
	if e == nil {
		e = f.Sync()
	}
	if e = errors.Join(e, f.Close()); e != nil {
		return writeFailed(path, e)
	}
	if created {
		// The new journal's directory entry must survive a crash too.
		if e = syncDir(s.Config.StateDir); e != nil {
			return writeFailed(path, e)
		}
	}
	s.journalRecords++
	s.journalBytes += int64(len(line))
	events := len(s.delta.events) > 0
	s.delta = journalDelta{}
	if events && !st.LastEvent.IsZero() {
		if e = s.writeFlag(); e != nil {
			return e
		}
	}
	if withHeartbeat {
		s.dirty = false
		s.lastSave = now.Add(time.Since(start))
	}
	return nil
}

// rotateJournal removes the journal after a snapshot that folded it in. The
// snapshot's rename is made durable first, so a crash leaves either the old
// snapshot with the whole journal or the new snapshot (skipping records up to
// its journal_seq), never a lost record.
func (s *Store) rotateJournal() error {
	// The first barrier makes the new state.json durable; the check, the
	// removal and the second barrier are the journal's. A failure names the
	// file it was for.
	if e := syncDir(s.Config.StateDir); e != nil {
		return writeFailed(filepath.Join(s.Config.StateDir, "state.json"), e)
	}
	path := s.journalPath()
	if e := safeExisting(path); e != nil {
		return writeFailed(path, e)
	}
	if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return writeFailed(path, e)
	}
	if e := syncDir(s.Config.StateDir); e != nil {
		return writeFailed(path, e)
	}
	s.delta = journalDelta{}
	s.journalRecords, s.journalBytes, s.journalBroken = 0, 0, false
	return nil
}

func syncDir(dir string) error {
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	return errors.Join(d.Sync(), d.Close())
}

// openJournal opens the journal for reading before state.json is read, so a
// rotation in between yields a consistent view: an old journal's records up
// to the new snapshot's journal_seq are skipped. It returns nil when there is
// no journal.
func openJournal(path string) (*os.File, error) {
	return openPrivate(path)
}

// replayJournal applies the journal's records after journal_seq, read-only.
// Only complete lines count. A last line that is incomplete or not valid
// JSON is a torn tail: ignored and reported. Anything else malformed, a seq
// gap or an unknown record type refuses the journal.
func (s *Store) replayJournal(f io.Reader) (torn bool, err error) {
	// Every successful exit, a torn tail included, applies the removals of
	// the records replayed (PR69 review r4).
	defer func() {
		if err == nil {
			s.dropEvents()
		}
	}()
	raw, e := io.ReadAll(io.LimitReader(f, s.Config.MaxStateBytes+1))
	if e != nil {
		return false, e
	}
	if int64(len(raw)) > s.Config.MaxStateBytes {
		return false, errors.New("journal exceeds max_state_bytes")
	}
	lines := bytes.Split(raw, []byte("\n"))
	if last := lines[len(lines)-1]; len(last) > 0 {
		torn = true // no newline: an append that never completed
	}
	lines = lines[:len(lines)-1]
	s.seq = s.State.JournalSeq
	var prev uint64
	for i, line := range lines {
		var r journalRecord
		if e := json.Unmarshal(line, &r); e != nil {
			// Only a final line that is not valid JSON is a torn write. Valid
			// JSON that does not decode (a wrong type, a bad timestamp) is
			// corruption, refused like any other (PR69 review r8).
			if i == len(lines)-1 && !torn && !json.Valid(line) {
				return true, nil
			}
			return torn, fmt.Errorf("journal record %d: %w", i+1, e)
		}
		if i > 0 && r.Seq != prev+1 {
			return torn, fmt.Errorf("journal record %d: seq %d after %d", i+1, r.Seq, prev)
		}
		prev = r.Seq
		if r.Seq <= s.State.JournalSeq {
			continue
		}
		if r.Seq != s.seq+1 {
			return torn, fmt.Errorf("journal record %d: seq %d, want %d", i+1, r.Seq, s.seq+1)
		}
		// Each record is checked before it is applied, so a later record
		// cannot overwrite and hide an earlier corrupt one (PR69 review r7).
		if r.Type == recordDelta {
			if e := s.validateRecord(r); e != nil {
				return torn, fmt.Errorf("journal record %d: %w", i+1, e)
			}
		}
		if e := s.applyRecord(r); e != nil {
			return torn, fmt.Errorf("journal record %d: %w", i+1, e)
		}
		s.seq = r.Seq
	}
	return torn, nil
}

// dropEvents removes one event per collected removal of its identity.
func (s *Store) dropEvents() {
	if len(s.replayDrop) == 0 {
		return
	}
	kept := s.State.Events[:0]
	for _, e := range s.State.Events {
		s.replayIDs++
		if id := eventID(e); s.replayDrop[id] > 0 {
			s.replayDrop[id]--
			continue
		}
		kept = append(kept, e)
	}
	s.State.Events = kept
	s.replayDrop = nil
}

func (s *Store) applyRecord(r journalRecord) error {
	if r.Type != recordDelta {
		return fmt.Errorf("unknown record type %q", r.Type)
	}
	st := &s.State
	for _, k := range r.RemovedEntries {
		delete(st.Entries, k)
	}
	for k, v := range r.Entries {
		if v == nil {
			return fmt.Errorf("entry %q without value", k)
		}
		st.Entries[k] = v
	}
	for _, k := range r.RemovedSigners {
		delete(st.Signers, k)
	}
	for k, v := range r.Signers {
		st.Signers[k] = v
	}
	st.Events = append(st.Events, r.Events...)
	// Removals are applied once, after the last record (dropEvents): events
	// with the same identity are interchangeable, so the order in which the
	// records removed them does not matter, and each event's identity is
	// computed once per replay instead of once per record (PR69 review r3).
	for _, id := range r.RemovedEvents {
		if s.replayDrop == nil {
			s.replayDrop = map[string]int{}
		}
		s.replayDrop[id]++
	}
	st.LastEvent, st.EvictedThrough = r.LastEvent, r.EvictedThrough
	if h := r.Heartbeat; h != nil {
		st.Parser, st.Netfilter, st.NetfilterError, st.NettopUnrecognized = h.Parser, h.Netfilter, h.NetfilterError, h.NettopUnrecognized
		st.BackendHealthy, st.Updated, st.NettopError = h.BackendHealthy, h.Updated, h.NettopError
		st.CoverageVersion, st.CoverageEvictedThrough, st.Health = h.CoverageVersion, h.CoverageEvictedThrough, h.Health
		d := h.Coverage
		if d.Base != s.snapLen {
			return fmt.Errorf("coverage base %d, snapshot has %d spans", d.Base, s.snapLen)
		}
		st.Coverage = st.Coverage[:d.Base]
		for _, o := range d.Open {
			if o.Index < 0 || o.Index >= d.Base {
				return fmt.Errorf("coverage open index %d outside the snapshot's %d spans", o.Index, d.Base)
			}
			st.Coverage[o.Index] = o.Span
		}
		st.Coverage = append(st.Coverage, d.Appended...)
	}
	return nil
}
