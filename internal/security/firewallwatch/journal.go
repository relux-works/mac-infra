package firewallwatch

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// The state journal keeps emitted events durable without rewriting the whole
// state for each one (BUG-261029-kpyw8s; sysadmin decisions 2026-10-29). Each
// record is one JSON line in state-journal.jsonl, appended and synced. A
// snapshot (Save) folds the journal into state.json, records the last folded
// seq as journal_seq, and only then removes the journal.
const (
	journalFile = "state-journal.jsonl"
	// A snapshot runs this long after the previous one, or after this many
	// records or bytes since it, whichever comes first.
	journalSnapshotInterval = 5 * time.Minute
	journalSnapshotRecords  = 500
	journalSnapshotBytes    = 8 << 20
	// A heartbeat whose coverage tail exceeds this many spans takes a
	// snapshot instead.
	journalMaxTailSpans = 256
)

// Journal record types.
const (
	recordObserve   = "observe"
	recordSigner    = "signer"
	recordHeartbeat = "heartbeat"
)

// journalRecord is one journal line. An observe record carries an observed
// key's entry after the observation and the events it emitted; a signer record
// one inspection result; a heartbeat the silently changing state.
type journalRecord struct {
	Seq       uint64       `json:"seq"`
	Type      string       `json:"type"`
	Key       string       `json:"key,omitempty"`
	Entry     *Entry       `json:"entry,omitempty"`
	Events    []Event      `json:"events,omitempty"`
	Path      string       `json:"path,omitempty"`
	Signer    *SignerEntry `json:"signer,omitempty"`
	Heartbeat *heartbeat   `json:"heartbeat,omitempty"`
}

// heartbeat is the state that changes without emitting: every State field
// except entries, events, signers and the journal seq, and of the coverage only
// each source's spans from its open span at the last snapshot. Replay applies
// the latest heartbeat. TestHeartbeatCoversState keeps this list complete.
type heartbeat struct {
	Parser                 ALFParser       `json:"alf"`
	Netfilter              NetfilterParser `json:"netfilter"`
	NetfilterError         string          `json:"netfilter_error,omitempty"`
	NettopUnrecognized     uint64          `json:"nettop_unrecognized"`
	LastEvent              time.Time       `json:"last_event"`
	BackendHealthy         bool            `json:"backend_healthy"`
	Updated                time.Time       `json:"updated"`
	NettopError            string          `json:"nettop_error,omitempty"`
	CoverageVersion        int             `json:"coverage_version"`
	EvictedThrough         time.Time       `json:"evicted_through"`
	CoverageEvictedThrough time.Time       `json:"coverage_evicted_through"`
	Health                 RunHealth       `json:"health"`
	Coverage               []coverageTail  `json:"coverage"`
}

// coverageTail replaces a source's spans that start at or after From.
type coverageTail struct {
	Source string         `json:"source"`
	From   time.Time      `json:"from"`
	Spans  []CoverageSpan `json:"spans"`
}

func (s *Store) journalPath() string { return filepath.Join(s.Config.StateDir, journalFile) }

// journalEntry queues an observe record. Called by observe when the
// observation emitted or changed deny-window state.
func (s *Store) journalEntry(k string, entry *Entry, events []Event) {
	copied := *entry
	copied.Escalated = slices.Clone(entry.Escalated)
	s.pending = append(s.pending, journalRecord{Type: recordObserve, Key: k, Entry: &copied, Events: slices.Clone(events)})
}

// journalSigner queues a signer record for a new or changed inspection result.
func (s *Store) journalSigner(path string, v SignerEntry) {
	s.pending = append(s.pending, journalRecord{Type: recordSigner, Path: path, Signer: &v})
}

// heartbeat applies the collectors' observations to coverage, as a snapshot
// does, and captures the silent state. It reports false when the coverage
// tail is too long for a journal record.
func (s *Store) heartbeat(now time.Time) (*heartbeat, bool) {
	s.applyCollectors(now)
	st := &s.State
	st.Updated = now
	h := &heartbeat{Parser: st.Parser, Netfilter: st.Netfilter, NetfilterError: st.NetfilterError, NettopUnrecognized: st.NettopUnrecognized, LastEvent: st.LastEvent, BackendHealthy: st.BackendHealthy, Updated: st.Updated, NettopError: st.NettopError, CoverageVersion: st.CoverageVersion, EvictedThrough: st.EvictedThrough, CoverageEvictedThrough: st.CoverageEvictedThrough, Health: st.Health}
	h.Health.SlowOps = slices.Clone(st.Health.SlowOps)
	spans := 0
	for _, source := range s.coverageSources() {
		tail := coverageTail{Source: source, From: s.snapOpen[source], Spans: []CoverageSpan{}}
		for _, span := range st.Coverage {
			if span.Source == source && !span.Start.Before(tail.From) {
				tail.Spans = append(tail.Spans, span)
			}
		}
		spans += len(tail.Spans)
		h.Coverage = append(h.Coverage, tail)
	}
	return h, spans <= journalMaxTailSpans
}

// coverageSources lists every source with a span, sorted.
func (s *Store) coverageSources() []string {
	var sources []string
	for _, span := range s.State.Coverage {
		if !slices.Contains(sources, span.Source) {
			sources = append(sources, span.Source)
		}
	}
	slices.Sort(sources)
	return sources
}

// markSnapshot records each source's open span (its last span) after a
// snapshot: later heartbeats carry the spans from there on.
func (s *Store) markSnapshot() {
	s.snapOpen = map[string]time.Time{}
	for _, span := range s.State.Coverage {
		s.snapOpen[span.Source] = span.Start
	}
}

// snapshotDue reports whether the next durable write must be a snapshot.
func (s *Store) snapshotDue(now time.Time) bool {
	return s.journalBroken || s.journalRecords >= journalSnapshotRecords || s.journalBytes >= journalSnapshotBytes ||
		(!s.lastSnapshot.IsZero() && !now.Before(s.lastSnapshot.Add(journalSnapshotInterval)))
}

// appendJournal appends the pending records, and a heartbeat when asked, in
// one write followed by a full sync. After a failed append nothing more is
// appended until a snapshot has replaced the journal, so a torn write can
// only be the journal's last line.
func (s *Store) appendJournal(now time.Time, withHeartbeat bool) (err error) {
	start := time.Now()
	records := s.pending
	defer func() {
		d, at := time.Since(start), time.Now()
		s.State.Health.Journal.observe(d, at)
		s.State.Health.recordSlow(SlowJournal, d, at, len(records))
	}()
	if withHeartbeat {
		h, ok := s.heartbeat(now)
		if !ok {
			return errJournalTail
		}
		records = append(records, journalRecord{Type: recordHeartbeat, Heartbeat: h})
	}
	var buf bytes.Buffer
	seq := s.seq
	events := false
	for i := range records {
		seq++
		records[i].Seq = seq
		line, e := json.Marshal(records[i])
		if e != nil {
			return e
		}
		buf.Write(line)
		buf.WriteByte('\n')
		events = events || len(records[i].Events) > 0
	}
	path := s.journalPath()
	if e := safeExisting(path); e != nil {
		return e
	}
	_, statErr := os.Lstat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if e != nil {
		return e
	}
	defer func() {
		if err != nil {
			s.journalBroken = true
		}
	}()
	if s.journalWrite != nil {
		e = s.journalWrite(f, buf.Bytes())
	} else {
		_, e = f.Write(buf.Bytes())
	}
	if e == nil {
		e = f.Sync()
	}
	if e = errors.Join(e, f.Close()); e != nil {
		return e
	}
	if created {
		// The new journal's directory entry must survive a crash too.
		if e = syncDir(s.Config.StateDir); e != nil {
			return e
		}
	}
	s.seq = seq
	s.pending = nil
	s.journalRecords += len(records)
	s.journalBytes += int64(buf.Len())
	if events && !s.State.LastEvent.IsZero() {
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

var errJournalTail = errors.New("coverage tail too long for a heartbeat")

// rotateJournal removes the journal after a snapshot that folded it in. The
// snapshot's rename is made durable first, so a crash leaves either the old
// snapshot with the whole journal or the new snapshot (skipping records up to
// its journal_seq), never a lost record.
func (s *Store) rotateJournal() error {
	if e := syncDir(s.Config.StateDir); e != nil {
		return e
	}
	path := s.journalPath()
	if e := safeExisting(path); e != nil {
		return e
	}
	if e := os.Remove(path); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := syncDir(s.Config.StateDir); e != nil {
		return e
	}
	s.pending = nil
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
			if i == len(lines)-1 && !torn {
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
		if e := s.applyRecord(r); e != nil {
			return torn, fmt.Errorf("journal record %d: %w", i+1, e)
		}
		s.seq = r.Seq
	}
	return torn, nil
}

func (s *Store) applyRecord(r journalRecord) error {
	st := &s.State
	switch r.Type {
	case recordObserve:
		if r.Key == "" || r.Entry == nil {
			return errors.New("incomplete observe record")
		}
		entry := *r.Entry
		st.Entries[r.Key] = &entry
		st.Events = append(st.Events, r.Events...)
		for _, event := range r.Events {
			if event.TS.After(st.LastEvent) {
				st.LastEvent = event.TS
			}
		}
	case recordSigner:
		if r.Path == "" || r.Signer == nil {
			return errors.New("incomplete signer record")
		}
		st.Signers[r.Path] = *r.Signer
	case recordHeartbeat:
		h := r.Heartbeat
		if h == nil {
			return errors.New("incomplete heartbeat record")
		}
		lastEvent := st.LastEvent
		st.Parser, st.Netfilter, st.NetfilterError, st.NettopUnrecognized = h.Parser, h.Netfilter, h.NetfilterError, h.NettopUnrecognized
		st.LastEvent, st.BackendHealthy, st.Updated, st.NettopError = h.LastEvent, h.BackendHealthy, h.Updated, h.NettopError
		st.CoverageVersion, st.EvictedThrough, st.CoverageEvictedThrough, st.Health = h.CoverageVersion, h.EvictedThrough, h.CoverageEvictedThrough, h.Health
		if lastEvent.After(st.LastEvent) {
			st.LastEvent = lastEvent
		}
		for _, tail := range h.Coverage {
			kept := st.Coverage[:0]
			for _, span := range st.Coverage {
				if span.Source != tail.Source || span.Start.Before(tail.From) {
					kept = append(kept, span)
				}
			}
			st.Coverage = append(kept, tail.Spans...)
		}
	default:
		return fmt.Errorf("unknown record type %q", r.Type)
	}
	return nil
}
