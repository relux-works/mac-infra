package firewallwatch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

// A write the shape check refuses ends the run: nothing the reader would
// reject is persisted. The supervisor restarts the watcher from the last
// valid state. So that the restart is not mistaken for an ordinary one, the
// ending run leaves a marker and the next start records it; the digest then
// labels the gap write_refused.
var (
	errRefusedRecord   = errors.New("refusing invalid journal record")
	errRefusedSnapshot = errors.New("refusing invalid state save")
)

const (
	refusalMarker = "last-write-refusal.json"
	// refusalLimit bounds the recorded refusals kept in the state.
	refusalLimit = 32
	// refusalLoopRestarts is how many earlier refusals are searched for the
	// same check; a match is reported as a repeat.
	refusalLoopRestarts = 3
	refusalKindJournal  = "journal"
	refusalKindSnapshot = "snapshot"
)

// WriteRefusal is a refused write, recorded at the next start. Repeats counts
// refusals of the same check among the refusalLoopRestarts recorded before it.
type WriteRefusal struct {
	At      time.Time `json:"at"`
	Check   string    `json:"check"`
	Kind    string    `json:"kind"`
	Repeats int       `json:"repeats,omitempty"`
}

// refusalMarkerFile is the marker's content: when, which check and which
// write, never a key, path or port (those go to stderr with the error).
type refusalMarkerFile struct {
	At    time.Time `json:"at"`
	Field string    `json:"field"`
	Kind  string    `json:"kind"`
}

// markWriteRefusal leaves the marker when err contains a shape-check refusal.
// A marker that cannot be written does not keep the run alive; stderr then
// carries the refusal alone.
func (s *Store) markWriteRefusal(err error) error {
	var shape shapeError
	if !errors.As(err, &shape) {
		return nil
	}
	kind := refusalKindSnapshot
	if errors.Is(err, errRefusedRecord) {
		kind = refusalKindJournal
	}
	b, e := json.Marshal(refusalMarkerFile{At: s.now(), Field: shape.check, Kind: kind})
	if e != nil {
		return e
	}
	return s.write(filepath.Join(s.Config.StateDir, refusalMarker), append(b, '\n'))
}

// takeWriteRefusal records a marker left by the previous run in the state.
// The marker is removed only after the startup snapshot holds the record
// (clearWriteRefusal). A marker that cannot be parsed is recorded with check
// "unknown" rather than ignored.
func (s *Store) takeWriteRefusal() (bool, error) {
	path := filepath.Join(s.Config.StateDir, refusalMarker)
	if e := safeExisting(path); e != nil {
		return false, e
	}
	b, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	if e != nil {
		return false, e
	}
	var m refusalMarkerFile
	if json.Unmarshal(b, &m) != nil || m.At.IsZero() || len(m.Field) == 0 || len(m.Field) > 64 || (m.Kind != refusalKindJournal && m.Kind != refusalKindSnapshot) {
		// The file's own time, so a retried start records the same refusal.
		at := s.now()
		if info, e := os.Lstat(path); e == nil {
			at = info.ModTime()
		}
		m = refusalMarkerFile{At: at, Field: "unknown", Kind: "unknown"}
	}
	r := WriteRefusal{At: m.At.Round(0), Check: m.Field, Kind: m.Kind}
	// A start that failed after its snapshot, or was interrupted before it
	// removed the marker, already recorded this refusal: record it once.
	for _, done := range s.State.WriteRefusals {
		if done.At.Equal(r.At) && done.Check == r.Check && done.Kind == r.Kind {
			return true, nil
		}
	}
	recent := s.State.WriteRefusals[max(0, len(s.State.WriteRefusals)-refusalLoopRestarts):]
	for _, earlier := range recent {
		if earlier.Check == r.Check {
			r.Repeats++
		}
	}
	s.State.WriteRefusals = append(s.State.WriteRefusals, r)
	if len(s.State.WriteRefusals) > refusalLimit {
		s.State.WriteRefusals = append([]WriteRefusal(nil), s.State.WriteRefusals[len(s.State.WriteRefusals)-refusalLimit:]...)
	}
	s.dirty = true
	return true, nil
}

func (s *Store) clearWriteRefusal() error {
	return os.Remove(filepath.Join(s.Config.StateDir, refusalMarker))
}

// openRun opens the store for a run: it sets the run clock, starts the flag
// writer, records a write refusal the previous run left, takes the startup
// snapshot (which folds a replayed journal into state.json and starts a fresh
// journal) and then removes the marker.
func openRun(c Config, now func() time.Time) (*Store, error) {
	s, e := OpenStore(c)
	if e != nil {
		return nil, e
	}
	return s.startRun(now)
}

// startRun is openRun on a store already opened.
func (s *Store) startRun(now func() time.Time) (*Store, error) {
	s.clock = now
	// The flag writer, the only writer of new-events.flag while the watcher
	// runs (flagwriter.go), starts before the startup snapshot posts its
	// stamp; every failure below stops it again.
	s.flags = startFlagWriter(s.writeFlagFile)
	fail := func(e error) (*Store, error) { return nil, errors.Join(e, s.stopFlags()) }
	marked, e := s.takeWriteRefusal()
	if e != nil {
		return fail(e)
	}
	if e = s.Save(s.now()); e != nil {
		return fail(e)
	}
	if marked {
		if e = s.clearWriteRefusal(); e != nil {
			return fail(e)
		}
	}
	return s, nil
}
