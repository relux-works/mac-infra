// Package journal is the bounded, hash-chained incident journal of the
// netfilter tool (spec-journal.md on STORY-261023-qbc86k). It holds only
// warnings, alarms, enforcement actions and their reporting, never per-flow
// records, in a ring of the newest Capacity entries.
package journal

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Capacity is the number of retained entries (owner decision 2026-10-23:
// a round robin of about 10k, warnings and alarms only).
const Capacity = 10000

// MaxEntryBytes bounds one canonical entry, so the journal stays below about
// Capacity * MaxEntryBytes (10 MB) between compactions. About 330 bytes of an
// entry are keys, timestamps and the two hashes.
const MaxEntryBytes = 1024

// Kinds that may be journaled; anything else is refused.
var kinds = map[string]bool{
	"warning": true, "alarm": true,
	"kill_intent": true, "kill_result": true,
	"block_intent": true, "block_result": true,
	"unblock": true, "undo": true,
	"reconcile_mismatch": true,
	"report_pending":     true, "report_done": true,
}

// Entry is one journal record. Seq is assigned by Append, never reused, and
// increases by one; Hash chains each entry to the previous one.
type Entry struct {
	Seq      uint64     `json:"seq"`
	TS       time.Time  `json:"ts"`
	Kind     string     `json:"kind"`
	Source   string     `json:"source"`
	Actor    string     `json:"actor"`
	Target   string     `json:"target"`
	Action   string     `json:"action"`
	Expiry   *time.Time `json:"expiry,omitempty"`
	Undo     string     `json:"undo,omitempty"`
	Ref      uint64     `json:"ref,omitempty"`
	PrevHash string     `json:"prev_hash"`
	Hash     string     `json:"hash"`
}

func (e Entry) digest() string {
	e.Hash = ""
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Journal is a journal file in an owner-only directory. Appends from several
// processes (the watcher and the CLI) are serialised by a lock file.
type Journal struct {
	dir      string
	capacity int
}

const fileName = "journal.ndjson"

// Open uses dir (created 0700 if missing; it must be a caller-owned,
// non-symlink 0700 directory). capacity is normally Capacity; tests pass less.
func Open(dir string, capacity int) (*Journal, error) {
	if capacity < 1 {
		return nil, errors.New("journal capacity must be positive")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !ok || int(st.Uid) != os.Getuid() {
		return nil, errors.New("journal dir must be owned by caller, non-symlink and mode 0700")
	}
	return &Journal{dir: dir, capacity: capacity}, nil
}

func (j *Journal) path() string { return filepath.Join(j.dir, fileName) }

func (j *Journal) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(j.dir, "journal.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Read returns the retained entries, oldest first.
func (j *Journal) Read() ([]Entry, error) {
	f, err := os.OpenFile(j.path(), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), 4*MaxEntryBytes)
	for sc.Scan() {
		var e Entry
		d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		d.DisallowUnknownFields()
		if err := d.Decode(&e); err != nil {
			return nil, fmt.Errorf("journal record %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Verify checks that seq increases by one and that every hash and chain link
// holds inside the window. The first retained entry anchors the chain.
func Verify(entries []Entry) error {
	for i, e := range entries {
		if e.Hash != e.digest() {
			return fmt.Errorf("journal seq %d: hash mismatch", e.Seq)
		}
		if i > 0 {
			if e.Seq != entries[i-1].Seq+1 {
				return fmt.Errorf("journal seq %d follows %d", e.Seq, entries[i-1].Seq)
			}
			if e.PrevHash != entries[i-1].Hash {
				return fmt.Errorf("journal seq %d: broken chain", e.Seq)
			}
		}
	}
	return nil
}

func validate(e Entry) error {
	if !kinds[e.Kind] {
		return fmt.Errorf("journal kind %q not allowed", e.Kind)
	}
	if e.TS.IsZero() || e.Actor == "" || e.Action == "" {
		return errors.New("journal entry needs ts, actor and action")
	}
	return nil
}

// Append assigns the next seq, chains, writes and fsyncs the entry before
// returning it, so a caller that proceeds only after a nil error never acts
// unjournaled. When the file holds more than the capacity plus a tenth, it
// is compacted atomically to the newest capacity entries.
func (j *Journal) Append(e Entry) (Entry, error) {
	if err := validate(e); err != nil {
		return Entry{}, err
	}
	unlock, err := j.lock()
	if err != nil {
		return Entry{}, err
	}
	defer unlock()
	entries, err := j.Read()
	if err != nil {
		return Entry{}, err
	}
	if err = Verify(entries); err != nil {
		return Entry{}, err
	}
	e.Seq, e.PrevHash = 1, ""
	if n := len(entries); n > 0 {
		e.Seq, e.PrevHash = entries[n-1].Seq+1, entries[n-1].Hash
	}
	e.Hash = e.digest()
	line, _ := json.Marshal(e)
	if len(line) > MaxEntryBytes {
		return Entry{}, fmt.Errorf("journal entry is %d bytes, limit %d", len(line), MaxEntryBytes)
	}
	f, err := os.OpenFile(j.path(), os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return Entry{}, err
	}
	if _, err = f.Write(append(line, '\n')); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Entry{}, err
	}
	if len(entries)+1 > j.capacity+j.capacity/10 {
		if err = j.compact(append(entries, e)); err != nil {
			return Entry{}, err
		}
	}
	return e, nil
}

// compact rewrites the file with the newest capacity entries via a synced
// temporary file and an atomic rename.
func (j *Journal) compact(entries []Entry) error {
	keep := entries[len(entries)-j.capacity:]
	tmp, err := os.CreateTemp(j.dir, ".journal-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, e := range keep {
		line, _ := json.Marshal(e)
		w.Write(append(line, '\n'))
	}
	if err = w.Flush(); err == nil {
		err = tmp.Chmod(0600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), j.path())
}
