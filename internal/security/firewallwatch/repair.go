package firewallwatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// RepairChange is one value the repair moved: in state.json (Seq 0) or in a
// journal record. Item names an entry by the SHA-256 of its key (keys can
// hold application paths) or a coverage span by position.
type RepairChange struct {
	File  string `json:"file"`
	Seq   uint64 `json:"seq,omitempty"`
	Check string `json:"check"`
	Item  string `json:"item"`
	Field string `json:"field"`
}

// RepairReport is the result of Repair.
type RepairReport struct {
	Out        string            `json:"out"`
	Originals  map[string]string `json:"originals_sha256"`
	Changes    []RepairChange    `json:"changes"`
	Records    int               `json:"journal_records"`
	TornTail   bool              `json:"journal_torn_tail"`
	Opens      bool              `json:"repaired_opens"`
	OpenError  string            `json:"repaired_open_error,omitempty"`
	BeforeOpen string            `json:"original_open_error,omitempty"`
}

// Repair is the operator's recovery for state that a backward wall-clock
// step made unreadable (a last_seen before first_seen or window_start, a
// coverage span or stall whose wall times run backward). It never writes the
// state directory's files (only the watcher's lock file is opened, and
// created if missing, as a watcher run does): it refuses while a watcher holds the directory's lock
// or when out exists, copies state.json and the journal byte for byte to
// out/original with their SHA-256, and writes to out/repaired the same files
// with each reversed time moved forward to the earlier time it must not
// precede (the watcher's own rule: last_seen never moves back, spans and
// stalls never run backward). Lines and records it does not change keep their
// bytes. A journal line that is not a valid record, other than a torn last
// line, is refused as before, and nothing is repaired. The report lists every
// change and whether the repaired directory opens with the normal reader;
// installing it is the operator's separate step.
func Repair(c Config, out string) (RepairReport, error) {
	report := RepairReport{Out: out, Originals: map[string]string{}}
	if e := checkDir(c.StateDir); e != nil {
		return report, e
	}
	absOut, e := filepath.Abs(out)
	if e != nil {
		return report, e
	}
	// Checked on the output's parent as the kernel resolves it, so a symlink
	// or a case variant on a case-insensitive volume cannot lead into the
	// state directory.
	inside, e := insideDir(filepath.Dir(absOut), c.StateDir)
	if e != nil {
		return report, fmt.Errorf("repair output: %w", e)
	}
	if inside {
		return report, errors.New("repair output must be outside the state directory")
	}
	if _, e := os.Lstat(absOut); !errors.Is(e, os.ErrNotExist) {
		return report, fmt.Errorf("repair output %s already exists", out)
	}
	unlock, e := (&Store{Config: c}).Lock()
	if e != nil {
		return report, fmt.Errorf("the watcher must be stopped: %w", e)
	}
	defer unlock()
	if _, e := OpenStore(c); e != nil {
		report.BeforeOpen = e.Error()
	}
	originals, repaired := filepath.Join(absOut, "original"), filepath.Join(absOut, "repaired")
	for _, dir := range []string{absOut, originals, repaired} {
		if e := os.Mkdir(dir, 0700); e != nil {
			return report, e
		}
	}
	files := map[string][]byte{}
	var sums bytes.Buffer
	for _, name := range []string{"state.json", journalFile} {
		f, e := openPrivate(filepath.Join(c.StateDir, name))
		if e != nil {
			return report, e
		}
		if f == nil { // absent: no journal since the last snapshot
			continue
		}
		b, e := readAllLimited(f, c.MaxStateBytes)
		f.Close()
		if e != nil {
			return report, fmt.Errorf("%s: %w", name, e)
		}
		sum := sha256.Sum256(b)
		report.Originals[name] = hex.EncodeToString(sum[:])
		if e := os.WriteFile(filepath.Join(originals, name), b, 0600); e != nil {
			return report, e
		}
		fmt.Fprintf(&sums, "%s  %s\n", report.Originals[name], name)
		files[name] = b
	}
	if e := os.WriteFile(filepath.Join(originals, "SHA256SUMS"), sums.Bytes(), 0600); e != nil {
		return report, e
	}
	outputs := map[string][]byte{}
	if b, ok := files["state.json"]; ok {
		var st State
		if e := json.Unmarshal(b, &st); e != nil {
			return report, fmt.Errorf("state.json: %w", e)
		}
		changes := repairEntries(st.Entries, "state.json", 0)
		changes = append(changes, repairSpans(st.Coverage, "state.json", 0, nil)...)
		if len(changes) > 0 {
			report.Changes = append(report.Changes, changes...)
			if b, e = json.Marshal(st); e != nil {
				return report, e
			}
		}
		outputs["state.json"] = b
	}
	if b, ok := files[journalFile]; ok {
		lines := bytes.Split(b, []byte("\n"))
		torn := len(lines[len(lines)-1]) > 0
		var outBuf bytes.Buffer
		for i, line := range lines {
			last := i == len(lines)-1
			if last && !torn {
				break
			}
			var r journalRecord
			if e := json.Unmarshal(line, &r); e != nil {
				if last && !json.Valid(line) {
					report.TornTail = true
					outBuf.Write(line) // kept: the reader drops a torn last line
					break
				}
				return report, fmt.Errorf("journal record %d is not repairable (%v); nothing was repaired", i+1, e)
			}
			report.Records++
			changes := repairEntries(r.Entries, journalFile, r.Seq)
			if h := r.Heartbeat; h != nil {
				var opens []CoverageSpan
				for _, o := range h.Coverage.Open {
					opens = append(opens, o.Span)
				}
				open := repairSpans(opens, journalFile, r.Seq, func(i int) int { return h.Coverage.Open[i].Index })
				for i := range h.Coverage.Open {
					h.Coverage.Open[i].Span = opens[i]
				}
				changes = append(changes, open...)
				changes = append(changes, repairSpans(h.Coverage.Appended, journalFile, r.Seq, func(i int) int { return h.Coverage.Base + i })...)
			}
			if len(changes) > 0 {
				report.Changes = append(report.Changes, changes...)
				if line, e = json.Marshal(r); e != nil {
					return report, e
				}
			}
			outBuf.Write(line)
			if !last {
				outBuf.WriteByte('\n')
			}
		}
		outputs[journalFile] = outBuf.Bytes()
	}
	// Written only once both files repaired: a refused journal leaves no
	// partial repair behind.
	for name, b := range outputs {
		if e := os.WriteFile(filepath.Join(repaired, name), b, 0600); e != nil {
			return report, e
		}
	}
	check := c
	check.StateDir = repaired
	if _, e := OpenStore(check); e != nil {
		report.OpenError = e.Error()
		return report, nil
	}
	report.Opens = true
	return report, nil
}

// insideDir reports whether dir is root or lies below it. It climbs from dir
// through ".." as the kernel resolves it, comparing each directory with root
// by device and inode, so symlinks and case variants are followed rather than
// compared as text. A climb that does not reach the volume root within 256
// steps is refused.
func insideDir(dir, root string) (bool, error) {
	rootInfo, e := os.Stat(root)
	if e != nil {
		return false, e
	}
	p := dir
	for range 256 {
		info, e := os.Stat(p)
		if e != nil {
			return false, e
		}
		if os.SameFile(info, rootInfo) {
			return true, nil
		}
		parent := p + string(filepath.Separator) + ".."
		up, e := os.Stat(parent)
		if e != nil {
			return false, e
		}
		if os.SameFile(up, info) {
			return false, nil
		}
		p = parent
	}
	return false, errors.New("too deep to check against the state directory")
}

func readAllLimited(f *os.File, limit int64) ([]byte, error) {
	var b bytes.Buffer
	n, e := b.ReadFrom(io.LimitReader(f, limit+1))
	if e != nil {
		return nil, e
	}
	if n > limit {
		return nil, errors.New("exceeds max_state_bytes")
	}
	return b.Bytes(), nil
}

// repairEntries moves each entry's last_seen forward to its first_seen or
// window_start when it is earlier by wall time. Keys are visited in order, so
// the report is the same on every run.
func repairEntries(entries map[string]*Entry, file string, seq uint64) []RepairChange {
	var changes []RepairChange
	for _, k := range slices.Sorted(maps.Keys(entries)) {
		v := entries[k]
		if v == nil {
			continue
		}
		latest := v.LastSeen
		for _, t := range []time.Time{v.FirstSeen, v.WindowStart} {
			if wallBefore(latest, t) {
				latest = t
			}
		}
		if !latest.Equal(v.LastSeen) {
			sum := sha256.Sum256([]byte(k))
			changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkEntryOrder, Item: "entry " + hex.EncodeToString(sum[:6]), Field: "last_seen"})
			v.LastSeen = latest
		}
	}
	return changes
}

// repairSpans makes each span's wall times run forward, erring toward
// "unavailable": an end before the start moves to the start; a stall that
// starts before the span's end shortens the covered span to the stall's
// start (never before the span's start), one that starts after it extends
// back to the span's end; a stall end before its start moves to the start.
// position names a span for the report.
func repairSpans(spans []CoverageSpan, file string, seq uint64, position func(int) int) []RepairChange {
	var changes []RepairChange
	name := func(i int) string {
		if position != nil {
			i = position(i)
		}
		return fmt.Sprintf("span %d", i)
	}
	for i := range spans {
		sp := &spans[i]
		if wallBefore(sp.End, sp.Start) {
			changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkSpanOrder, Item: name(i), Field: "end"})
			sp.End = sp.Start
		}
		if st := sp.StallAfter; st != nil {
			switch {
			case wallBefore(st.From, sp.End) && !wallBefore(st.From, sp.Start):
				changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkStallOrder, Item: name(i), Field: "end"})
				sp.End = st.From
			case !st.From.Round(0).Equal(sp.End.Round(0)):
				changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkStallOrder, Item: name(i), Field: "stall_after.from"})
				st.From = sp.End
			}
			if wallBefore(st.To, st.From) {
				changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkStallOrder, Item: name(i), Field: "stall_after.to"})
				st.To = st.From
			}
		}
	}
	return changes
}
