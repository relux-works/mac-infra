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
	Out       string            `json:"out"`
	Originals map[string]string `json:"originals_sha256"`
	Changes   []RepairChange    `json:"changes"`
	Records   int               `json:"journal_records"`
	TornTail  bool              `json:"journal_torn_tail"`
	Opens     bool              `json:"repaired_opens"`
	OpenError string            `json:"repaired_open_error,omitempty"`
	// Starts is whether a watcher start on the repaired files succeeds: it
	// records a refusal marker left in the state directory and saves. Checked
	// on a disposable copy only when the repaired files open.
	Starts     bool   `json:"repaired_starts"`
	StartError string `json:"repaired_start_error,omitempty"`
	// StartCheckError is a failure to prepare or remove the start check's
	// copy: the start was not tried, or its copy was left at the named path.
	StartCheckError string `json:"start_check_error,omitempty"`
	// RetainedUnsafe names the files the install leaves in the state
	// directory (the new-events flag and the daily event files) that a
	// watcher start would refuse to touch, with the reason: not a private
	// regular file of the caller with one link. The start check's copy does
	// not hold them, so they are checked in place, read-only.
	RetainedUnsafe []string `json:"retained_unsafe,omitempty"`
	BeforeOpen     string   `json:"original_open_error,omitempty"`
}

// Repair is the operator's recovery for state that a backward wall-clock
// step made unreadable (a last_seen before first_seen or window_start, a
// coverage span or stall whose wall times run backward). It never writes the
// state directory's files (only the watcher's lock file is opened, and
// created if missing, as a watcher run does): it refuses while a watcher
// holds the directory's lock or when out exists, copies state.json, the
// journal and a refusal marker byte for byte to out/original with their
// SHA-256, and writes to out/repaired state.json and the journal with each
// reversed time moved forward to the earlier time it must not precede (the
// watcher's own rule: last_seen never moves back, spans and stalls never run
// backward). Lines and records it does not change keep their bytes, and a
// torn tail is kept as the reader treats it. A journal line the reader would
// refuse as not a record of this journal (not JSON, not a delta, a seq out of
// order or not following the snapshot) is refused, and nothing repaired is
// written. The report lists every change, whether the repaired files open
// with the normal reader, and whether a watcher start on them (with the
// marker the operator leaves in place) succeeds, tried on a disposable copy,
// and which files left in place a start would refuse; installing them is the
// operator's separate step.
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
	if report.RetainedUnsafe, e = retainedUnsafe(c.StateDir); e != nil {
		return report, e
	}
	originals, repaired := filepath.Join(absOut, "original"), filepath.Join(absOut, "repaired")
	for _, dir := range []string{absOut, originals, repaired} {
		if e := os.Mkdir(dir, 0700); e != nil {
			return report, e
		}
	}
	files := map[string][]byte{}
	var sums bytes.Buffer
	for _, name := range []string{"state.json", journalFile, refusalMarker} {
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
	// The last journal record the snapshot holds; replay applies only later
	// records, starting with the next seq.
	var folded uint64
	if b, ok := files["state.json"]; ok {
		var st State
		if e := json.Unmarshal(b, &st); e != nil {
			return report, fmt.Errorf("state.json: %w", e)
		}
		folded = st.JournalSeq
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
		// The reader's rule (replayJournal): only newline-terminated lines
		// count; a final segment without a newline is an incomplete append and
		// ignored, whatever it holds; with none, a last complete line that is
		// not valid JSON is a torn write and ignored. Either is kept as is.
		lines := bytes.Split(b, []byte("\n"))
		tail := lines[len(lines)-1]
		lines = lines[:len(lines)-1]
		var outBuf bytes.Buffer
		var prev uint64
		for i, line := range lines {
			var r journalRecord
			if e := json.Unmarshal(line, &r); e != nil {
				if i == len(lines)-1 && len(tail) == 0 && !json.Valid(line) {
					report.TornTail = true
					outBuf.Write(line)
					outBuf.WriteByte('\n')
					break
				}
				return report, fmt.Errorf("journal record %d is not repairable (%v); nothing was repaired", i+1, e)
			}
			// Decoding alone does not make a record (null decodes): the
			// reader's identity checks, before anything repaired is written.
			if r.Type != recordDelta || r.Seq == 0 || (i > 0 && r.Seq != prev+1) {
				return report, fmt.Errorf("journal record %d is not repairable (not a record of this journal: type %q, seq %d); nothing was repaired", i+1, r.Type, r.Seq)
			}
			// The first record after the snapshot's must follow it (records
			// the snapshot already holds are skipped by replay).
			if r.Seq > folded && (i == 0 || prev <= folded) && r.Seq != folded+1 {
				return report, fmt.Errorf("journal record %d is not repairable (seq %d does not follow the snapshot's %d); nothing was repaired", i+1, r.Seq, folded)
			}
			prev = r.Seq
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
			outBuf.WriteByte('\n')
		}
		if len(tail) > 0 {
			report.TornTail = true
			outBuf.Write(tail)
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
	started, startErr, checkErr := checkStart(c, filepath.Join(absOut, "startup-check"), outputs, files[refusalMarker])
	report.Starts = started
	if startErr != nil {
		report.StartError = startErr.Error()
	}
	if checkErr != nil {
		report.StartCheckError = checkErr.Error()
	}
	return report, nil
}

// checkStart tries a watcher start (openRun: record the marker, then save)
// on a disposable copy of the repaired files plus the marker, which the
// install leaves in the state directory, and removes the copy. startErr is
// openRun's refusal; checkErr is a failure to prepare or remove the copy, in
// which case the start was not tried or the copy was left behind (named).
func checkStart(c Config, dir string, outputs map[string][]byte, marker []byte) (started bool, startErr, checkErr error) {
	if e := os.Mkdir(dir, 0700); e != nil {
		return false, nil, fmt.Errorf("the start was not tried: %w", e)
	}
	remove := func() error {
		if e := os.RemoveAll(dir); e != nil {
			return fmt.Errorf("the start check's copy %s was not removed: %w", dir, e)
		}
		return nil
	}
	files := maps.Clone(outputs)
	if marker != nil {
		files[refusalMarker] = marker
	}
	for name, b := range files {
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			return false, nil, errors.Join(fmt.Errorf("the start was not tried: %w", e), remove())
		}
	}
	c.StateDir = dir
	_, startErr = openRun(c, time.Now)
	return startErr == nil, startErr, remove()
}

// retainedUnsafe applies the startup save's file check (safeExisting) to the
// files of dir that the save may rewrite or remove and the install keeps: the
// new-events flag and every daily event file (dayFiles, as the save lists
// them). It only reads metadata. A flag is named even when the next start
// would not rewrite it (no event recorded yet): any later save would.
func retainedUnsafe(dir string) ([]string, error) {
	days, e := dayFiles(dir)
	if e != nil {
		return nil, e
	}
	var unsafe []string
	for _, name := range append([]string{"new-events.flag"}, days...) {
		if e := safeExisting(filepath.Join(dir, name)); e != nil {
			unsafe = append(unsafe, name+": "+e.Error())
		}
	}
	return unsafe, nil
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
// start, or to the span's own start if the stall began earlier (the stall then
// starts there); one that starts after the span's end extends back to it; a
// stall end before its start moves to the start.
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
			case wallBefore(st.From, sp.Start):
				// The stall began before the span did: none of the span is
				// known covered. The span keeps its start and the stall starts
				// there, so the whole recorded stall stays unavailable.
				if !sp.End.Round(0).Equal(sp.Start.Round(0)) {
					changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkStallOrder, Item: name(i), Field: "end"})
					sp.End = sp.Start
				}
				changes = append(changes, RepairChange{File: file, Seq: seq, Check: checkStallOrder, Item: name(i), Field: "stall_after.from"})
				st.From = sp.End
			case wallBefore(st.From, sp.End):
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
