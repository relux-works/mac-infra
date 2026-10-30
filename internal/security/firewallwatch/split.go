package firewallwatch

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Split buckets and known false-positive groups for `watch digest --split`.
const (
	KnownFPNettopRawIP       = "nettop_policy_raw_ip"
	KnownFPALFUnknownOrAllow = "alf_unknown_or_allow_decide"
	KnownFPLoopbackSSHKNN    = "loopback_ssh_limactl_knn"
)

// SplitRow is one retained event as shown in a split bucket.
type SplitRow struct {
	TS          time.Time `json:"ts"`
	Source      string    `json:"source"`
	App         string    `json:"app"`
	Verdict     string    `json:"verdict"`
	Port        *int      `json:"port"`
	RemoteClass string    `json:"remote_class"`
	Bucket      string    `json:"bucket"`
	Counts      uint64    `json:"counts"`
	Label       string    `json:"proposed_label"`
	Reason      string    `json:"reason"`
}

// SplitGroup is one known false-positive cause with its rows.
type SplitGroup struct {
	Count int        `json:"count"`
	Rows  []SplitRow `json:"rows"`
}

const (
	GapNotRunning      = "not_running"
	GapStall           = "stall"
	GapCoverageEvicted = "coverage_evicted"
	GapLegacyUnknown   = "legacy_unknown"
	// GapWriteRefused is a not_running gap during which a run ended because
	// the shape check refused a write (refusal.go).
	GapWriteRefused = "write_refused"
)

// SplitGap is a part of the window with unavailable or unknown coverage.
type SplitGap struct {
	Kind string    `json:"kind"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Detail names the refused check of a write_refused gap and whether the
	// same check was refused before within the last restarts.
	Detail string `json:"detail,omitempty"`
}

// CoalescedShortStalls sums whole intersecting ALF spans; exact stall positions
// are unavailable, so these totals can include stalls outside the window.
type CoalescedShortStalls struct {
	Count     uint64 `json:"count"`
	StalledNS int64  `json:"stalled_ns"`
}

// SplitWindow describes the events actually covered. Truncated is set when
// part of [since, as_of] may be missing: a coverage gap (watcher stopped,
// crashed, restarted, stalled or never recorded), evicted history, or a span
// with coalesced short stalls whose precise positions are no longer known.
type SplitWindow struct {
	Since                  time.Time            `json:"since"`
	AsOf                   time.Time            `json:"as_of"`
	FirstTS                *time.Time           `json:"first_ts"`
	LastTS                 *time.Time           `json:"last_ts"`
	EventsInWindow         int                  `json:"events_in_window"`
	CoverageGaps           []SplitGap           `json:"coverage_gaps"`
	CoalescedShortStalls   CoalescedShortStalls `json:"coalesced_short_stalls"`
	EvictedThrough         *time.Time           `json:"evicted_through"`
	CoverageEvictedThrough *time.Time           `json:"coverage_evicted_through"`
	Truncated              bool                 `json:"truncated"`
	SlowOps                WindowSlowOps        `json:"slow_ops"`
}

// WindowSlowOps holds the slow-operation records that completed in
// [since, as_of] and each kind's count and maximum there. An operation counts
// in the window of its completion, even if it started earlier. DroppedThrough
// is set when the record's bound dropped operations that completed at or after
// since, so the window may lack some.
type WindowSlowOps struct {
	Records        []SlowOp                  `json:"records"`
	Kinds          map[string]WindowSlowKind `json:"kinds"`
	DroppedThrough *time.Time                `json:"dropped_through"`
}

// WindowSlowKind is one kind's count and maximum within a window.
type WindowSlowKind struct {
	Count int       `json:"count"`
	MaxNS int64     `json:"max_ns"`
	MaxAt time.Time `json:"max_at"`
}

func windowSlowOps(h RunHealth, since, asOf time.Time) WindowSlowOps {
	w := WindowSlowOps{Records: []SlowOp{}, Kinds: map[string]WindowSlowKind{}}
	for _, op := range h.SlowOps {
		if op.At.Before(since) || op.At.After(asOf) {
			continue
		}
		w.Records = append(w.Records, op)
		k := w.Kinds[op.Kind]
		k.Count++
		if k.Count == 1 || op.NS > k.MaxNS {
			k.MaxNS, k.MaxAt = op.NS, op.At
		}
		w.Kinds[op.Kind] = k
	}
	if d := h.SlowOpsDroppedThrough; d != nil && !d.Before(since) {
		at := *d
		w.DroppedThrough = &at
	}
	return w
}

// DigestSplit is the deterministic triage view of one digest window.
type DigestSplit struct {
	Window      SplitWindow           `json:"window"`
	Health      map[string]any        `json:"health"`
	RealDeny    []SplitRow            `json:"real_deny"`
	KnownFP     map[string]SplitGroup `json:"known_fp"`
	NeedsReview []SplitRow            `json:"needs_review"`
}

// Split classifies every retained event at or after since into at most one
// bucket, with precedence real_deny > known_fp > needs_review:
//   - real_deny: non-nettop events whose verdict is deny, denied, block,
//     blocked or drop (any case), whatever their label;
//   - known_fp: decide events of a known false-positive cause (nettop rows
//     decided by policy_raw_ip; ALF rows with verdict unknown or allow;
//     kNN-decided loopback rows of ssh or limactl);
//   - needs_review: every other decide event.
//
// Events labelled noise or digest that are not denies appear in no bucket.
// Events after asOf are outside the window.
func (s *Store) Split(since, asOf time.Time) DigestSplit {
	split := DigestSplit{
		Window:      SplitWindow{Since: since, AsOf: asOf, CoverageGaps: s.coverageGaps(since, asOf), SlowOps: windowSlowOps(s.State.Health, since, asOf)},
		Health:      s.Status(),
		RealDeny:    []SplitRow{},
		KnownFP:     map[string]SplitGroup{},
		NeedsReview: []SplitRow{},
	}
	for _, group := range []string{KnownFPNettopRawIP, KnownFPALFUnknownOrAllow, KnownFPLoopbackSSHKNN} {
		split.KnownFP[group] = SplitGroup{Rows: []SplitRow{}}
	}
	for i := range s.State.Events {
		e := s.State.Events[i]
		if e.TS.Before(since) || e.TS.After(asOf) {
			continue
		}
		split.Window.EventsInWindow++
		if split.Window.FirstTS == nil || e.TS.Before(*split.Window.FirstTS) {
			ts := e.TS
			split.Window.FirstTS = &ts
		}
		if split.Window.LastTS == nil || e.TS.After(*split.Window.LastTS) {
			ts := e.TS
			split.Window.LastTS = &ts
		}
		row := splitRow(e)
		switch {
		case e.Source != "nettop" && denyVerdict(e.Verdict):
			split.RealDeny = append(split.RealDeny, row)
		case e.Label != "decide":
		case e.Source == "nettop" && row.Reason == "policy_raw_ip":
			split.addKnownFP(KnownFPNettopRawIP, row)
		case e.Source == "alf" && (e.Verdict == "unknown" || e.Verdict == "allow"):
			split.addKnownFP(KnownFPALFUnknownOrAllow, row)
		case row.Reason == "knn" && e.RemoteClass == "loopback" && (appBase(e.App) == "ssh" || appBase(e.App) == "limactl"):
			split.addKnownFP(KnownFPLoopbackSSHKNN, row)
		default:
			split.NeedsReview = append(split.NeedsReview, row)
		}
	}
	if evicted := s.State.EvictedThrough; !evicted.IsZero() {
		split.Window.EvictedThrough = &evicted
	}
	if evicted := s.State.CoverageEvictedThrough; !evicted.IsZero() {
		split.Window.CoverageEvictedThrough = &evicted
	}
	split.Window.Truncated = len(split.Window.CoverageGaps) > 0 || (split.Window.EvictedThrough != nil && !split.Window.EvictedThrough.Before(since)) || (split.Window.CoverageEvictedThrough != nil && !split.Window.CoverageEvictedThrough.Before(since))
	// Compaction preserves counts rather than exact timestamps. Any window
	// touching that span may include a short stall, so remain conservative.
	for _, span := range s.State.Coverage {
		if since.Before(asOf) && span.Source == "" && span.Start.Before(asOf) && span.End.After(since) {
			total := &split.Window.CoalescedShortStalls
			total.Count = addCount(total.Count, span.ShortStalls)
			total.StalledNS = addNS(total.StalledNS, span.ShortStalledNS)
			if span.ShortStalls > 0 {
				split.Window.Truncated = true
			}
		}
	}
	sortRows := func(rows []SplitRow) {
		sort.SliceStable(rows, func(i, j int) bool { return rows[i].TS.Before(rows[j].TS) })
	}
	sortRows(split.RealDeny)
	sortRows(split.NeedsReview)
	for name, group := range split.KnownFP {
		sortRows(group.Rows)
		split.KnownFP[name] = group
	}
	return split
}

// coverageGaps sweeps recorded ALF coverage and exact stalls. Evicted history
// is unknown even if a retained span overlaps it. The existing tail grace
// applies only to unrecorded time after coverage, never to an explicit stall.
func (s *Store) coverageGaps(since, asOf time.Time) []SplitGap {
	gaps := []SplitGap{}
	if !since.Before(asOf) {
		return gaps
	}
	type boundary struct {
		at                       time.Time
		covered, stalled, legacy int
	}
	points := []boundary{{at: since}, {at: asOf}}
	add := func(from, to time.Time, covered, stalled, legacy int) {
		if from.Before(since) {
			from = since
		}
		if to.After(asOf) {
			to = asOf
		}
		if !from.Before(to) {
			return
		}
		points = append(points, boundary{from, covered, stalled, legacy}, boundary{to, -covered, -stalled, -legacy})
	}
	touched := false
	var lastEnd time.Time
	alf := make([]CoverageSpan, 0, len(s.State.Coverage))
	for _, span := range s.State.Coverage {
		if span.Source != "" {
			continue
		}
		alf = append(alf, span)
		add(span.Start, span.End, 1, 0, 0)
		if !span.End.Before(since) && !span.Start.After(asOf) {
			touched = true
			if span.End.After(lastEnd) {
				lastEnd = span.End
			}
		}
		if stall := span.StallAfter; stall != nil {
			add(stall.From, stall.To, 0, 1, 0)
		}
	}
	// Use the actual ALF coverage boundaries, including those outside the
	// window. Overlaps cannot invent a gap or let another source bound one.
	// At tied boundaries any legacy history keeps the cause unknown.
	sort.Slice(alf, func(i, j int) bool { return alf[i].Start.Before(alf[j].Start) })
	type interval struct {
		start, end             time.Time
		startLegacy, endLegacy bool
	}
	intervals := []interval{}
	for _, span := range alf {
		if len(intervals) == 0 || span.Start.After(intervals[len(intervals)-1].end) {
			intervals = append(intervals, interval{span.Start, span.End, span.Legacy, span.Legacy})
			continue
		}
		prev := &intervals[len(intervals)-1]
		if span.Start.Equal(prev.start) {
			prev.startLegacy = prev.startLegacy || span.Legacy
		}
		if span.End.After(prev.end) {
			prev.end, prev.endLegacy = span.End, span.Legacy
		} else if span.End.Equal(prev.end) {
			prev.endLegacy = prev.endLegacy || span.Legacy
		}
	}
	for i := 1; i < len(intervals); i++ {
		left, right := intervals[i-1], intervals[i]
		if left.endLegacy && right.startLegacy {
			add(left.end, right.start, 0, 0, 1)
		}
	}
	evicted := s.State.CoverageEvictedThrough
	if evicted.After(since) && evicted.Before(asOf) {
		points = append(points, boundary{at: evicted})
	}
	sort.Slice(points, func(i, j int) bool { return points[i].at.Before(points[j].at) })
	covered, stalled, legacy := 0, 0, 0
	grace := duration(s.Config.NettopInterval) + duration(s.Config.SaveInterval)
	for i := 0; i < len(points); {
		from := points[i].at
		for i < len(points) && points[i].at.Equal(from) {
			covered += points[i].covered
			stalled += points[i].stalled
			legacy += points[i].legacy
			i++
		}
		if i == len(points) {
			break
		}
		to := points[i].at
		kind := ""
		switch {
		case from.Before(evicted):
			kind = GapCoverageEvicted
		case stalled > 0:
			kind = GapStall
		case covered > 0:
		case legacy > 0:
			kind = GapLegacyUnknown
		case touched && !from.Before(lastEnd) && asOf.Sub(lastEnd) <= grace:
		default:
			kind = GapNotRunning
		}
		if kind == "" {
			continue
		}
		if len(gaps) > 0 && gaps[len(gaps)-1].Kind == kind && gaps[len(gaps)-1].To.Equal(from) {
			gaps[len(gaps)-1].To = to
		} else {
			gaps = append(gaps, SplitGap{From: from, To: to, Kind: kind})
		}
	}
	return s.labelRefusals(gaps)
}

// labelRefusals marks each not_running gap that contains a recorded write
// refusal as write_refused, naming the check and any repeat.
func (s *Store) labelRefusals(gaps []SplitGap) []SplitGap {
	for i := range gaps {
		if gaps[i].Kind != GapNotRunning {
			continue
		}
		for _, r := range s.State.WriteRefusals {
			if r.At.Before(gaps[i].From) || r.At.After(gaps[i].To) {
				continue
			}
			gaps[i].Kind = GapWriteRefused
			gaps[i].Detail = r.Kind + " " + r.Check
			if r.Repeats > 0 {
				gaps[i].Detail += fmt.Sprintf(", repeated: %d earlier refusal(s) of this check in the last %d", r.Repeats, refusalLoopRestarts)
			}
		}
	}
	return gaps
}

func (d *DigestSplit) addKnownFP(group string, row SplitRow) {
	g := d.KnownFP[group]
	g.Count++
	g.Rows = append(g.Rows, row)
	d.KnownFP[group] = g
}

func splitRow(e Event) SplitRow {
	return SplitRow{TS: e.TS, Source: e.Source, App: e.App, Verdict: e.Verdict, Port: e.Port, RemoteClass: e.RemoteClass, Bucket: e.Bucket, Counts: e.Counts, Label: e.Label, Reason: reasonKind(e.Reason)}
}

// reasonKind names an event's reason: the rule name for rule decisions, or
// the kind ("knn") for structured reasons, whether the event came from disk
// (string or decoded map) or from memory (a struct).
func reasonKind(reason any) string {
	switch r := reason.(type) {
	case nil:
		return ""
	case string:
		return r
	case map[string]any:
		if kind, ok := r["kind"].(string); ok {
			return kind
		}
		return ""
	}
	data, err := json.Marshal(reason)
	if err != nil {
		return ""
	}
	var decoded struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(data, &decoded) != nil {
		return ""
	}
	return decoded.Kind
}

// denyVerdict reports a blocking verdict. nettop only observes traffic, so
// its rows never count as denies whatever their verdict text.
func denyVerdict(verdict string) bool {
	for _, deny := range []string{"deny", "denied", "block", "blocked", "drop"} {
		if strings.EqualFold(verdict, deny) {
			return true
		}
	}
	return false
}

func appBase(app string) string { return filepath.Base(app) }
