package firewallwatch

import (
	"encoding/json"
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

// SplitGap is part of the window in which no watcher was recorded running.
type SplitGap struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// SplitWindow describes the events actually covered. Truncated is set when
// part of [since, as_of] may be missing: a coverage gap (watcher stopped,
// crashed, restarted or never recorded) or a pruned event at or after since.
type SplitWindow struct {
	Since          time.Time  `json:"since"`
	AsOf           time.Time  `json:"as_of"`
	FirstTS        *time.Time `json:"first_ts"`
	LastTS         *time.Time `json:"last_ts"`
	EventsInWindow int        `json:"events_in_window"`
	CoverageGaps   []SplitGap `json:"coverage_gaps"`
	EvictedThrough *time.Time `json:"evicted_through"`
	Truncated      bool       `json:"truncated"`
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
		Window:      SplitWindow{Since: since, AsOf: asOf, CoverageGaps: s.coverageGaps(since, asOf)},
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
	split.Window.Truncated = len(split.Window.CoverageGaps) > 0 || (split.Window.EvictedThrough != nil && !split.Window.EvictedThrough.Before(since))
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

// coverageGaps lists the parts of [since, asOf] covered by no recorded watcher
// span. When a span reaches the window, the time after the last covered point
// is a gap only if longer than nettop_interval + save_interval, the expected
// save cadence of a live watcher (a save delayed longer only adds a spurious
// gap). Without such a span the whole window is a gap whatever its length;
// gaps between spans count whatever their length.
func (s *Store) coverageGaps(since, asOf time.Time) []SplitGap {
	gaps := []SplitGap{}
	spans := append([]CoverageSpan(nil), s.State.Coverage...)
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].Start.Before(spans[j].Start) })
	cursor := since
	touched := false
	for _, span := range spans {
		if !cursor.Before(asOf) {
			break
		}
		if span.End.Before(cursor) {
			continue
		}
		touched = true
		if span.Start.After(cursor) {
			to := span.Start
			if to.After(asOf) {
				to = asOf
			}
			gaps = append(gaps, SplitGap{From: cursor, To: to})
		}
		if span.End.After(cursor) {
			cursor = span.End
		}
	}
	grace := duration(s.Config.NettopInterval) + duration(s.Config.SaveInterval)
	if cursor.Before(asOf) && (!touched || asOf.Sub(cursor) > grace) {
		gaps = append(gaps, SplitGap{From: cursor, To: asOf})
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
