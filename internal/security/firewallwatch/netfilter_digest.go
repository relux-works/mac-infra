package firewallwatch

import (
	"encoding/json"
	"errors"
	"time"
)

type netfilterCapabilities struct {
	FlowWindowCounts        string `json:"flow_window_counts"`
	FullCodeIdentity        string `json:"full_code_identity"`
	DestinationNovelty      string `json:"destination_novelty"`
	DestinationCompleteness string `json:"destination_completeness"`
}

type netfilterWindow struct {
	Since                     time.Time         `json:"since"`
	AsOf                      time.Time         `json:"as_of"`
	EventRows                 int               `json:"event_rows"`
	OutboundEventRows         int               `json:"outbound_event_rows"`
	UnknownDirectionEventRows int               `json:"unknown_direction_event_rows"`
	FirstTS                   *time.Time        `json:"first_ts"`
	LastTS                    *time.Time        `json:"last_ts"`
	EventEvictedThrough       *time.Time        `json:"event_evicted_through"`
	Coverage                  netfilterCoverage `json:"coverage"`
}

type netfilterDigest struct {
	Schema           string                    `json:"schema"`
	Basis            string                    `json:"basis"`
	Status           string                    `json:"status"`
	Reason           string                    `json:"reason"`
	CollectionStatus string                    `json:"collection_status"`
	Capabilities     netfilterCapabilities     `json:"capabilities"`
	Window           netfilterWindow           `json:"window"`
	PerApp           []netfilterAppRow         `json:"per_app"`
	Destinations     []netfilterDestinationRow `json:"destinations"`
	UnsignedOutbound netfilterCategory         `json:"unsigned_or_adhoc_outbound"`
	OddPorts         netfilterPolicyCategory   `json:"odd_ports"`
	KnownFP          struct{}                  `json:"known_fp"`
	Alarms           netfilterAlarmSummary     `json:"alarms"`
}

// SplitWithNetfilter adds retained netfilter evidence to the existing split
// digest. It reads existing incident history without creating or repairing it.
// The legacy Split method and its fields retain their existing behavior.
func (s *Store) SplitWithNetfilter(since, asOf time.Time) (DigestSplit, error) {
	if since.IsZero() || asOf.IsZero() || !wallBefore(since, asOf) {
		return DigestSplit{}, errors.New("netfilter digest: invalid window")
	}
	if !s.validNetfilterDigestState() {
		return DigestSplit{}, errors.New("netfilter digest: invalid retained state")
	}
	from, to := since.Round(0).UTC(), asOf.Round(0).UTC()
	rows := buildNetfilterRows(s.State.Events, from, to)
	coverage := buildNetfilterCoverage(s.State.Coverage, s.State.CoverageEvictedThrough, s.State.EvictedThrough, from, to)
	section := &netfilterDigest{
		Schema: "mac-infra.netfilter-digest/v1", Basis: "retained_events",
		Status: "unavailable", Reason: "history_absent", CollectionStatus: "disabled",
		Capabilities: netfilterCapabilities{"unavailable", "unavailable", "unavailable", "retained_tuples_only"},
		Window: netfilterWindow{
			Since: from, AsOf: to, EventRows: rows.EventRows,
			OutboundEventRows: rows.OutboundEventRows, UnknownDirectionEventRows: rows.UnknownDirectionEventRows,
			FirstTS: rows.FirstTS, LastTS: rows.LastTS, Coverage: coverage,
		},
		PerApp: rows.PerApp, Destinations: rows.Destinations,
		UnsignedOutbound: rows.UnsignedOutbound, OddPorts: rows.OddPorts,
		Alarms: readNetfilterAlarms(s.Config.NetfilterJournalDir, from, to),
	}
	if rows.EventRows > 0 || coverage.Status != "unavailable" {
		section.Status, section.Reason = "available", "none"
	}
	if *s.Config.NetfilterSource {
		section.CollectionStatus = "enabled"
	}
	if !s.State.EvictedThrough.IsZero() {
		at := s.State.EvictedThrough.UTC()
		section.Window.EventEvictedThrough = &at
	}
	// time.Time values outside JSON's RFC3339 year range must not create a
	// partially emitted digest. Keep the refusal free of source payloads.
	if _, err := json.Marshal(section); err != nil {
		return DigestSplit{}, errors.New("netfilter digest: invalid retained state")
	}
	split := s.Split(since, asOf)
	split.Netfilter = section
	return split, nil
}

func (s *Store) validNetfilterDigestState() bool {
	if s == nil || s.Config.MaxEntries < 1 || s.Config.MaxEntries > 100000 || s.Config.NetfilterSource == nil || s.validateShape(true, journalMaxTailSpans) != nil {
		return false
	}
	for _, event := range s.State.Events {
		if event.Source != SourceNetfilter {
			continue
		}
		if !persistedText(event.Bucket, 128) || !persistedText(event.RemoteClass, 128) {
			return false
		}
		switch event.RemoteClass {
		case "loopback", "tailnet", "lan", "internet", "internet-raw-ip", "unknown":
		default:
			return false
		}
	}
	return true
}
