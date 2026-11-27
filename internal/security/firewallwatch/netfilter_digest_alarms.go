package firewallwatch

import (
	"errors"
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
)

type netfilterAlarmCounts struct {
	Warning           int `json:"warning"`
	Alarm             int `json:"alarm"`
	ReconcileMismatch int `json:"reconcile_mismatch"`
}

type netfilterAlarmSummary struct {
	Status    string                `json:"status"`
	Reason    string                `json:"reason"`
	Counts    *netfilterAlarmCounts `json:"counts"`
	SeqRefs   []uint64              `json:"seq_refs"`
	Truncated bool                  `json:"truncated"`
}

// The reader verifies the entire retained chain before this function selects
// incident kinds and timestamps. Only this closed projection reaches the wire;
// journal payloads and error text are never included in it.
func readNetfilterAlarms(dir string, since, asOf time.Time) netfilterAlarmSummary {
	entries, err := journal.ReadExisting(dir)
	if err != nil {
		return netfilterAlarmRefusal(err)
	}
	result := netfilterAlarmSummary{
		Status: "verified", Reason: "none",
		Counts: &netfilterAlarmCounts{}, SeqRefs: make([]uint64, 0),
		Truncated: len(entries) > 0 && entries[0].Seq > 1,
	}
	for _, entry := range entries {
		if entry.TS.Before(since) || entry.TS.After(asOf) {
			continue
		}
		switch entry.Kind {
		case "warning":
			result.Counts.Warning++
		case "alarm":
			result.Counts.Alarm++
		case "reconcile_mismatch":
			result.Counts.ReconcileMismatch++
		default:
			continue
		}
		result.SeqRefs = append(result.SeqRefs, entry.Seq)
	}
	return result
}

func netfilterAlarmRefusal(err error) netfilterAlarmSummary {
	result := netfilterAlarmSummary{
		Status: "invalid", Reason: "malformed",
		SeqRefs: make([]uint64, 0), Truncated: true,
	}
	var readErr *journal.ReadError
	if !errors.As(err, &readErr) || readErr == nil {
		return result
	}
	switch readErr.Reason {
	case "not_found", "unreadable", "unsafe_path":
		result.Status, result.Reason = "unavailable", readErr.Reason
	case "malformed", "chain_invalid":
		result.Reason = readErr.Reason
	}
	return result
}
