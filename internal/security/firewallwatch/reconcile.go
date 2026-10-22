package firewallwatch

import (
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
	"github.com/relux-works/mac-infra/internal/security/netfilterctl"
)

// reconcileWindow is how far before an extension action its journaled
// intent may be: the CLI writes the intent, then waits for the app.
// reconcileSlack covers the extension's whole-second timestamps.
const (
	reconcileWindow = 2 * time.Minute
	reconcileSlack  = 2 * time.Second
)

// ReconcileAction checks an applied extension action against the journal.
// Kill, block and unblock actions that the extension applied must follow a
// journaled intent of the same actor and target; otherwise a
// reconcile_mismatch alarm is journaled. Refused actions and other ops
// (protect-list loads, list, blocked_new) need no intent.
func ReconcileAction(j *journal.Journal, a NetfilterAction, now time.Time) (alarmed bool, err error) {
	var wantKind, target string
	switch a.Op {
	case "kill":
		wantKind = "kill_intent"
	case "block":
		wantKind = "block_intent"
	case "unblock":
		wantKind = "unblock"
	default:
		return false, nil
	}
	if !a.OK {
		return false, nil
	}
	switch {
	case a.Op == "unblock":
		target = "rule=" + a.RuleID
	case a.FlowID != "":
		target = "flow=" + a.FlowID
	case a.Target != nil:
		target = netfilterctl.Target{App: a.Target.App, Host: a.Target.Host, Port: a.Target.Port}.String()
	}
	entries, err := j.Read()
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.Kind == wantKind && e.Actor == a.Actor && e.Target == target && e.TS.Sub(a.TS) <= reconcileSlack && a.TS.Sub(e.TS) <= reconcileWindow {
			return false, nil
		}
	}
	_, err = j.Append(journal.Entry{TS: now.UTC(), Kind: "reconcile_mismatch", Source: "netfilter action log", Actor: "mac-firewall watch", Target: target, Action: "applied " + a.Op + " by " + a.Actor + " without a journaled intent"})
	return err == nil, err
}
