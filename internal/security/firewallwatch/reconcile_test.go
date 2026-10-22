package firewallwatch

import (
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
)

func actionLine(t *testing.T, action map[string]any, record map[string]any) []byte {
	t.Helper()
	msg, _ := json.Marshal(action)
	r := map[string]any{"subsystem": "works.relux.mac-infra.netfilter", "category": "action", "processImagePath": testSender, "senderImagePath": testSender, "userID": 0, "eventMessage": string(msg)}
	for k, v := range record {
		r[k] = v
	}
	b, _ := json.Marshal(r)
	return b
}

// Action lines pass the same sender check as flow lines: the installed
// extension's actions parse; a forged action from another process is counted
// as rejected and never reaches reconciliation.
func TestNetfilterActionParsing(t *testing.T) {
	var p NetfilterParser
	it, a := p.ParseRecord(actionLine(t, map[string]any{"ts": "2026-10-23T01:00:01Z", "op": "kill", "actor": "sysadmin", "ok": true, "killed": 1, "target": map[string]any{"app": "/tmp/evil", "host": "", "port": 0}}, nil))
	if it != nil || a == nil || a.Op != "kill" || a.Target == nil || a.Target.App != "/tmp/evil" {
		t.Fatalf("action: %+v %+v", it, a)
	}
	it, a = p.ParseRecord(actionLine(t, map[string]any{"ts": "2026-10-23T01:00:01Z", "op": "kill", "actor": "x", "ok": true}, map[string]any{"processImagePath": "/tmp/forger", "senderImagePath": "/tmp/forger"}))
	if it != nil || a != nil || p.RejectedSender != 1 {
		t.Fatalf("forged action: %+v %+v %+v", it, a, p)
	}
	if _, a = p.ParseRecord(actionLine(t, map[string]any{"op": "kill"}, nil)); a != nil || p.Invalid != 1 {
		t.Fatalf("action without ts accepted: %+v", p)
	}
}

// An applied kill, block or unblock with a matching journaled intent (same
// actor and target, at most two minutes earlier, or within the extension's
// whole-second stamp) raises no alarm. Without one, or with an intent of
// another actor or target, or outside the window, a reconcile_mismatch alarm
// is journaled. Refused actions and other ops never alarm.
func TestReconcileAction(t *testing.T) {
	j, err := journal.Open(filepath.Join(t.TempDir(), "j"), 100)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
	intent := func(kind, actor, target string, ts time.Time) {
		if _, err := j.Append(journal.Entry{TS: ts, Kind: kind, Actor: actor, Target: target, Action: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	intent("kill_intent", "sysadmin", "app=/tmp/evil host=bad.example port=443", t0)
	intent("kill_intent", "sysadmin", "flow=F1", t0.Add(700*time.Millisecond))
	intent("unblock", "sysadmin", "rule=R1", t0)
	target := func(app, host string, port int) *struct {
		App  string `json:"app"`
		Host string `json:"host"`
		Port int    `json:"port"`
	} {
		return &struct {
			App  string `json:"app"`
			Host string `json:"host"`
			Port int    `json:"port"`
		}{app, host, port}
	}
	quiet := []NetfilterAction{
		{TS: t0.Add(time.Second), Op: "kill", Actor: "sysadmin", OK: true, Killed: 1, Target: target("/tmp/evil", "bad.example", 443)},
		{TS: t0, Op: "kill", Actor: "sysadmin", OK: true, FlowID: "F1"},
		{TS: t0.Add(5 * time.Second), Op: "unblock", Actor: "sysadmin", OK: true, RuleID: "R1"},
		{TS: t0, Op: "kill", Actor: "rogue", OK: false, Target: target("/tmp/x", "", 0)},
		{TS: t0, Op: "protect_list", OK: true},
		{TS: t0, Op: "blocked_new", OK: true},
	}
	for _, a := range quiet {
		if alarmed, err := ReconcileAction(j, a, t0); alarmed || err != nil {
			t.Errorf("unexpected alarm for %+v: %v", a, err)
		}
	}
	loud := []NetfilterAction{
		{TS: t0, Op: "kill", Actor: "rogue", OK: true, Killed: 2, Target: target("/tmp/evil", "bad.example", 443)},
		{TS: t0, Op: "kill", Actor: "sysadmin", OK: true, Target: target("/tmp/other", "", 0)},
		{TS: t0.Add(3 * time.Minute), Op: "kill", Actor: "sysadmin", OK: true, Target: target("/tmp/evil", "bad.example", 443)},
		{TS: t0, Op: "block", Actor: "sysadmin", OK: true, RuleID: "R2", Target: target("/tmp/evil", "", 0)},
	}
	for _, a := range loud {
		if alarmed, err := ReconcileAction(j, a, t0); !alarmed || err != nil {
			t.Errorf("no alarm for %+v: %v", a, err)
		}
	}
	entries, _ := j.Read()
	mismatches := 0
	for _, e := range entries {
		if e.Kind == "reconcile_mismatch" {
			mismatches++
		}
	}
	if mismatches != len(loud) || journal.Verify(entries) != nil {
		t.Fatalf("mismatch entries %d", mismatches)
	}
}
