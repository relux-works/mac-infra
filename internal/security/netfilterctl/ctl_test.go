package netfilterctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/security/journal"
)

const protectJSON = `{"schema":"mac-infra.netfilter-protect/v1","entries":[
 {"app_path_prefix":"/opt/homebrew/Cellar/sing-box/","reason":"multi-tun upstream"},
 {"app_path":"/Users/alexis/.local/bin/a2a","reason":"a2a CLI"},
 {"host_suffix":"matrix.relux.works","reason":"Matrix"}]}`

var fixedNow = func() time.Time { return time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC) }

func setup(t *testing.T) (ProtectList, *journal.Journal) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "protect.json")
	if err := os.WriteFile(path, []byte(protectJSON), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := LoadProtectList(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := journal.Open(filepath.Join(t.TempDir(), "journal"), 100)
	if err != nil {
		t.Fatal(err)
	}
	return p, j
}

type fakeApp struct {
	calls [][]string
	out   string
	err   error
}

func (f *fakeApp) run(_ context.Context, args []string) ([]byte, error) {
	f.calls = append(f.calls, args)
	return []byte(f.out), f.err
}

func kinds(t *testing.T, j *journal.Journal) string {
	t.Helper()
	entries, err := j.Read()
	if err != nil || journal.Verify(entries) != nil {
		t.Fatalf("journal unreadable: %v", err)
	}
	var k []string
	for _, e := range entries {
		k = append(k, e.Kind)
	}
	return strings.Join(k, ",")
}

// Positive: a kill by tuple journals the intent first, runs the app with the
// tuple, journals the result referencing the intent, opens a report and
// returns a Russian incident text with app, place, reason, undo and the
// journal anchor.
func TestKillJournalsAndReports(t *testing.T) {
	p, j := setup(t)
	app := &fakeApp{out: `{"ok":true,"killed":[{"appPath":"/tmp/evil"}],"rules":[],"killable_flows":3}` + "\n"}
	r := Request{Op: "kill", Actor: "m1max_local-sysadmin_keeper", Reason: "rule:policy_unsigned_outbound", Target: Target{App: "/tmp/evil", Host: "bad.example", Port: 443}}
	res := Execute(context.Background(), r, p, j, app.run, fixedNow)
	if !res.OK || len(app.calls) != 1 || strings.Join(app.calls[0], " ") != "kill --actor m1max_local-sysadmin_keeper --app /tmp/evil --host bad.example --port 443" {
		t.Fatalf("result %+v calls %v", res, app.calls)
	}
	if got := kinds(t, j); got != "kill_intent,kill_result,report_pending" {
		t.Fatalf("journal kinds %s", got)
	}
	if res.Outcome.Ref != res.Intent.Seq || res.ReportPending.Ref != res.Outcome.Seq || res.Outcome.Action != "killed 1" {
		t.Fatalf("refs: %+v %+v", res.Outcome, res.ReportPending)
	}
	for _, want := range []string{"[mac-infra / netfilter]", "/tmp/evil", "bad.example:443", "rule:policy_unsigned_outbound", "Как отменить", "Журнал: запись 2"} {
		if !strings.Contains(res.IncidentRU, want) {
			t.Errorf("incident lacks %q:\n%s", want, res.IncidentRU)
		}
	}
}

// Negative: no kill without a journal write. With an unreadable journal the
// app is never run, nothing is reported, and the error says nothing was sent.
func TestNoKillWithoutJournal(t *testing.T) {
	p, _ := setup(t)
	dir := filepath.Join(t.TempDir(), "journal")
	j, err := journal.Open(dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "journal.ndjson"), []byte("not a journal record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	app := &fakeApp{out: `{"ok":true}`}
	res := Execute(context.Background(), Request{Op: "kill", Actor: "a", Reason: "r", Target: Target{App: "/tmp/evil"}}, p, j, app.run, fixedNow)
	if res.OK || len(app.calls) != 0 || !strings.HasPrefix(res.Error, "journal write failed, nothing sent") {
		t.Fatalf("result %+v calls %d", res, len(app.calls))
	}
}

// Negative: protected targets (by path prefix, exact path, host suffix) are
// refused before anything is journaled or sent; a look-alike host is not
// protected (control).
func TestProtectedTargetsRefused(t *testing.T) {
	p, j := setup(t)
	app := &fakeApp{out: `{"ok":true,"killed":[]}`}
	for _, tg := range []Target{
		{App: "/opt/homebrew/Cellar/sing-box/1.13.3/bin/sing-box"},
		{App: "/Users/alexis/.local/bin/a2a", Host: "x.example"},
		{Host: "sync.matrix.relux.works"},
	} {
		for _, op := range []string{"kill", "block"} {
			res := Execute(context.Background(), Request{Op: op, Actor: "a", Reason: "r", Target: tg, Duration: time.Hour}, p, j, app.run, fixedNow)
			if res.OK || !strings.HasPrefix(res.Error, "target is protected") {
				t.Errorf("%s %v: %+v", op, tg, res)
			}
		}
	}
	if len(app.calls) != 0 || kinds(t, j) != "" {
		t.Fatalf("protected request reached the app or the journal: %v %s", app.calls, kinds(t, j))
	}
	if p.Protects(Target{Host: "evilmatrix.relux.works"}) != "" {
		t.Fatal("look-alike host protected")
	}
}

// Negative: a missing or malformed protect-list is an error (enforcement
// off); the CLI never falls back to an empty list.
func TestProtectListRequired(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadProtectList(filepath.Join(dir, "missing.json")); err == nil {
		t.Fatal("missing list accepted")
	}
	for i, body := range []string{`{"schema":"mac-infra.netfilter-protect/v1","entries":[]}`, `{"schema":"x","entries":[{"app_path":"/a","reason":"r"}]}`,
		`{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/a","host_suffix":"b","reason":"r"}]}`,
		`{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/a","reason":"r","x":1}]}`} {
		path := filepath.Join(dir, "p"+string(rune('0'+i)))
		_ = os.WriteFile(path, []byte(body), 0644)
		if _, err := LoadProtectList(path); err == nil {
			t.Errorf("invalid list %d accepted", i)
		}
	}
}

// An extension refusal or a missing answer is journaled as the result, no
// report is opened and the CLI fails; the intent always precedes the call.
func TestRefusalsAndFailuresJournaled(t *testing.T) {
	p, j := setup(t)
	refused := &fakeApp{out: `{"ok":false,"error":"protect-list missing: enforcement is disabled","killed":[],"rules":[],"killable_flows":0}`}
	res := Execute(context.Background(), Request{Op: "kill", Actor: "a", Reason: "r", FlowID: "F1"}, p, j, refused.run, fixedNow)
	if res.OK || !strings.Contains(res.Error, "enforcement is disabled") || res.ReportPending != nil || !strings.HasPrefix(res.Outcome.Action, "refused") {
		t.Fatalf("refusal: %+v", res)
	}
	broken := &fakeApp{out: "", err: errors.New("exit status 1")}
	res = Execute(context.Background(), Request{Op: "kill", Actor: "a", Reason: "r", FlowID: "F2"}, p, j, broken.run, fixedNow)
	if res.OK || res.Outcome.Action != "error: no answer from the extension" {
		t.Fatalf("failure: %+v", res)
	}
	if got := kinds(t, j); got != "kill_intent,kill_result,kill_intent,kill_result" {
		t.Fatalf("journal %s", got)
	}
}

// Blocks need a duration within 24 h; the journal records the expiry and the
// undo command carrying the extension's rule id; unblock closes it with an
// undo entry and opens no report.
func TestBlockAndUnblock(t *testing.T) {
	p, j := setup(t)
	app := &fakeApp{out: `{"ok":true,"killed":[],"rule":{"id":"R1","expiry":"2026-10-23T02:00:00Z"},"rules":[],"killable_flows":0}`}
	for _, d := range []time.Duration{0, MaxBlock + time.Second} {
		if res := Execute(context.Background(), Request{Op: "block", Actor: "a", Reason: "r", Target: Target{Host: "bad.example"}, Duration: d}, p, j, app.run, fixedNow); res.OK {
			t.Fatalf("duration %v accepted", d)
		}
	}
	res := Execute(context.Background(), Request{Op: "block", Actor: "a", Reason: "r", Target: Target{Host: "bad.example"}, Duration: time.Hour}, p, j, app.run, fixedNow)
	if !res.OK || res.Outcome.Undo != "mac-firewall netfilter unblock --rule R1" || res.Outcome.Expiry == nil || !res.Outcome.Expiry.Equal(fixedNow().Add(time.Hour)) ||
		strings.Join(app.calls[0], " ") != "block --actor a --host bad.example --for 3600" || !strings.Contains(res.IncidentRU, "до 2026-10-23 02:00 UTC") {
		t.Fatalf("block: %+v calls %v\n%s", res, app.calls, res.IncidentRU)
	}
	app.out = `{"ok":true,"killed":[],"rules":[],"killable_flows":0}`
	un := Execute(context.Background(), Request{Op: "unblock", Actor: "a", RuleID: "R1"}, p, j, app.run, fixedNow)
	if !un.OK || un.ReportPending != nil || un.Outcome.Kind != "undo" {
		t.Fatalf("unblock: %+v", un)
	}
}

// Usage-level validation: actor and reason are required, kill takes exactly
// one of flow or target, out-of-bounds fields are refused.
func TestValidate(t *testing.T) {
	for _, r := range []Request{
		{Op: "kill", Reason: "r", FlowID: "F"},
		{Op: "kill", Actor: "a", FlowID: "F"},
		{Op: "kill", Actor: "a", Reason: "r"},
		{Op: "kill", Actor: "a", Reason: "r", FlowID: "F", Target: Target{App: "/x"}},
		{Op: "kill", Actor: "a", Reason: "r", Target: Target{App: strings.Repeat("x", 257)}},
		{Op: "kill", Actor: "a", Reason: "r", Target: Target{Host: "h", Port: 70000}},
		{Op: "unblock", Actor: "a"},
		{Op: "drop", Actor: "a", Reason: "r"},
	} {
		if r.Validate() == nil {
			t.Errorf("accepted %+v", r)
		}
	}
	if (Request{Op: "kill", Actor: "a", Reason: "r", FlowID: "F"}).Validate() != nil {
		t.Fatal("control refused")
	}
}

// reported closes an open report exactly once; an unknown ref or a second
// close is refused.
func TestReported(t *testing.T) {
	p, j := setup(t)
	app := &fakeApp{out: `{"ok":true,"killed":[{}],"rules":[],"killable_flows":0}`}
	res := Execute(context.Background(), Request{Op: "kill", Actor: "a", Reason: "r", FlowID: "F"}, p, j, app.run, fixedNow)
	ref := res.ReportPending.Seq
	if _, err := Reported(j, "a", ref+5, "$evt", fixedNow()); err == nil {
		t.Fatal("unknown ref accepted")
	}
	done, err := Reported(j, "a", ref, "$evt", fixedNow())
	if err != nil || done.Kind != "report_done" || done.Ref != ref {
		t.Fatalf("reported: %+v %v", done, err)
	}
	if _, err := Reported(j, "a", ref, "$evt2", fixedNow()); err == nil {
		t.Fatal("second close accepted")
	}
}
