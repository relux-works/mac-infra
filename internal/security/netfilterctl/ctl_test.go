package netfilterctl

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
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

// The filesystem case table mirrors ProtectListFileTests.swift; no root privileges are needed.
func TestProtectListFileTrust(t *testing.T) {
	cases := []struct {
		name, want string
	}{
		// Positive: a valid 0644 file under safe ancestors loads and decodes.
		{"valid", ""},
		// Negative: the explicit expected uid applies to the root anchor too.
		{"wrong_owner", "protect-list directory not owned by root"},
		// Negative: group-writable files cannot enable enforcement.
		{"group_writable", "protect-list is group/world writable"},
		// Negative: world-writable files cannot enable enforcement.
		{"world_writable", "protect-list is group/world writable"},
		// Negative: a file symlink cannot enable enforcement.
		{"symlink", "protect-list path component is a symlink"},
		// Negative: a second hard link cannot enable enforcement.
		{"hard_link", "protect-list link count is not 1"},
		// Negative: a symlink ancestor cannot redirect the read.
		{"ancestor_symlink", "protect-list path component is a symlink"},
		// Negative: a group-writable ancestor cannot enable enforcement.
		{"ancestor_group_writable", "protect-list directory is group/world writable"},
		// Negative: a world-writable ancestor cannot enable enforcement.
		{"ancestor_world_writable", "protect-list directory is group/world writable"},
		// Negative: the root anchor itself must have safe mode bits.
		{"root_writable", "protect-list directory is group/world writable"},
		// Negative: a regular file cannot serve as an ancestor directory.
		{"ancestor_file", "protect-list path component is not a directory"},
		// Negative: set-uid files cannot enable enforcement.
		{"setuid", "protect-list has set-uid, set-gid or sticky bit"},
		// Negative: set-gid files cannot enable enforcement.
		{"setgid", "protect-list has set-uid, set-gid or sticky bit"},
		// Negative: sticky files cannot enable enforcement.
		{"sticky", "protect-list has set-uid, set-gid or sticky bit"},
		// Negative: a FIFO is refused without blocking on a writer.
		{"fifo", "protect-list is not a regular file"},
		// Negative: a directory at the file path cannot enable enforcement.
		{"directory", "protect-list is not a regular file"},
		// Negative: a missing file still leaves enforcement off.
		{"missing", "protect-list missing (enforcement off)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "safe")
			path := filepath.Join(dir, "protect.json")
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			must(os.Mkdir(dir, 0755))
			must(os.WriteFile(path, []byte(protectJSON), 0644))
			must(unix.Chmod(path, 0644))
			uid := uint32(os.Getuid())
			switch tc.name {
			case "wrong_owner":
				uid++
			case "group_writable":
				must(unix.Chmod(path, 0664))
			case "world_writable":
				must(unix.Chmod(path, 0646))
			case "setuid":
				must(unix.Chmod(path, 04644))
			case "setgid":
				must(unix.Chmod(path, 02644))
			case "sticky":
				must(unix.Chmod(path, 01644))
			case "hard_link":
				must(os.Link(path, filepath.Join(dir, "other.json")))
			case "symlink":
				must(os.Rename(path, path+".real"))
				must(os.Symlink(path+".real", path))
			case "ancestor_symlink":
				must(os.Rename(dir, dir+".real"))
				must(os.Symlink(dir+".real", dir))
			case "ancestor_group_writable":
				must(unix.Chmod(dir, 0775))
			case "ancestor_world_writable":
				must(unix.Chmod(dir, 0757))
			case "root_writable":
				must(unix.Chmod(root, 0775))
			case "ancestor_file":
				must(os.Rename(dir, dir+".real"))
				must(os.WriteFile(dir, nil, 0644))
			case "fifo", "directory", "missing":
				must(os.Remove(path))
				if tc.name == "fifo" {
					must(unix.Mkfifo(path, 0644))
				}
				if tc.name == "directory" {
					must(os.Mkdir(path, 0755))
				}
			}
			p, err := loadProtectList("/safe/protect.json", uid, root)
			if tc.want == "" {
				if err != nil || p.Schema != "mac-infra.netfilter-protect/v1" || len(p.Entries) != 3 || p.Protects(Target{Host: "sync.matrix.relux.works"}) != "Matrix" {
					t.Fatalf("positive control: %+v, %v", p, err)
				}
				return
			}
			if err == nil || err.Error() != tc.want || !reflect.DeepEqual(p, ProtectList{}) {
				t.Fatalf("want no list and %q; got %+v, %v", tc.want, p, err)
			}
		})
	}
}

// Negative: even if a caller passes a refused list to Execute, no intent or app call occurs.
func TestRefusedProtectListNeverExecutes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "protect.json")
	if err := os.WriteFile(path, []byte(protectJSON), 0664); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chmod(path, 0664); err != nil {
		t.Fatal(err)
	}
	p, err := loadProtectList("/protect.json", uint32(os.Getuid()), root)
	if err == nil || err.Error() != "protect-list is group/world writable" {
		t.Fatalf("refusal: %v", err)
	}
	j, err := journal.Open(filepath.Join(t.TempDir(), "journal"), 100)
	if err != nil {
		t.Fatal(err)
	}
	app := &fakeApp{out: `{"ok":true}`}
	for _, op := range []string{"kill", "block", "unblock"} {
		res := Execute(context.Background(), Request{Op: op, Actor: "a", Reason: "r", Target: Target{App: "/tmp/evil"}, Duration: time.Hour, RuleID: "R1"}, p, j, app.run, fixedNow)
		if res.OK || res.Error != "protect-list unavailable (enforcement off)" || res.Intent != nil || len(app.calls) != 0 || kinds(t, j) != "" {
			t.Fatalf("%s with refused list: %+v calls %v", op, res, app.calls)
		}
	}
}

// The trusted-file reader preserves the 64 KiB boundary and still rejects invalid content.
func TestProtectListFileContent(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		// Positive: trailing JSON whitespace up to exactly 64 KiB is admitted.
		{"limit", protectJSON + strings.Repeat(" ", 65536-len(protectJSON)), ""},
		// Negative: one byte beyond the limit returns no list.
		{"oversize", protectJSON + strings.Repeat(" ", 65537-len(protectJSON)), "protect-list larger than 64 KiB"},
		// Negative: safe filesystem metadata does not bypass strict decoding.
		{"invalid", "not JSON", "protect-list invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "protect.json"), []byte(tc.body), 0644); err != nil {
				t.Fatal(err)
			}
			p, err := loadProtectList("/protect.json", uint32(os.Getuid()), root)
			if tc.want == "" {
				if err != nil || len(p.Entries) != 3 {
					t.Fatalf("boundary: %+v %v", p, err)
				}
			} else if err == nil || err.Error() != tc.want || !reflect.DeepEqual(p, ProtectList{}) {
				t.Fatalf("want no list and %q; got %+v %v", tc.want, p, err)
			}
		})
	}
}

func setup(t *testing.T) (ProtectList, *journal.Journal) {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "protect.json")
	if err := os.WriteFile(path, []byte(protectJSON), 0644); err != nil {
		t.Fatal(err)
	}
	p, err := loadProtectList("/protect.json", uint32(os.Getuid()), root)
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
	if _, err := loadProtectList("/missing.json", uint32(os.Getuid()), dir); err == nil {
		t.Fatal("missing list accepted")
	}
	for i, body := range []string{`{"schema":"mac-infra.netfilter-protect/v1","entries":[]}`, `{"schema":"x","entries":[{"app_path":"/a","reason":"r"}]}`,
		`{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/a","host_suffix":"b","reason":"r"}]}`,
		`{"schema":"mac-infra.netfilter-protect/v1","entries":[{"app_path":"/a","reason":"r","x":1}]}`} {
		path := filepath.Join(dir, "p"+string(rune('0'+i)))
		_ = os.WriteFile(path, []byte(body), 0644)
		if _, err := loadProtectList("/"+filepath.Base(path), uint32(os.Getuid()), dir); err == nil {
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

// alarm and warning are journal-only: no protect-list or app is involved,
// a reason is required, and they refuse kill-only fields. Hosts are journaled
// lowercased, as the extension reports them, so reconciliation matches.
func TestAlarmAndHostCase(t *testing.T) {
	p, j := setup(t)
	res := Execute(context.Background(), Request{Op: "alarm", Actor: "sysadmin", Reason: "danger:unsigned-to-new-host", Target: Target{App: "/tmp/evil", Host: "Bad.Example"}}, ProtectList{}, j, nil, fixedNow)
	if !res.OK || res.Outcome.Kind != "alarm" || res.Outcome.Target != "app=/tmp/evil host=bad.example" {
		t.Fatalf("alarm: %+v", res)
	}
	for _, r := range []Request{{Op: "warning", Actor: "a"}, {Op: "alarm", Actor: "a", Reason: "r", FlowID: "F"}} {
		if Execute(context.Background(), r, ProtectList{}, j, nil, fixedNow).OK {
			t.Errorf("accepted %+v", r)
		}
	}
	app := &fakeApp{out: `{"ok":true,"killed":[]}`}
	k := Execute(context.Background(), Request{Op: "kill", Actor: "a", Reason: "r", Target: Target{Host: "MIXED.Case.example"}}, p, j, app.run, fixedNow)
	if !k.OK || k.Intent.Target != "host=mixed.case.example" || app.calls[0][4] != "mixed.case.example" {
		t.Fatalf("host case: %+v %v", k.Intent, app.calls)
	}
}
