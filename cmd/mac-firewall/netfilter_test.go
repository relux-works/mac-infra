package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/mac-infra/internal/security/netfilterctl"
)

func netfilterFixture(t *testing.T, answer string) (journalDir, protect string, calls *[][]string) {
	t.Helper()
	// The temp dir lies under the /var symlink on macOS; anchor the checked
	// walk at its resolved path and expect the test user instead of root.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	protect = filepath.Join(root, "protect.json")
	if err := os.WriteFile(protect, []byte(`{"schema":"mac-infra.netfilter-protect/v1","entries":[{"host_suffix":"matrix.relux.works","reason":"Matrix"}]}`), 0644); err != nil {
		t.Fatal(err)
	}
	oldLoad := netfilterLoadProtectList
	netfilterLoadProtectList = func(path string) (netfilterctl.ProtectList, error) {
		rel, err := filepath.Rel(root, path)
		if err != nil || strings.HasPrefix(rel, "..") {
			return netfilterctl.ProtectList{}, fmt.Errorf("fixture path %s is outside %s", path, root)
		}
		return netfilterctl.LoadProtectListFrom("/"+rel, uint32(os.Getuid()), root)
	}
	t.Cleanup(func() { netfilterLoadProtectList = oldLoad })
	var c [][]string
	old := netfilterRun
	netfilterRun = func(string) netfilterctl.Runner {
		return func(_ context.Context, args []string) ([]byte, error) {
			c = append(c, args)
			return []byte(answer), nil
		}
	}
	t.Cleanup(func() { netfilterRun = old })
	return filepath.Join(root, "journal"), protect, &c
}

// The CLI path journals and reports a kill end to end (JSON out, exit 0),
// then reported closes the report; status shows the chain and no pending
// report afterwards.
func TestNetfilterCLIKillReportedStatus(t *testing.T) {
	jdir, protect, calls := netfilterFixture(t, `{"ok":true,"killed":[{}],"rules":[],"killable_flows":1}`)
	var o, e bytes.Buffer
	code := run([]string{"netfilter", "kill", "--journal-dir", jdir, "--protect-list", protect, "--app-binary", "/Applications/NetFilter.app/Contents/MacOS/NetFilter", "--actor", "sysadmin", "--reason", "rule:x", "--app", "/tmp/evil"}, &o, &e)
	var res struct {
		OK            bool
		ReportPending struct{ Seq uint64 } `json:"report_pending"`
		IncidentRU    string               `json:"incident_ru"`
	}
	if code != 0 || json.Unmarshal(o.Bytes(), &res) != nil || !res.OK || res.ReportPending.Seq != 3 || !strings.Contains(res.IncidentRU, "/tmp/evil") || len(*calls) != 1 {
		t.Fatalf("kill: code %d out %s err %s", code, o.String(), e.String())
	}
	o.Reset()
	if code = run([]string{"netfilter", "reported", "--journal-dir", jdir, "--actor", "sysadmin", "--ref", "3", "--event", "$evt"}, &o, &e); code != 0 {
		t.Fatalf("reported: %d %s", code, o.String())
	}
	o.Reset()
	*calls = nil
	code = run([]string{"netfilter", "status", "--journal-dir", jdir, "--app-binary", "/x"}, &o, &e)
	if code != 0 || !strings.Contains(o.String(), `"chain_ok":true`) || !strings.Contains(o.String(), `"reports_pending":0`) || !strings.Contains(o.String(), `"entries":4`) {
		t.Fatalf("status: %d %s", code, o.String())
	}
}

// Usage errors exit 2 and run nothing: missing journal/protect/app paths,
// actor or reason, kill without a target, a relative journal dir is a
// failure (exit 1), and a protected target exits 1 without running the app.
func TestNetfilterCLIUsageAndRefusals(t *testing.T) {
	jdir, protect, calls := netfilterFixture(t, `{"ok":true}`)
	base := []string{"--journal-dir", jdir, "--protect-list", protect, "--app-binary", "/x"}
	for _, args := range [][]string{
		{"netfilter"},
		{"netfilter", "kill", "--protect-list", protect, "--app-binary", "/x", "--actor", "a", "--reason", "r", "--app", "/y"},
		append(append([]string{"netfilter", "kill"}, base...), "--reason", "r", "--app", "/y"),
		append(append([]string{"netfilter", "kill"}, base...), "--actor", "a", "--app", "/y"),
		append(append([]string{"netfilter", "kill"}, base...), "--actor", "a", "--reason", "r"),
		append(append([]string{"netfilter", "block"}, base...), "--actor", "a", "--reason", "r", "--host", "h"),
		{"netfilter", "reported", "--journal-dir", jdir, "--actor", "a", "--event", "e"},
		{"netfilter", "frobnicate"},
	} {
		var o, e bytes.Buffer
		if code := run(args, &o, &e); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	var o, e bytes.Buffer
	if code := run(append(append([]string{"netfilter", "kill"}, base...), "--actor", "a", "--reason", "r", "--host", "matrix.relux.works"), &o, &e); code != 1 || !strings.Contains(o.String(), "protected") {
		t.Fatalf("protected: %d %s", code, o.String())
	}
	if code := run([]string{"netfilter", "kill", "--journal-dir", "rel/dir", "--protect-list", protect, "--app-binary", "/x", "--actor", "a", "--reason", "r", "--app", "/y"}, &o, &e); code != 1 {
		t.Fatalf("relative journal dir: %d", code)
	}
	if len(*calls) != 0 {
		t.Fatalf("app ran: %v", *calls)
	}
}

// Negative: the CLI uses the checked loader. A group-writable protect-list is
// refused with exit 1, and nothing is journaled or sent to the app. The kill
// test above is the positive control with a safe 0644 list.
func TestNetfilterCLIRefusesUnsafeProtectList(t *testing.T) {
	jdir, protect, calls := netfilterFixture(t, `{"ok":true,"killed":[{}],"rules":[],"killable_flows":1}`)
	if err := os.Chmod(protect, 0664); err != nil {
		t.Fatal(err)
	}
	var o, e bytes.Buffer
	code := run([]string{"netfilter", "kill", "--journal-dir", jdir, "--protect-list", protect, "--app-binary", "/x", "--actor", "a", "--reason", "r", "--app", "/y"}, &o, &e)
	if code != 1 || !strings.Contains(o.String(), "protect-list is group/world writable") {
		t.Fatalf("unsafe list: code %d out %s", code, o.String())
	}
	if len(*calls) != 0 {
		t.Fatalf("app ran: %v", *calls)
	}
	if entries, _ := os.ReadDir(jdir); len(entries) != 0 {
		t.Fatalf("journal written: %d entries", len(entries))
	}
}
