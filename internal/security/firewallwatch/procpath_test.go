package firewallwatch

import (
	"strings"
	"testing"
	"time"
)

// Package tests never resolve fixture pids against live processes: a fixture
// pid could belong to a real process. The real resolver has its own tests.
func init() { lookupProcessPath = func(int, string) string { return "" } }

// A nettop process row's pid and raw name are kept on its connection rows:
// a name nettop cut at 15 bytes and one with invalid UTF-8 stay raw in
// ProcName, while App is sanitized as before. A connection row before any
// process row gets neither.
func TestParseNettopKeepsPIDAndRawName(t *testing.T) {
	text := "time,,bytes_out\n" +
		"com.cisco.anyco.592,,10\n\"tcp4 10.0.0.2:5000<->93.184.216.34:443\",,100\n" +
		"caf\xe9.77,,10\n\"tcp4 10.0.0.2:5001<->93.184.216.34:443\",,100\n"
	items, unknown := ParseNettop(text)
	if unknown != 0 || len(items) != 2 {
		t.Fatalf("items=%d unknown=%d", len(items), unknown)
	}
	if items[0].PID != 592 || items[0].ProcName != "com.cisco.anyco" || items[0].App != "com.cisco.anyco" {
		t.Fatalf("first: %+v", items[0])
	}
	if items[1].PID != 77 || items[1].ProcName != "caf\xe9" || items[1].App == items[1].ProcName {
		t.Fatalf("second: pid=%d raw=%q app=%q", items[1].PID, items[1].ProcName, items[1].App)
	}
	orphan, unknown := ParseNettop("time,,bytes_out\n\"tcp4 10.0.0.2:5000<->93.184.216.34:443\",,100\n")
	if len(orphan) != 0 || unknown != 1 {
		t.Fatalf("orphan row: %+v %d", orphan, unknown)
	}
}

// The kernel name must be the printed one: equal when nettop printed fewer
// than 15 bytes, a prefix match when it printed exactly 15 (its cut). A
// shorter printed name is never a prefix match, and an empty one never
// matches.
func TestNameMatches(t *testing.T) {
	cases := []struct {
		comm, printed string
		want          bool
	}{
		{"Browser", "Browser", true},
		{"com.cisco.anyconnect", "com.cisco.anyco", true},
		{"identityservicesd", "identityservice", true},
		{"Browser2", "Browser", false},
		{"other", "Browser", false},
		{"com.cisco.other", "com.cisco.anyco", false},
		{"", "", false},
		{"x", "", false},
	}
	for _, c := range cases {
		if got := nameMatches(c.comm, c.printed); got != c.want {
			t.Fatalf("nameMatches(%q, %q) = %v", c.comm, c.printed, got)
		}
	}
}

// Each pid is looked up once per sample; a confirmed path becomes the item's
// Path and its InspectionPath (the signer inspection's input); an
// unconfirmed one leaves both empty; other sources are never looked up.
func TestAttributePathsOncePerPID(t *testing.T) {
	items := []Item{
		{Source: "nettop", App: "a", PID: 10, ProcName: "a"},
		{Source: "nettop", App: "a", PID: 10, ProcName: "a"},
		{Source: "nettop", App: "b", PID: 11, ProcName: "b"},
		{Source: "alf", App: "c", PID: 12, ProcName: "c"},
	}
	calls := map[int]int{}
	attributePaths(items, func(pid int, name string) string {
		calls[pid]++
		if pid == 10 {
			return "/Applications/A.app/Contents/MacOS/a"
		}
		return ""
	})
	if calls[10] != 1 || calls[11] != 1 || calls[12] != 0 {
		t.Fatalf("lookups: %v", calls)
	}
	for _, i := range []int{0, 1} {
		if items[i].Path != "/Applications/A.app/Contents/MacOS/a" || items[i].InspectionPath != items[i].Path {
			t.Fatalf("item %d: %+v", i, items[i])
		}
	}
	if items[2].Path != "" || items[2].InspectionPath != "" || items[3].Path != "" {
		t.Fatalf("unconfirmed or other source got a path: %+v %+v", items[2], items[3])
	}
}

// The identity of a nettop row includes its confirmed path, so two binaries
// behind one name are two items; without a path the key is exactly the
// previous one; other sources ignore a path.
func TestKeyAddsConfirmedPathForNettopOnly(t *testing.T) {
	port := 443
	base := Item{Source: "nettop", App: "netproxy", Verdict: "observed", Remote: "internet-raw-ip", RemotePort: &port}
	a, b := base, base
	a.Path, b.Path = "/opt/pilot/netproxy", "/Users/x/src/build/netproxy"
	if key(a) == key(b) || key(a) == key(base) {
		t.Fatalf("paths did not separate: %s %s %s", key(a), key(b), key(base))
	}
	if key(base) != `["nettop","netproxy","observed",443,"internet-raw-ip"]` {
		t.Fatalf("pathless key changed: %s", key(base))
	}
	alf := Item{Source: "alf", App: "x", Verdict: "allow", Remote: "unknown", Path: "/bin/x"}
	alfNoPath := alf
	alfNoPath.Path = ""
	if key(alf) != key(alfNoPath) {
		t.Fatal("an alf item's key took a path")
	}
}

// Events carry a path only from nettop and only an absolute, valid one; the
// validator refuses a path anywhere else, a relative path, control
// characters and an over-long path, and admits the valid nettop path
// (control).
func TestEventPathOnlyForNettop(t *testing.T) {
	ok := Event{Source: "nettop", Path: "/opt/pilot/netproxy"}
	if !validEventPath(ok) || !validEventPath(Event{Source: "alf"}) {
		t.Fatal("control refused")
	}
	bad := []Event{
		{Source: "alf", Path: "/bin/x"},
		{Source: SourceNetfilter, Path: "/bin/x"},
		{Source: "nettop", Path: "relative/x"},
		{Source: "nettop", Path: "/bin/x\n"},
		{Source: "nettop", Path: "/" + strings.Repeat("a", 1024)},
	}
	for _, e := range bad {
		if validEventPath(e) {
			t.Fatalf("admitted %+v", e)
		}
	}
	if eventPath(Item{Source: "alf", Path: "/bin/x"}) != "" || eventPath(Item{Source: "nettop", Path: "rel"}) != "" || eventPath(Item{Source: "nettop", Path: "/bin/x"}) != "/bin/x" {
		t.Fatal("eventPath")
	}
}

// Observing two nettop rows that differ only by confirmed path makes two
// entries and gives each event its path; the same rows without paths make
// one entry (the previous behaviour, control).
func TestObservedNettopEventsCarryPath(t *testing.T) {
	port := 443
	row := Item{Source: "nettop", Kind: "outbound", App: "netproxy", Signer: "adhoc", Verdict: "observed", Remote: "internet-raw-ip", RemotePort: &port, Bucket: "160.79.104.0/24", Count: 1}
	classify := func(Item) Decision { return Decision{Label: "digest", Reason: "test"} }
	now := time.Date(2026, 10, 30, 19, 0, 0, 0, time.UTC)
	s, _ := journalStore(t)
	a, b := row, row
	a.Path, b.Path = "/opt/pilot/netproxy", "/Users/x/src/build/netproxy"
	ea := s.Observe(a, now, classify)
	eb := s.Observe(b, now, classify)
	if len(s.State.Entries) != 2 || len(ea) == 0 || len(eb) == 0 || ea[0].Path != a.Path || eb[0].Path != b.Path {
		t.Fatalf("entries=%d events=%+v %+v", len(s.State.Entries), ea, eb)
	}
	s2, _ := journalStore(t)
	s2.Observe(row, now, classify)
	s2.Observe(row, now, classify)
	if len(s2.State.Entries) != 1 {
		t.Fatalf("control: %d entries", len(s2.State.Entries))
	}
}

// Two events that differ only by path have different identities, so the
// journal removes the right one; an event without a path keeps exactly the
// identity it had before paths existed (control: a fixed value computed on
// main before this change).
func TestEventIDIncludesPathOnlyWhenPresent(t *testing.T) {
	port := 443
	e := Event{TS: time.Date(2026, 10, 30, 19, 0, 0, 0, time.UTC), Source: "nettop", App: "netproxy", Signer: "unknown", Verdict: "observed", Port: &port, RemoteClass: "internet-raw-ip", Bucket: "160.79.104.0/24", Counts: 1, Label: "digest", Reason: "r", Mode: "shadow"}
	if got := eventID(e); got != pathlessEventID {
		t.Fatalf("a pathless event changed identity: %s", got)
	}
	a, b := e, e
	a.Path, b.Path = "/opt/pilot/netproxy", "/Users/x/src/build/netproxy"
	if eventID(a) == eventID(b) || eventID(a) == eventID(e) {
		t.Fatal("paths did not separate event identities")
	}
}

// pathlessEventID is eventID of the event above, computed on main before
// paths existed.
const pathlessEventID = "4b9185cab5ae41b41325497b"
