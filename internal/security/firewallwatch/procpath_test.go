package firewallwatch

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Package tests never resolve fixture pids against live processes: a fixture
// pid could belong to a real process. The real resolver has its own tests.
func init() { lookupProcessImage = func(int, string) processImage { return processImage{} } }

// signerOnly adapts a test inspector that reports only a signer.
func signerOnly(f func(context.Context, string) (string, error)) func(context.Context, string) (codeFacts, error) {
	return func(ctx context.Context, path string) (codeFacts, error) {
		v, err := f(ctx, path)
		return codeFacts{Signer: v}, err
	}
}

const (
	hashA = "94fbd37b8f8951bb0e37c1229a071fd321448817"
	hashB = "d0795d8bca8f0892188e582bc30a4361228fed4f"
)

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
// than 15 bytes, a prefix match only when it printed exactly 15 (its cut). A
// shorter or longer printed name is never a prefix match, and an empty one
// never matches.
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
		{"com.cisco.anyconnect", "com.cisco.anycon", false},
		{"", "", false},
		{"x", "", false},
	}
	for _, c := range cases {
		if got := nameMatches(c.comm, c.printed); got != c.want {
			t.Fatalf("nameMatches(%q, %q) = %v", c.comm, c.printed, got)
		}
	}
}

// confirmImage returns the image only when the process read before and after
// the image lookup is the printed one with an unchanged name and start time;
// each broken condition gives the zero value, and the control returns the
// image with its hash.
func TestConfirmImage(t *testing.T) {
	proc := procInfo{PID: 42, Comm: "netproxy", Start: 100}
	img := processImage{Path: "/opt/pilot/netproxy", CDHash: hashA}
	cases := []struct {
		name          string
		before, after procInfo
		failBefore    bool
		failAfter     bool
		image         processImage
		failImage     bool
		want          processImage
	}{
		{name: "confirmed", before: proc, after: proc, image: img, want: img},
		{name: "confirmed without hash", before: proc, after: proc, image: processImage{Path: img.Path}, want: processImage{Path: img.Path}},
		{name: "other name", before: procInfo{PID: 42, Comm: "other", Start: 100}, after: proc, image: img},
		{name: "other pid", before: procInfo{PID: 43, Comm: "netproxy", Start: 100}, after: proc, image: img},
		{name: "exited before", failBefore: true, image: img},
		{name: "no image", before: proc, after: proc, failImage: true},
		{name: "empty path", before: proc, after: proc, image: processImage{CDHash: hashA}},
		{name: "exited after", before: proc, failAfter: true, image: img},
		{name: "start changed", before: proc, after: procInfo{PID: 42, Comm: "netproxy", Start: 101}, image: img},
		{name: "name changed", before: proc, after: procInfo{PID: 42, Comm: "other", Start: 100}, image: img},
	}
	for _, c := range cases {
		reads := 0
		info := func(int) (procInfo, bool) {
			reads++
			if reads == 1 {
				return c.before, !c.failBefore
			}
			return c.after, !c.failAfter
		}
		image := func(int) (processImage, bool) { return c.image, !c.failImage }
		if got := confirmImage(42, "netproxy", info, image); got != c.want {
			t.Fatalf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

// Each pid is looked up once per sample; a confirmed image gives the item its
// Path and ImageCDHash; an unconfirmed one leaves both empty; other sources
// are never looked up.
func TestAttributePathsOncePerPID(t *testing.T) {
	items := []Item{
		{Source: "nettop", App: "a", PID: 10, ProcName: "a"},
		{Source: "nettop", App: "a", PID: 10, ProcName: "a"},
		{Source: "nettop", App: "b", PID: 11, ProcName: "b"},
		{Source: "alf", App: "c", PID: 12, ProcName: "c"},
	}
	calls := map[int]int{}
	attributePaths(items, func(pid int, name string) processImage {
		calls[pid]++
		if pid == 10 {
			return processImage{Path: "/Applications/A.app/Contents/MacOS/a", CDHash: hashA}
		}
		return processImage{}
	})
	if calls[10] != 1 || calls[11] != 1 || calls[12] != 0 {
		t.Fatalf("lookups: %v", calls)
	}
	for _, i := range []int{0, 1} {
		if items[i].Path != "/Applications/A.app/Contents/MacOS/a" || items[i].ImageCDHash != hashA {
			t.Fatalf("item %d: %+v", i, items[i])
		}
	}
	if items[2].Path != "" || items[2].ImageCDHash != "" || items[3].Path != "" {
		t.Fatalf("unconfirmed or other source got a path: %+v %+v", items[2], items[3])
	}
}

// A sample's nettop rows reach collection with the image the lookup
// resolved: sampleNettop wires attribution in (PR81 review r1 found the wiring
// untested). Limit: the lookup is a fixture, not the kernel.
func TestSampleNettopAttributesImages(t *testing.T) {
	saved := lookupProcessImage
	defer func() { lookupProcessImage = saved }()
	lookupProcessImage = func(pid int, name string) processImage {
		if pid == 592 && name == "netproxy" {
			return processImage{Path: "/opt/pilot/netproxy", CDHash: hashA}
		}
		return processImage{}
	}
	s, _ := journalStore(t)
	out := &cappedBuffer{limit: 1 << 20}
	out.WriteString("time,,bytes_out\nnetproxy.592,,10\n\"tcp4 10.0.0.2:5000<->93.184.216.34:443\",,100\n")
	var got []Item
	collect := func(it Item) bool { got = append(got, it); return false }
	if _, e := s.sampleNettop(nettopRun{output: out}, time.Now(), collect, func(bool) error { return nil }, noDrain); e != nil {
		t.Fatal(e)
	}
	if len(got) != 1 || got[0].Path != "/opt/pilot/netproxy" || got[0].ImageCDHash != hashA {
		t.Fatalf("collected %+v", got)
	}
}

// signerFixture is a store whose inspector reports signer and hash for any
// path, counting its runs, and a real file for the cache's identity.
func signerFixture(t *testing.T, signer, hash string) (*Store, string, *int) {
	t.Helper()
	s, _ := journalStore(t)
	path := filepath.Join(t.TempDir(), "netproxy")
	if e := os.WriteFile(path, []byte("image"), 0o600); e != nil {
		t.Fatal(e)
	}
	runs := 0
	s.inspectSigner = func(context.Context, string) (codeFacts, error) {
		runs++
		return codeFacts{Signer: signer, CDHash: hash}, nil
	}
	return s, path, &runs
}

// A running process gets its file's signer only when the file's hash is the
// image hash the kernel reported; another hash, no reported hash, or a file
// with no hash gives "unknown". The plain lookup (other sources) is
// unchanged (control).
func TestRunningSignerRequiresImageHash(t *testing.T) {
	s, path, _ := signerFixture(t, "Apple", hashA)
	ctx := context.Background()
	if got := s.runningSigner(ctx, path, hashA); got != "Apple" {
		t.Fatalf("matching image: %q", got)
	}
	for _, running := range []string{hashB, "", "none", strings.ToUpper(hashA)} {
		if got := s.runningSigner(ctx, path, running); got != "unknown" {
			t.Fatalf("image %q: %q", running, got)
		}
	}
	if got := s.signer(ctx, path); got != "Apple" {
		t.Fatalf("plain lookup: %q", got)
	}
	unsigned, upath, _ := signerFixture(t, "Apple", "")
	if got := unsigned.runningSigner(ctx, upath, hashA); got != "unknown" {
		t.Fatalf("file without hash: %q", got)
	}
	for _, v := range unsigned.State.Signers {
		if v.CDHash != noCDHash {
			t.Fatalf("no-hash inspection recorded %q", v.CDHash)
		}
	}
}

// A cached entry recorded before hashes were kept is inspected again for a
// running process, once; a plain lookup still uses it as before (control).
func TestRunningSignerReinspectsEntryWithoutHash(t *testing.T) {
	s, path, runs := signerFixture(t, "Apple", hashA)
	ctx := context.Background()
	s.signer(ctx, path)
	for k, v := range s.State.Signers {
		v.CDHash = ""
		s.State.Signers[k] = v
	}
	s.signer(ctx, path)
	if *runs != 1 {
		t.Fatalf("plain lookup re-inspected: %d runs", *runs)
	}
	if got := s.runningSigner(ctx, path, hashA); got != "Apple" || *runs != 2 {
		t.Fatalf("running lookup: %q after %d runs", got, *runs)
	}
	if got := s.runningSigner(ctx, path, hashA); got != "Apple" || *runs != 2 {
		t.Fatalf("hash not cached: %q after %d runs", got, *runs)
	}
}

// collect takes a nettop row's signer from the running image: with a
// mismatched hash the event's signer is "unknown" although the file is
// Apple's; with the matching hash it is "Apple" (control).
func TestCollectAttestsNettopSigner(t *testing.T) {
	port := 443
	for _, c := range []struct{ running, want string }{{hashB, "unknown"}, {hashA, "Apple"}} {
		s, path, _ := signerFixture(t, "Apple", hashA)
		it := Item{Source: "nettop", Kind: "outbound", App: "netproxy", Verdict: "observed", Remote: "lan", RemotePort: &port, Count: 1, PID: 7, ProcName: "netproxy", Path: path, ImageCDHash: c.running}
		if !s.collect(context.Background(), &Classifier{}, it) {
			t.Fatal("fixture row emitted nothing")
		}
		e := s.State.Events[len(s.State.Events)-1]
		if e.Signer != c.want || e.Path != path {
			t.Fatalf("image %s: signer %q path %q", c.running, e.Signer, e.Path)
		}
	}
}

// codesign's CDHash line is taken only as 40 lowercase hex digits; anything
// else, or no line, is noCDHash.
func TestParseCDHash(t *testing.T) {
	if got := ParseCDHash("Executable=/bin/ls\nCandidateCDHash sha256=" + hashA + "\nCDHash=" + hashA + "\n"); got != hashA {
		t.Fatalf("valid: %q", got)
	}
	for _, out := range []string{"", "CDHash=" + strings.ToUpper(hashA), "CDHash=" + hashA[:39], "CDHash=" + hashA + "00", " CDHash=" + hashA, "code object is not signed at all"} {
		if got := ParseCDHash(out); got != noCDHash {
			t.Fatalf("%q: %q", out, got)
		}
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

// The path is not part of an event's identity, so a reader that predates
// paths (it drops them) computes the same identity; a pathless event keeps
// exactly the identity it had before paths existed (a fixed value computed on
// main before this change).
func TestEventIDIgnoresPath(t *testing.T) {
	e := pathEvent("")
	if got := eventID(e); got != pathlessEventID {
		t.Fatalf("a pathless event changed identity: %s", got)
	}
	if eventID(pathEvent("/opt/pilot/netproxy")) != pathlessEventID {
		t.Fatal("a path changed the identity")
	}
}

// pathlessEventID is eventID of pathEvent(""), computed on main before paths
// existed.
const pathlessEventID = "4b9185cab5ae41b41325497b"

func pathEvent(path string) Event {
	port := 443
	return Event{TS: time.Date(2026, 10, 30, 19, 0, 0, 0, time.UTC), Source: "nettop", App: "netproxy", Signer: "unknown", Verdict: "observed", Port: &port, RemoteClass: "internet-raw-ip", Bucket: "160.79.104.0/24", Counts: 1, Label: "digest", Reason: "r", Mode: "shadow", Path: path}
}

// replayRemoval appends one journal record that adds events and removes the
// events at the given positions, through the watcher's own append, and
// replays the written line on a fresh store; it returns the events left and
// the line. stripPaths replays it as a reader that predates paths sees it:
// without the removal paths and the events' path fields.
func replayRemoval(t *testing.T, events []Event, remove []int, stripPaths bool) ([]Event, string) {
	t.Helper()
	s, _ := journalStore(t)
	s.delta.events = events
	for _, i := range remove {
		s.eventRemoved(events[i])
	}
	if e := s.appendJournal(time.Now(), false); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(s.journalPath())
	if e != nil {
		t.Fatal(e)
	}
	line := strings.TrimSpace(string(raw))
	if strings.Contains(line, "\n") {
		t.Fatalf("more than one record: %s", line)
	}
	data := []byte(line)
	if stripPaths {
		var m map[string]any
		if e := json.Unmarshal(data, &m); e != nil {
			t.Fatal(e)
		}
		delete(m, "removed_event_paths")
		for _, v := range m["events"].([]any) {
			delete(v.(map[string]any), "path")
		}
		if data, e = json.Marshal(m); e != nil {
			t.Fatal(e)
		}
	}
	var back journalRecord
	if e := json.Unmarshal(data, &back); e != nil {
		t.Fatal(e)
	}
	r, _ := journalStore(t)
	if e := r.applyRecord(back); e != nil {
		t.Fatal(e)
	}
	r.dropEvents()
	return r.State.Events, line
}

// Two events that differ only by path: removing one leaves the other on this
// reader, and leaves one event on a reader that predates paths (PR81 review
// r1, which found the old reader kept both). Pathless removals write no path
// field, so their records are unchanged (control).
func TestJournalPathRemovalRollbackSafe(t *testing.T) {
	a, b := pathEvent("/opt/pilot/netproxy"), pathEvent("/Users/x/src/build/netproxy")
	left, raw := replayRemoval(t, []Event{a, b}, []int{1}, false)
	if len(left) != 1 || left[0].Path != a.Path {
		t.Fatalf("this reader kept %+v", left)
	}
	if !strings.Contains(raw, `"removed_event_paths":["/Users/x/src/build/netproxy"]`) {
		t.Fatalf("record without the removed path: %s", raw)
	}
	left, _ = replayRemoval(t, []Event{a, b}, []int{1}, true)
	if len(left) != 1 {
		t.Fatalf("a pathless reader kept %d events", len(left))
	}
	left, _ = replayRemoval(t, []Event{a, b}, []int{0}, false)
	if len(left) != 1 || left[0].Path != b.Path {
		t.Fatalf("removing the first kept %+v", left)
	}
	p := pathEvent("")
	left, raw = replayRemoval(t, []Event{p, a}, []int{0}, false)
	if len(left) != 1 || left[0].Path != a.Path || strings.Contains(raw, "removed_event_paths") {
		t.Fatalf("pathless removal kept %+v, record %s", left, raw)
	}
}

// A record whose removal paths do not line up with its removals, or name an
// invalid path, is refused, so replay never guesses which event a removal
// meant; a well-formed one applies (control).
func TestJournalRemovalPathsChecked(t *testing.T) {
	id := eventID(pathEvent(""))
	bad := []journalRecord{
		{Seq: 1, Type: recordDelta, RemovedEvents: []string{id, id}, RemovedEventPaths: []string{"/a"}},
		{Seq: 1, Type: recordDelta, RemovedEvents: []string{id}, RemovedEventPaths: []string{"/a", "/b"}},
		{Seq: 1, Type: recordDelta, RemovedEvents: []string{id}, RemovedEventPaths: []string{"relative"}},
		{Seq: 1, Type: recordDelta, RemovedEvents: []string{id}, RemovedEventPaths: []string{"/a\n"}},
	}
	for i, r := range bad {
		s, _ := journalStore(t)
		if e := s.applyRecord(r); e == nil {
			t.Fatalf("record %d applied", i)
		}
	}
	s, _ := journalStore(t)
	if e := s.applyRecord(journalRecord{Seq: 1, Type: recordDelta, RemovedEvents: []string{id, id}, RemovedEventPaths: []string{"", "/a"}}); e != nil {
		t.Fatalf("control: %v", e)
	}
}
