package firewallwatch

// Regression witnesses from the independent PR69 review r4 (Codex,
// review-pr69-r4.md), kept as written by the reviewer.
import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Accepted torn tails must retain all valid-prefix removals, including those
// whose runtime expiry differs from wall-time oldest order. Controls: no tail,
// incomplete tail and complete invalid tail, each against runtime B/C.
func TestR4TornTailRemoval(t *testing.T) {
	for _, suffix := range []string{"", `{"seq":`, "garbage\n"} {
		t.Run(strings.ReplaceAll(suffix, "\n", "NL"), func(t *testing.T) {
			s := pruneFixture(t, 2)
			base := time.Now()
			futureA := base.Add(12 * time.Hour).Round(0)
			s.Observe(newKey(1), futureA, ruleClassify)
			start := sameWallLaterMono(t, base, 16*24*time.Hour)
			if e := s.Save(start); e != nil {
				t.Fatal(e)
			}
			s = reopen(t, s.Config)
			if e := s.Save(start); e != nil {
				t.Fatal(e)
			}
			later := sameWallLaterMono(t, base.Add(8*24*time.Hour), 8*24*time.Hour+time.Second)
			observeFlush(t, s, newKey(2), start)
			observeFlush(t, s, newKey(3), later)
			if s.journalRecords != 2 {
				t.Fatal("fixture unexpectedly snapshotted")
			}
			want := eventApps(s.State.Events)
			if !reflect.DeepEqual(want, []string{"app2", "app3"}) {
				t.Fatal("fixture", want)
			}
			appendRaw(t, s.journalPath(), suffix)
			hashes := dirHashes(t, s.Config.StateDir)
			r := reopen(t, s.Config)
			got := eventApps(r.State.Events)
			if !reflect.DeepEqual(hashes, dirHashes(t, s.Config.StateDir)) {
				t.Fatal("reader wrote files")
			}
			t.Logf("suffix=%q runtime=%v reader=%v torn=%d", suffix, want, got, r.State.Health.JournalTornTail)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("valid-prefix removals lost: got %v want %v", got, want)
			}
		})
	}
}

// Heartbeat replay preserves exact spans/gaps under repeated snapshots,
// tail overflow, both sources, stalls and source ends; no reader mutates bytes.
func TestR4CoverageTransitions(t *testing.T) {
	for _, cap := range []int{1, 3, 260} {
		c := testConfig(t)
		c.MaxEntries = cap
		s := reopen(t, c)
		b := time.Now().Add(-time.Hour).Round(0)
		s.BeginCoverage(b)
		s.BeginSourceCoverage(SourceNetfilter, b.Add(time.Millisecond))
		if e := s.Save(b.Add(2 * time.Millisecond)); e != nil {
			t.Fatal(e)
		}
		for i := 1; i <= 140; i++ {
			at := b.Add(time.Duration(i) * time.Second)
			source := ""
			if i%2 == 0 {
				source = SourceNetfilter
			}
			sc := s.Coverage(source)
			sc.StallCoverage(at)
			sc.ResumeCoverage(at.Add(100 * time.Millisecond))
			if i == 140 {
				s.EndCoverage(at.Add(200 * time.Millisecond))
				s.Coverage(SourceNetfilter).EndCoverage(at.Add(300 * time.Millisecond))
			}
			if e := s.Checkpoint(at.Add(500 * time.Millisecond)); e != nil {
				t.Fatal(e)
			}
			r := reopen(t, c)
			if a, z := canonicalCoverage(s.State.Coverage), canonicalCoverage(r.State.Coverage); a != z {
				t.Fatalf("cap %d step %d spans differ", cap, i)
			}
			a, z := s.Split(b, at.Add(500*time.Millisecond)).Window, r.Split(b, at.Add(500*time.Millisecond)).Window
			if a.Truncated != z.Truncated || !reflect.DeepEqual(a.CoverageGaps, z.CoverageGaps) {
				t.Fatalf("cap %d step %d gaps differ", cap, i)
			}
		}
	}
}

// A heartbeat tail >256 must take a snapshot, then restart remains readable.
func TestR4TailLimit(t *testing.T) {
	c := testConfig(t)
	c.MaxEntries = 300
	s := reopen(t, c)
	b := time.Now().Add(-time.Hour).Round(0)
	s.BeginCoverage(b)
	if e := s.Save(b); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 257; i++ {
		at := b.Add(time.Duration(i+1) * time.Second)
		s.StallCoverage(at)
		s.ResumeCoverage(at.Add(100 * time.Millisecond))
	}
	if e := s.Checkpoint(b.Add(260 * time.Second)); e != nil {
		t.Fatal(e)
	}
	if s.journalRecords != 0 {
		t.Fatal("tail overflow did not snapshot")
	}
	if a, z := canonicalCoverage(s.State.Coverage), canonicalCoverage(reopen(t, c).State.Coverage); a != z {
		t.Fatal("tail-limit snapshot differs")
	}
	if _, e := os.Stat(filepath.Join(c.StateDir, journalFile)); !os.IsNotExist(e) {
		t.Fatal("journal remained", e)
	}
}

// Independent read-only stores opening the same immutable files concurrently
// must not share unsynchronized mutable replay state. No writer runs here.
func TestR4ParallelReadersAtCap(t *testing.T) {
	s := pruneFixture(t, 3)
	b := time.Now()
	for i := 0; i < 3; i++ {
		s.Observe(newKey(i), b.Add(time.Duration(i)*time.Millisecond), ruleClassify)
	}
	if e := s.Save(b); e != nil {
		t.Fatal(e)
	}
	observeFlush(t, s, newKey(99), b.Add(time.Second))
	hashes := dirHashes(t, s.Config.StateDir)
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				r, e := OpenStore(s.Config)
				if e != nil {
					t.Error(e)
					return
				}
				if len(r.State.Events) != 3 {
					t.Errorf("events %d", len(r.State.Events))
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(hashes, dirHashes(t, s.Config.StateDir)) {
		t.Fatal("reader changed artifacts")
	}
}
