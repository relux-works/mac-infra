package journal

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newJournal(t *testing.T, capacity int) *Journal {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "j")
	j, err := Open(dir, capacity)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func alarm(n int) Entry {
	return Entry{TS: time.Unix(int64(1_800_000_000+n), 0).UTC(), Kind: "alarm", Source: "rule:policy_unsigned_outbound", Actor: "test", Target: "app=/x host=example.org", Action: "alarm"}
}

// The ring stays bounded: after capacity+N appends the journal holds at most
// capacity plus a tenth, the newest entries are present, the oldest are gone,
// seq is monotonic without reuse, and the chain verifies.
func TestRingBounded(t *testing.T) {
	j := newJournal(t, 10)
	for i := 1; i <= 25; i++ {
		e, err := j.Append(alarm(i))
		if err != nil || e.Seq != uint64(i) {
			t.Fatalf("append %d: seq %d err %v", i, e.Seq, err)
		}
	}
	entries, err := j.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > 11 || len(entries) < 10 || entries[len(entries)-1].Seq != 25 || entries[0].Seq < 15 {
		t.Fatalf("window: %d entries, seq %d..%d", len(entries), entries[0].Seq, entries[len(entries)-1].Seq)
	}
	if err = Verify(entries); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(j.path())
	if info.Size() > 11*MaxEntryBytes || info.Mode().Perm() != 0600 {
		t.Fatalf("file size %d perm %v", info.Size(), info.Mode().Perm())
	}
}

// Negative: a record edited inside the window breaks verification, and
// Append refuses to extend a broken chain (no write after tampering).
func TestTamperDetected(t *testing.T) {
	j := newJournal(t, 100)
	for i := 1; i <= 3; i++ {
		if _, err := j.Append(alarm(i)); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(j.path())
	edited := strings.Replace(string(raw), `"seq":2,"ts":"2027-01-15T08:00:02Z","kind":"alarm"`, `"seq":2,"ts":"2027-01-15T08:00:02Z","kind":"warning"`, 1)
	if edited == string(raw) {
		t.Fatal("test edit did not apply")
	}
	if err := os.WriteFile(j.path(), []byte(edited), 0600); err != nil {
		t.Fatal(err)
	}
	entries, _ := j.Read()
	if Verify(entries) == nil {
		t.Fatal("tampered record verified")
	}
	if _, err := j.Append(alarm(4)); err == nil {
		t.Fatal("append extended a broken chain")
	}
	after, _ := os.ReadFile(j.path())
	if string(after) != edited {
		t.Fatal("refused append changed the file")
	}
}

// Negative: kinds outside the allowed set, entries without an actor, and
// entries above MaxEntryBytes are refused before anything is written. A
// valid entry next to them is accepted (control).
func TestInvalidEntriesRefused(t *testing.T) {
	j := newJournal(t, 100)
	bad := []Entry{
		func() Entry { e := alarm(1); e.Kind = "flow"; return e }(),
		func() Entry { e := alarm(1); e.Actor = ""; return e }(),
		func() Entry { e := alarm(1); e.Target = strings.Repeat("x", MaxEntryBytes); return e }(),
	}
	for _, e := range bad {
		if _, err := j.Append(e); err == nil {
			t.Errorf("accepted %+v", e.Kind)
		}
	}
	if _, err := os.Stat(j.path()); !os.IsNotExist(err) {
		t.Fatal("refused entries created the journal")
	}
	if e, err := j.Append(alarm(1)); err != nil || e.Seq != 1 {
		t.Fatalf("control: %v %v", e, err)
	}
}

// Appends from separate handles (watcher and CLI processes) are serialised:
// every append gets a unique seq and the chain verifies.
func TestConcurrentAppends(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "j")
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, err := Open(dir, 1000)
			if err != nil {
				t.Error(err)
				return
			}
			for i := 0; i < 10; i++ {
				if _, err := j.Append(alarm(i)); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	j, _ := Open(dir, 1000)
	entries, err := j.Read()
	if err != nil || len(entries) != 80 || entries[79].Seq != 80 || Verify(entries) != nil {
		t.Fatalf("entries %d err %v verify %v", len(entries), err, Verify(entries))
	}
}

// Negative: a group/world-accessible directory and a symlinked journal file
// are refused.
func TestUnsafePathsRefused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, 10); err == nil {
		t.Fatal("0755 dir accepted")
	}
	j := newJournal(t, 10)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Symlink(target, j.path()); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(alarm(1)); err == nil {
		t.Fatal("append followed a symlinked journal")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatal("symlink target written")
	}
}

// Negative: a replaced record that is self-consistent (recomputed hash, same
// seq) still breaks the chain to its successor, so a rewritten history inside
// the window is detected even though every single hash holds.
func TestReplacedRecordBreaksChain(t *testing.T) {
	j := newJournal(t, 100)
	for i := 1; i <= 3; i++ {
		if _, err := j.Append(alarm(i)); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := j.Read()
	forged := entries[1]
	forged.Target = "app=/innocent"
	forged.Hash = forged.digest()
	entries[1] = forged
	if err := Verify(entries); err == nil || !strings.Contains(err.Error(), "broken chain") {
		t.Fatalf("replaced record verified: %v", err)
	}
}
