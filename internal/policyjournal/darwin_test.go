//go:build darwin

package policyjournal

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Documents the actual OS limit: event-only is a notification hint, not read
// isolation. Reads here are synthetic test controls, never production behavior.
func TestEventOnlyIsNotReadIsolation(t *testing.T) {
	p := filepath.Join(t.TempDir(), Names[0])
	put(t, p, "synthetic")
	fd, e := unix.Open(p, unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	if n, e := unix.Read(fd, make([]byte, 16)); e != nil || n != 9 {
		t.Fatalf("documented macOS control changed: %d %v", n, e)
	}
}

// Proves O_EVTONLY notifications, including an equal-size/equal-mtime rewrite
// and rearming after atomic replace. Unreadable inputs report a coverage gap.
func TestVnodeWriteAndReplacement(t *testing.T) {
	r := t.TempDir()
	p := filepath.Join(r, Names[0])
	put(t, p, "old")
	mtime := time.Now().Add(-time.Hour)
	_ = os.Chtimes(p, mtime, mtime)
	w, e := NewWatcher()
	if e != nil {
		t.Fatal(e)
	}
	defer w.Close()
	if w.Sync([]string{r, p}) {
		t.Fatal("watch gap")
	}
	if e := os.Chmod(p, 0000); e != nil {
		t.Fatal(e)
	}
	blocked, e := NewWatcher()
	if e != nil {
		t.Fatal(e)
	}
	if !blocked.Sync([]string{p}) {
		blocked.Close()
		t.Fatal("unreadable input did not report gap")
	}
	blocked.Close()
	if e = os.Chmod(p, 0600); e != nil {
		t.Fatal(e)
	}
	put(t, p, "new")
	_ = os.Chtimes(p, mtime, mtime)
	changed, e := w.Wait()
	if e != nil || !changed[p] {
		t.Fatalf("%v %v", changed, e)
	}
	next := filepath.Join(r, "next")
	put(t, next, "replacement")
	if e = os.Rename(next, p); e != nil {
		t.Fatal(e)
	}
	changed, e = w.Wait()
	if e != nil || (!changed[r] && !changed[p]) {
		t.Fatalf("%v %v", changed, e)
	}
	if w.Sync([]string{r, p}) {
		t.Fatal("replacement rearm gap")
	}
	put(t, p, "again")
	changed, e = w.Wait()
	if e != nil || !changed[p] {
		t.Fatalf("%v %v", changed, e)
	}
}

// Proves single-writer exclusion and refusal of symlinks, hardlinks, policy
// names, public journals/directories. Existing sentinel bytes remain untouched.
func TestPrivateJournalAdmission(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_ = os.Chmod(r, 0700)
	p := filepath.Join(r, "journal.jsonl")
	f, e := OpenJournal(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := OpenJournal(p, nil); e == nil {
		second.Close()
		t.Fatal("duplicate writer admitted")
	}
	_ = f.Close()
	secret := filepath.Join(r, "secret")
	put(t, secret, "SENTINEL")
	link := filepath.Join(r, "link.jsonl")
	_ = os.Symlink(secret, link)
	fifo := filepath.Join(r, "fifo.jsonl")
	if e := unix.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if s := Inspect(OSMetadata{}, fifo); s.State != "unsupported" {
		t.Fatal(s)
	}
	for _, bad := range []string{link, fifo, filepath.Join(r, Names[0])} {
		if f, e := OpenJournal(bad, nil); e == nil {
			f.Close()
			t.Fatal("unsafe journal admitted")
		}
	}
	data, _ := os.ReadFile(secret)
	if !bytes.Equal(data, []byte("SENTINEL")) {
		t.Fatal("secret changed")
	}
	hard := filepath.Join(r, "hard.jsonl")
	_ = os.Link(secret, hard)
	if f, e := OpenJournal(hard, nil); e == nil {
		f.Close()
		t.Fatal("hardlink admitted")
	}
	public := filepath.Join(r, "public.log")
	put(t, public, "SENTINEL")
	_ = os.Chmod(public, 0644)
	if f, e := OpenJournal(public, nil); e == nil {
		f.Close()
		t.Fatal("public log admitted")
	}
	_ = os.Chmod(r, 0755)
	if f, e := OpenJournal(p, nil); e == nil {
		f.Close()
		t.Fatal("public parent admitted")
	}
}

// Proves the journal name allowlist: the forms the pipeline emits (events.jsonl,
// service.log) and other lowercase .jsonl/.log names are admitted; policy names,
// their case aliases, other extensions, uppercase and non-ASCII names are not.
func TestJournalNameForms(t *testing.T) {
	for _, ok := range []string{"events.jsonl", "service.log", "a.b-c_d.jsonl", "2026-11-04.log"} {
		if !journalName.MatchString(ok) {
			t.Errorf("valid %q refused", ok)
		}
	}
	for _, bad := range []string{Names[0], Names[1], "REMOTE-SETTINGS.JSON", "Policy-Limits.json", "journal", "events.json", "Events.jsonl", "events.JSONL", "x.jsonl.json", ".hidden.jsonl", "événements.jsonl", "events.jsonl/"} {
		if journalName.MatchString(bad) {
			t.Errorf("invalid %q admitted", bad)
		}
	}
}

// Proves output admission separates the journal from monitored inputs under the
// filesystem's real name and object equivalence: exact names, case aliases (an
// existing and a not-yet-created policy), a valid name inside a monitored home
// or a case alias of that home, a symlink and a hardlink to a policy are all
// refused, every policy byte stays unchanged and no file is created in the home.
// A separate private journal is admitted as the paired positive control. On a
// case-sensitive filesystem the aliases are distinct names; they must still be
// refused, so the test does not depend on the volume's case behaviour.
func TestJournalSeparatedFromPolicyInputs(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	_ = os.Chmod(r, 0700)
	h := filepath.Join(r, ".claude")
	if e = os.Mkdir(h, 0700); e != nil {
		t.Fatal(e)
	}
	settings := filepath.Join(h, Names[0])
	put(t, settings, "POLICY_SENTINEL")
	homes := []string{h}
	unchanged := func(label string) {
		t.Helper()
		data, e := os.ReadFile(settings)
		if e != nil || string(data) != "POLICY_SENTINEL" {
			t.Fatalf("%s: policy changed: %q %v", label, data, e)
		}
		entries, e := os.ReadDir(h)
		if e != nil || len(entries) != 1 {
			t.Fatalf("%s: home contents changed: %v %v", label, entries, e)
		}
	}
	link := filepath.Join(r, "to-policy.jsonl")
	if e = os.Symlink(settings, link); e != nil {
		t.Fatal(e)
	}
	hard := filepath.Join(r, "policy-hard.jsonl")
	if e = os.Link(settings, hard); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{
		settings,
		filepath.Join(h, Names[1]),
		filepath.Join(h, "REMOTE-SETTINGS.JSON"),
		filepath.Join(h, "POLICY-LIMITS.JSON"),
		filepath.Join(h, "events.jsonl"),
		filepath.Join(r, ".CLAUDE", "events.jsonl"),
		link,
		hard,
	} {
		if f, e := OpenJournal(bad, homes); e == nil {
			f.Close()
			t.Fatalf("%s admitted", bad)
		}
		unchanged(bad)
	}
	if _, e = os.Lstat(filepath.Join(h, Names[1])); !os.IsNotExist(e) {
		t.Fatal("absent policy created")
	}
	_ = os.Remove(hard)
	for _, ok := range []string{filepath.Join(r, "events.jsonl"), filepath.Join(r, "service.log")} {
		f, e := OpenJournal(ok, homes)
		if e != nil {
			t.Fatalf("%s refused: %v", ok, e)
		}
		if _, e = f.WriteString("{}\n"); e != nil {
			t.Fatal(e)
		}
		_ = f.Close()
		unchanged(ok)
	}
}

// Proves the per-scan recheck: an observer whose journal directory is a
// monitored home stops with an error before scanning, and writes no record
// for any policy file.
func TestRunStopsWhenJournalDirIsHome(t *testing.T) {
	r, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	h := filepath.Join(r, ".claude")
	if e = os.Mkdir(h, 0700); e != nil {
		t.Fatal(e)
	}
	put(t, filepath.Join(h, Names[0]), "POLICY_SENTINEL")
	var out bytes.Buffer
	o := &Observer{FS: OSMetadata{}, Writer: &out, JournalDir: h}
	if e = Run(t.Context(), r, nil, time.Second, o); e == nil {
		t.Fatal("observer ran with its journal inside a monitored home")
	}
	if bytes.Contains(out.Bytes(), []byte(`"file"`)) {
		t.Fatalf("scanned after separation failure: %s", out.String())
	}
	// Positive control: the same root with a separate journal directory scans.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	out.Reset()
	o = &Observer{FS: OSMetadata{}, Writer: &out, JournalDir: r}
	if e = Run(ctx, r, nil, time.Second, o); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(out.Bytes(), []byte(`"kind":"baseline"`)) {
		t.Fatalf("no baseline: %s", out.String())
	}
}
