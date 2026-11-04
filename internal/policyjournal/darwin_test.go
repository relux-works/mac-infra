//go:build darwin

package policyjournal

import (
	"bytes"
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
	f, e := OpenJournal(p)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := OpenJournal(p); e == nil {
		second.Close()
		t.Fatal("duplicate writer admitted")
	}
	_ = f.Close()
	secret := filepath.Join(r, "secret")
	put(t, secret, "SENTINEL")
	link := filepath.Join(r, "link")
	_ = os.Symlink(secret, link)
	fifo := filepath.Join(r, "fifo")
	if e := unix.Mkfifo(fifo, 0600); e != nil {
		t.Fatal(e)
	}
	if s := Inspect(OSMetadata{}, fifo); s.State != "unsupported" {
		t.Fatal(s)
	}
	for _, bad := range []string{link, fifo, filepath.Join(r, Names[0])} {
		if f, e := OpenJournal(bad); e == nil {
			f.Close()
			t.Fatal("unsafe journal admitted")
		}
	}
	data, _ := os.ReadFile(secret)
	if !bytes.Equal(data, []byte("SENTINEL")) {
		t.Fatal("secret changed")
	}
	hard := filepath.Join(r, "hard")
	_ = os.Link(secret, hard)
	if f, e := OpenJournal(hard); e == nil {
		f.Close()
		t.Fatal("hardlink admitted")
	}
	public := filepath.Join(r, "public")
	put(t, public, "SENTINEL")
	_ = os.Chmod(public, 0644)
	if f, e := OpenJournal(public); e == nil {
		f.Close()
		t.Fatal("public log admitted")
	}
	_ = os.Chmod(r, 0755)
	if f, e := OpenJournal(p); e == nil {
		f.Close()
		t.Fatal("public parent admitted")
	}
}
