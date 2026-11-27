package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func requireReadFailure(t *testing.T, dir, reason string) {
	t.Helper()
	entries, err := ReadExisting(dir)
	var failure *ReadError
	if !errors.As(err, &failure) || failure.Reason != reason || entries != nil {
		t.Fatalf("want reason=%s with no partial entries; got entries=%d err=%v", reason, len(entries), err)
	}
}

// A present safe journal, including an empty one and a retained compacted chain,
// is read without creating a lock, altering bytes, modes, names or mtimes.
func TestReadExistingPreservesJournal(t *testing.T) {
	for _, count := range []int{0, 3, 25} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			j := newJournal(t, 10)
			if count == 0 {
				if err := os.WriteFile(j.path(), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			for i := 1; i <= count; i++ {
				if _, err := j.Append(alarm(i)); err != nil {
					t.Fatal(err)
				}
			}
			// Remove the writer's fixture lock to detect any reader-created lock.
			if err := os.Remove(filepath.Join(j.dir, "journal.lock")); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			before, err := os.ReadFile(j.path())
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(j.path())
			if err != nil {
				t.Fatal(err)
			}
			dirInfo, err := os.Stat(j.dir)
			if err != nil {
				t.Fatal(err)
			}
			got, err := ReadExisting(j.dir)
			if err != nil || got == nil {
				t.Fatalf("safe journal read: entries=%v err=%v", got, err)
			}
			want, err := j.Read()
			if err != nil || (len(want) != 0 && !reflect.DeepEqual(got, want)) || (len(want) == 0 && len(got) != 0) {
				t.Fatalf("entries differ from actual writer: %v", err)
			}
			after, err := os.ReadFile(j.path())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("reader changed bytes", err)
			}
			afterInfo, err := os.Stat(j.path())
			if err != nil || !os.SameFile(info, afterInfo) || afterInfo.Mode() != info.Mode() || !afterInfo.ModTime().Equal(info.ModTime()) {
				t.Fatal("reader changed file metadata", err)
			}
			afterDir, err := os.Stat(j.dir)
			if err != nil || !os.SameFile(dirInfo, afterDir) || afterDir.Mode() != dirInfo.Mode() || !afterDir.ModTime().Equal(dirInfo.ModTime()) {
				t.Fatal("reader changed directory metadata", err)
			}
			names, err := os.ReadDir(j.dir)
			if err != nil || len(names) != 1 || names[0].Name() != fileName {
				t.Fatal("reader created an artifact", err)
			}
		})
	}
}

// Missing paths are unavailable, never verified empty, and remain absent.
// Absolute aliases used by the existing joined path remain supported, while
// an alias whose final directory is a symlink remains unsafe after cleaning.
func TestReadExistingPathForms(t *testing.T) {
	parent := t.TempDir()
	missing := filepath.Join(parent, "missing")
	requireReadFailure(t, missing, "not_found")
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("reader created a missing directory", err)
	}
	j, err := Open(filepath.Join(parent, "j"), Capacity)
	if err != nil {
		t.Fatal(err)
	}
	requireReadFailure(t, j.dir, "not_found")
	if names, err := os.ReadDir(j.dir); err != nil || len(names) != 0 {
		t.Fatal("missing file caused writes", err)
	}
	if _, err := j.Append(alarm(1)); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{j.dir, j.dir + "/", j.dir + "//", j.dir + "/.", parent + "/./j"} {
		if entries, err := ReadExisting(dir); err != nil || len(entries) != 1 {
			t.Fatalf("supported absolute alias %q: %v", dir, err)
		}
	}
	alias := filepath.Join(parent, "alias")
	if err := os.Symlink(j.dir, alias); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{alias, alias + "/", alias + "/."} {
		requireReadFailure(t, dir, "unsafe_path")
	}
	requireReadFailure(t, "", "unsafe_path")
	requireReadFailure(t, "relative", "unsafe_path")
}

// The file must be caller-owned, private, regular and single-link; wrong
// modes, symlinks, hardlinks, directories and FIFOs cannot supply a snapshot.
// The FIFO case exercises the real nonblocking acquisition, not a mock.
func TestReadExistingUnsafePaths(t *testing.T) {
	for _, name := range []string{"dir-mode", "file-mode", "symlink", "hardlink", "directory", "fifo"} {
		t.Run(name, func(t *testing.T) {
			j := newJournal(t, Capacity)
			if _, err := j.Append(alarm(1)); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "dir-mode":
				if err := os.Chmod(j.dir, 0755); err != nil {
					t.Fatal(err)
				}
			case "file-mode":
				if err := os.Chmod(j.path(), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(j.path(), j.path()+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(j.path()+".real", j.path()); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(j.path(), j.path()+".link"); err != nil {
					t.Fatal(err)
				}
			case "directory", "fifo":
				if err := os.Remove(j.path()); err != nil {
					t.Fatal(err)
				}
				if name == "directory" {
					if err := os.Mkdir(j.path(), 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := syscall.Mkfifo(j.path(), 0600); err != nil {
					t.Fatal(err)
				}
			}
			requireReadFailure(t, j.dir, "unsafe_path")
		})
	}
}

// Strict framing and typed members reject malformed records even when an
// ignored duplicate/unknown field could leave the decoded hash unchanged.
// A valid record is a positive control for the same acquisition/parser path.
func TestReadExistingMalformed(t *testing.T) {
	j := newJournal(t, Capacity)
	if _, err := j.Append(alarm(1)); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(j.path())
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(raw), "\n")
	for _, tc := range []struct{ name, data string }{
		{"duplicate", strings.Replace(line, `"seq":1`, `"seq":1,"seq":1`, 1) + "\n"},
		{"escaped duplicate", strings.Replace(line, `"seq":1`, `"seq":1,"s\u0065q":1`, 1) + "\n"},
		{"unknown", strings.TrimSuffix(line, "}") + `,"extra":true}` + "\n"},
		{"wrong case", strings.Replace(line, `"seq":1`, `"Seq":1`, 1) + "\n"},
		{"missing", strings.Replace(line, `"seq":1,`, "", 1) + "\n"},
		{"null", strings.Replace(line, `"source":"rule:policy_unsigned_outbound"`, `"source":null`, 1) + "\n"},
		{"float", strings.Replace(line, `"seq":1`, `"seq":1.0`, 1) + "\n"},
		{"zero seq", strings.Replace(line, `"seq":1`, `"seq":0`, 1) + "\n"},
		{"trailing document", line + " {}\n"},
		{"missing newline", line},
		{"blank line", string(raw) + "\n"},
		{"partial record", string(raw) + `{"seq":2`},
		{"oversize line", line + strings.Repeat(" ", 4097-len(line)) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.data == string(raw) {
				t.Fatal("negative control did not change input")
			}
			if err := os.WriteFile(j.path(), []byte(tc.data), 0600); err != nil {
				t.Fatal(err)
			}
			requireReadFailure(t, j.dir, "malformed")
			after, err := os.ReadFile(j.path())
			if err != nil || string(after) != tc.data {
				t.Fatal("reader repaired malformed data", err)
			}
		})
	}
	if err := os.WriteFile(j.path(), []byte(line+strings.Repeat(" ", 4096-len(line))+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadExisting(j.dir); err != nil || len(got) != 1 {
		t.Fatalf("4096-byte valid neighbor: %v", err)
	}
}

// The actual writer's Unicode and literal replacement rune remain valid.
// Invalid original UTF-8 must be malformed even when JSON decoding would
// normalize it to that same rune and leave the canonical entry hash valid.
func TestReadExistingOriginalUTF8(t *testing.T) {
	j := newJournal(t, Capacity)
	entry := alarm(1)
	entry.Target = "Unicode-армянский-😀-replacement-\uFFFD"
	if _, err := j.Append(entry); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(j.path())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadExisting(j.dir); err != nil || len(got) != 1 || got[0].Target != entry.Target {
		t.Fatalf("valid Unicode writer control: %v", err)
	}
	needle := []byte("replacement-\uFFFD")
	if bytes.Count(raw, needle) != 1 {
		t.Fatal("replacement-rune control not applied")
	}
	for _, tc := range []struct {
		name    string
		invalid []byte
	}{
		{"invalid-leading-byte", []byte{0xff}},
		{"incomplete-multibyte-sequence", []byte{0xc2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			replacement := append([]byte("replacement-"), tc.invalid...)
			broken := bytes.Replace(raw, needle, replacement, 1)
			var decoded Entry
			if err := json.Unmarshal(broken, &decoded); err != nil {
				t.Fatal("JSON normalization control not applied", err)
			}
			if decoded.Target != entry.Target || Verify([]Entry{decoded}) != nil {
				t.Fatal("control must preserve decoded entry and its canonical hash")
			}
			if err := os.WriteFile(j.path(), broken, 0600); err != nil {
				t.Fatal(err)
			}
			requireReadFailure(t, j.dir, "malformed")
			if after, err := os.ReadFile(j.path()); err != nil || !bytes.Equal(after, broken) {
				t.Fatal("reader repaired invalid UTF-8", err)
			}
		})
	}
	if err := os.WriteFile(j.path(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := ReadExisting(j.dir); err != nil || len(got) != 1 {
		t.Fatalf("restored Unicode positive: %v", err)
	}
}

// Verification covers every retained record; tampering in any position refuses
// the entire read rather than returning trusted-looking partial entries.
func TestReadExistingChainBeforeSelection(t *testing.T) {
	j := newJournal(t, Capacity)
	for i := 1; i <= 3; i++ {
		if _, err := j.Append(alarm(i)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(j.path())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
	for i := range lines {
		edited := append([][]byte(nil), lines...)
		edited[i] = bytes.Replace(lines[i], []byte(`"kind":"alarm"`), []byte(`"kind":"warning"`), 1)
		if bytes.Equal(edited[i], lines[i]) {
			t.Fatal("tamper plant did not apply")
		}
		data := append(bytes.Join(edited, []byte("\n")), '\n')
		if err := os.WriteFile(j.path(), data, 0600); err != nil {
			t.Fatal(err)
		}
		requireReadFailure(t, j.dir, "chain_invalid")
	}
	if err := os.WriteFile(j.path(), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if entries, err := ReadExisting(j.dir); err != nil || len(entries) != 3 {
		t.Fatalf("restored valid control: %v", err)
	}
}

// Bounds refuse excess before returning entries, while the exact 11000-record
// reader tail is accepted through the actual parser and chain verifier.
func TestReadExistingBounds(t *testing.T) {
	j := newJournal(t, Capacity)
	var data bytes.Buffer
	previous := ""
	for i := 1; i <= 11001; i++ {
		e := alarm(i)
		e.Seq, e.PrevHash = uint64(i), previous
		e.Hash = e.digest()
		previous = e.Hash
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		data.Write(line)
		data.WriteByte('\n')
		if i == 11000 {
			if err := os.WriteFile(j.path(), data.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if entries, err := ReadExisting(j.dir); err != nil || len(entries) != 11000 {
				t.Fatalf("exact retained tail: %v", err)
			}
		}
	}
	if err := os.WriteFile(j.path(), data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	requireReadFailure(t, j.dir, "malformed")
	f, err := os.OpenFile(j.path(), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = f.Truncate((16 << 20) + 1)
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	requireReadFailure(t, j.dir, "malformed")
}

// All current writer kinds and optional fields remain admitted; a reader-only
// boundary must not reject an ordinary existing writer representation.
func TestReadExistingWriterForms(t *testing.T) {
	j := newJournal(t, Capacity)
	for i, kind := range []string{"warning", "alarm", "kill_intent", "kill_result", "block_intent", "block_result", "unblock", "undo", "reconcile_mismatch", "report_pending", "report_done"} {
		e := alarm(i)
		e.Kind = kind
		expires := e.TS.Add(time.Hour)
		e.Expiry, e.Undo, e.Ref = &expires, "fixture undo", 1
		if _, err := j.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := ReadExisting(j.dir)
	if err != nil || len(entries) != 11 {
		t.Fatalf("writer optional-field forms: %v", err)
	}
	for _, e := range entries {
		if e.Expiry == nil || e.Undo != "fixture undo" || e.Ref != 1 {
			t.Fatalf("lost optional fields: %+v", e)
		}
	}
}

type readInfoWithStat struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (s readInfoWithStat) Sys() any { return s.stat }

// The real descriptor-info guard rejects a different UID without changing
// ownership of a live file. The synthetic UID does not prove OS acquisition;
// the actual reader tests above cover descriptor acquisition with our UID.
func TestReadExistingOwnershipGuard(t *testing.T) {
	j := newJournal(t, Capacity)
	if _, err := j.Append(alarm(1)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path      string
		directory bool
	}{{j.dir, true}, {j.path(), false}} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if !safeReadInfo(info, tc.directory) {
			t.Fatal("valid owned descriptor info rejected")
		}
		st := *info.Sys().(*syscall.Stat_t)
		st.Uid++
		if safeReadInfo(readInfoWithStat{info, &st}, tc.directory) {
			t.Fatal("foreign UID admitted")
		}
	}
}
