package journal

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	readMaxBytes   = 16 << 20
	readMaxLine    = 4096
	readMaxEntries = Capacity + Capacity/10
)

// ReadError distinguishes absence, acquisition refusals and invalid history.
// Reason is not_found, unreadable, unsafe_path, malformed or chain_invalid.
// The error deliberately carries no journal payload or private pathname.
type ReadError struct{ Reason string }

func (e *ReadError) Error() string { return "incident journal: " + e.Reason }

func readError(reason string) error { return &ReadError{Reason: reason} }

func readOpenError(err error) error {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return readError("not_found")
	case errors.Is(err, syscall.ELOOP), errors.Is(err, syscall.ENOTDIR):
		return readError("unsafe_path")
	default:
		return readError("unreadable")
	}
}

func safeReadInfo(info os.FileInfo, directory bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return false
	}
	mode := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if directory {
		return info.IsDir() && mode == 0700
	}
	return info.Mode().IsRegular() && mode == 0600 && st.Nlink == 1
}

// ReadExisting reads and verifies the complete bounded retained journal without
// creating directories, locks, files or history. It accepts an absolute config
// path; lexical aliases are cleaned once, as in the writer's filepath.Join.
// The opened directory pins file acquisition across pathname replacement.
// A successful result is a bounded snapshot, not an external trust anchor or
// proof that no concurrent writer can ever change the journal afterwards.
func ReadExisting(dir string) ([]Entry, error) {
	if !filepath.IsAbs(dir) {
		return nil, readError("unsafe_path")
	}
	fd, err := unix.Open(filepath.Clean(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, readOpenError(err)
	}
	directory := os.NewFile(uintptr(fd), "incident-directory")
	defer directory.Close()
	dirInfo, err := directory.Stat()
	if err != nil {
		return nil, readError("unreadable")
	}
	if !safeReadInfo(dirInfo, true) {
		return nil, readError("unsafe_path")
	}
	fileFD, err := unix.Openat(fd, fileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, readOpenError(err)
	}
	f := os.NewFile(uintptr(fileFD), "incident-journal")
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, readError("unreadable")
	}
	if !safeReadInfo(before, false) {
		return nil, readError("unsafe_path")
	}
	if before.Size() > readMaxBytes {
		return nil, readError("malformed")
	}
	data, err := io.ReadAll(io.LimitReader(f, readMaxBytes+1))
	if err != nil {
		return nil, readError("unreadable")
	}
	after, err := f.Stat()
	if err != nil {
		return nil, readError("unreadable")
	}
	if !safeReadInfo(after, false) {
		return nil, readError("unsafe_path")
	}
	afterDir, err := directory.Stat()
	if err != nil {
		return nil, readError("unreadable")
	}
	if !safeReadInfo(afterDir, true) {
		return nil, readError("unsafe_path")
	}
	if len(data) > readMaxBytes || int64(len(data)) != before.Size() || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, readError("malformed")
	}
	entries := make([]Entry, 0)
	reader := bufio.NewReaderSize(bytes.NewReader(data), readMaxLine+2)
	for {
		line, err := reader.ReadSlice('\n')
		if err == io.EOF && len(line) == 0 {
			break
		}
		if err != nil || len(line) < 2 || len(line)-1 > readMaxLine || len(entries) >= readMaxEntries {
			return nil, readError("malformed")
		}
		e, err := decodeReadEntry(line[:len(line)-1])
		if err != nil {
			return nil, readError("malformed")
		}
		entries = append(entries, e)
	}
	if Verify(entries) != nil {
		return nil, readError("chain_invalid")
	}
	return entries, nil
}

// Entry is a flat object. Decode names before admission so escape-spelled
// duplicates are refused, and reject any member not emitted by the writer.
func decodeReadEntry(line []byte) (Entry, error) {
	bad := func() (Entry, error) { return Entry{}, readError("malformed") }
	// encoding/json replaces invalid UTF-8. Reject original malformed bytes
	// before decoding so replacement cannot conceal a changed journal record.
	if !utf8.Valid(line) {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(line))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return bad()
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return bad()
		}
		seen[key] = true
		var raw json.RawMessage
		if d.Decode(&raw) != nil || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return bad()
		}
		switch key {
		case "seq", "ref":
			var n uint64
			if json.Unmarshal(raw, &n) != nil {
				return bad()
			}
		case "ts", "kind", "source", "actor", "target", "action", "expiry", "undo", "prev_hash", "hash":
			var text string
			if json.Unmarshal(raw, &text) != nil {
				return bad()
			}
		default:
			return bad()
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return bad()
	}
	if _, err := d.Token(); err != io.EOF {
		return bad()
	}
	for _, key := range []string{"seq", "ts", "kind", "source", "actor", "target", "action", "prev_hash", "hash"} {
		if !seen[key] {
			return bad()
		}
	}
	var e Entry
	if json.Unmarshal(line, &e) != nil || e.Seq == 0 || validate(e) != nil {
		return bad()
	}
	return e, nil
}
