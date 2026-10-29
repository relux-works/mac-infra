package toolsecret

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

type AuditRecord struct {
	Time         time.Time `json:"time"`
	Actor        string    `json:"actor"`
	Outcome      string    `json:"outcome"`
	Sequence     uint64    `json:"sequence"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash"`
	Plan
}
type AuditHead struct {
	Count uint64 `json:"count"`
	Hash  string `json:"hash"`
}

func DefaultAuditPath() (string, error) {
	h, e := os.UserHomeDir()
	return filepath.Join(h, "Library/Application Support/mac-infra/tool-secret/audit.jsonl"), e
}

// The tool only appends to the log. Neither append nor verify repairs, truncates
// or migrates an invalid chain. The separate checkpoint also detects a rehashed
// replacement or truncation; --expected-head can anchor it outside this directory.
func openOwnedFile(path string, flags int) (*os.File, error) {
	fd, e := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	st, e := f.Stat()
	if e != nil {
		f.Close()
		return nil, e
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) || st.Sys().(*syscall.Stat_t).Nlink != 1 {
		f.Close()
		return nil, fmt.Errorf("audit state must be a singly linked owner-owned regular 0600 file")
	}
	return f, nil
}
func OpenAudit(path string) (*os.File, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return nil, e
	}
	f, e := openOwnedFile(path, syscall.O_RDWR|syscall.O_APPEND|syscall.O_CREAT)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fmt.Errorf("audit is busy: %w", e)
	}
	if _, e = verifyAuditFile(f, ""); e != nil {
		f.Close()
		return nil, e
	}
	return f, nil
}
func recordHash(r AuditRecord) (string, error) {
	r.Hash = ""
	b, e := json.Marshal(r)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
func scanAudit(f *os.File) (AuditHead, error) {
	head := AuditHead{Hash: genesisHash}
	if _, e := f.Seek(0, io.SeekStart); e != nil {
		return head, e
	}
	scanner := bufio.NewScanner(f)
	// ScanLines silently removes CR, which would hide a CRLF rewrite.
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	scanner.Buffer(make([]byte, 65536), 8<<20)
	for scanner.Scan() {
		line := scanner.Bytes()
		var r AuditRecord
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&r); e != nil {
			return head, fmt.Errorf("audit record cannot be verified: %w", e)
		}
		canonical, e := json.Marshal(r)
		if e != nil || !bytes.Equal(canonical, line) {
			return head, fmt.Errorf("audit record was rewritten or is non-canonical")
		}
		h, e := recordHash(r)
		if e != nil {
			return head, e
		}
		if r.Sequence != head.Count+1 || r.PreviousHash != head.Hash || r.Hash != h {
			return head, fmt.Errorf("audit hash chain mismatch at record %d", head.Count+1)
		}
		head = AuditHead{Count: r.Sequence, Hash: r.Hash}
	}
	if e := scanner.Err(); e != nil {
		return head, e
	}
	// Every appended record ends with a newline: detect partial last writes.
	st, e := f.Stat()
	if e != nil {
		return head, e
	}
	if st.Size() > 0 {
		var b [1]byte
		if _, e = f.ReadAt(b[:], st.Size()-1); e != nil {
			return head, e
		}
		if b[0] != '\n' {
			return head, fmt.Errorf("audit has a partial final record")
		}
	}
	return head, nil
}
func verifyAuditFile(f *os.File, expected string) (AuditHead, error) {
	head, e := scanAudit(f)
	if e != nil {
		return head, e
	}
	checkpoint, e := openOwnedFile(f.Name()+".head", syscall.O_RDONLY)
	if os.IsNotExist(e) && head.Count == 0 {
		if expected != "" && expected != head.Hash {
			return head, fmt.Errorf("audit expected head mismatch")
		}
		return head, nil
	}
	if e != nil {
		return head, fmt.Errorf("audit checkpoint unavailable: %w", e)
	}
	defer checkpoint.Close()
	data, e := io.ReadAll(io.LimitReader(checkpoint, 4096))
	if e != nil {
		return head, e
	}
	var saved AuditHead
	if e = json.Unmarshal(data, &saved); e != nil || saved != head {
		return head, fmt.Errorf("audit checkpoint mismatch: rewritten, truncated, or interrupted append")
	}
	if expected != "" && expected != head.Hash {
		return head, fmt.Errorf("audit expected head mismatch")
	}
	return head, nil
}
func VerifyAudit(path, expected string) (AuditHead, error) {
	if expected != "" {
		if len(expected) != 64 {
			return AuditHead{}, fmt.Errorf("expected head must be a SHA-256 hex string")
		}
		if _, e := hex.DecodeString(expected); e != nil {
			return AuditHead{}, e
		}
		expected = strings.ToLower(expected)
	}
	f, e := openOwnedFile(path, syscall.O_RDONLY)
	if e != nil {
		return AuditHead{}, e
	}
	defer f.Close()
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); e != nil {
		return AuditHead{}, fmt.Errorf("audit is busy: %w", e)
	}
	return verifyAuditFile(f, expected)
}
func writeCheckpoint(path string, head AuditHead) error {
	// Refuse unsafe existing checkpoint state before an atomic owner-only replace.
	if f, e := openOwnedFile(path, syscall.O_RDONLY); e == nil {
		f.Close()
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".audit-head-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if e = json.NewEncoder(f).Encode(head); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func AppendAudit(f *os.File, record AuditRecord) error {
	head, e := verifyAuditFile(f, "")
	if e != nil {
		return e
	}
	record.Sequence = head.Count + 1
	record.PreviousHash = head.Hash
	record.Hash, e = recordHash(record)
	if e != nil {
		return e
	}
	b, e := json.Marshal(record)
	if e != nil {
		return e
	}
	b = append(b, '\n')
	n, e := f.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	if e = f.Sync(); e != nil {
		return e
	}
	return writeCheckpoint(f.Name()+".head", AuditHead{Count: record.Sequence, Hash: record.Hash})
}
