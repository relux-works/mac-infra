package maccore

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// The daemon consumes only framed bytes. All untrusted filesystem I/O belongs
// to a killable process running with the authorized client's credentials.
type vpnCoreSourceReader interface {
	Read(context.Context, string, int, int, func(io.Reader) error) error
}

type vpnCoreExecSource struct {
	executable func() (string, error)
	start      func(*exec.Cmd) error
}

func newVPNCoreExecSource() *vpnCoreExecSource {
	return &vpnCoreExecSource{executable: trustedVPNCoreExecutable, start: (*exec.Cmd).Start}
}

func trustedVPNCoreExecutable() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	file, err := openTrustedPath(path, false)
	if err != nil {
		return "", err
	}
	return path, file.Close()
}

// Drop supplementary groups rather than resolving membership as root. Packages
// must be owned by the client; primary-group access suffices for this contract.
func vpnCoreSourceCommand(executable, pkg string, uid, gid int) *exec.Cmd {
	cmd := exec.Command(executable, "_vpn-core-source", pkg)
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
		Uid: uint32(uid), Gid: uint32(gid), Groups: []uint32{},
	}}
	cmd.WaitDelay = time.Second
	return cmd
}

// stderr is drained, but at most 1 KiB is retained and overflow invalidates it.
type vpnCoreWorkerStderr struct {
	data     []byte
	overflow bool
}

func (w *vpnCoreWorkerStderr) Write(p []byte) (int, error) {
	n := min(len(p), 1024-len(w.data))
	w.data = append(w.data, p[:n]...)
	w.overflow = w.overflow || n < len(p)
	return len(p), nil
}

func (s *vpnCoreExecSource) Read(ctx context.Context, pkg string, uid, gid int, consume func(io.Reader) error) error {
	if uid <= 0 || gid <= 0 {
		return vpnRefuse("invalid_client", "non-root worker credentials required")
	}
	executable, err := s.executable()
	if err != nil {
		return vpnRefuse("source_failed", "trusted worker executable unavailable")
	}
	cmd := vpnCoreSourceCommand(executable, pkg, uid, gid)
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return vpnRefuse("source_failed", "worker stdin unavailable")
	}
	defer stdin.Close()
	cmd.Stdin = stdin
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return vpnRefuse("source_failed", "worker pipe unavailable")
	}
	defer stdout.Close()
	stderr := &vpnCoreWorkerStderr{}
	cmd.Stderr = stderr
	if err := ctx.Err(); err != nil {
		return vpnRefuse("source_timeout", "source deadline exceeded")
	}
	if err := s.start(cmd); err != nil {
		return vpnRefuse("source_failed", "source worker could not start")
	}
	// Always reap the exact process we started. Closing the pipe also releases
	// a reader if cancellation races with exit or an incomplete frame.
	finished, watcherDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_ = stdout.Close()
		case <-finished:
		}
	}()
	streamErr := consume(stdout)
	if streamErr != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	close(finished)
	<-watcherDone
	if ctx.Err() != nil {
		return vpnRefuse("source_timeout", "source deadline exceeded")
	}
	if waitErr != nil {
		if code := vpnCoreWorkerCode(stderr); code != "" {
			return vpnRefuse(code, "source worker refused package")
		}
		// A consumer deliberately kills a malformed producer. An unrelated
		// exit or unknown diagnostic is always source_failed.
		if state, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && state.Signaled() && state.Signal() == syscall.SIGKILL && len(stderr.data) == 0 && streamErr != nil {
			return streamErr
		}
		return vpnRefuse("source_failed", "source worker failed")
	}
	if streamErr != nil {
		return streamErr
	}
	if len(stderr.data) != 0 || stderr.overflow {
		return vpnRefuse("source_failed", "unexpected worker diagnostics")
	}
	return nil
}

func vpnCoreWorkerCode(stderr *vpnCoreWorkerStderr) string {
	if stderr.overflow {
		return ""
	}
	var refusal struct {
		Code string `json:"code"`
	}
	// The trusted worker emits exactly one bounded JSON line, with no paths.
	if len(stderr.data) == 0 || stderr.data[len(stderr.data)-1] != '\n' || bytes.Count(stderr.data, []byte{'\n'}) != 1 {
		return ""
	}
	if json.Unmarshal(stderr.data, &refusal) != nil {
		return ""
	}
	switch refusal.Code {
	case "invalid_package_path", "symlink", "non_regular", "source_owner", "package_entries", "file_too_large", "source_unreadable", "io_error":
		return refusal.Code
	}
	return ""
}

// RunVPNCoreSource is a hidden, unprivileged entry point, never an installer.
func RunVPNCoreSource(args []string, stdout, stderr io.Writer) int {
	err := vpnRefuse("invalid_package_path", "one package path required")
	if len(args) == 1 && os.Geteuid() > 0 && os.Getegid() > 0 {
		err = streamVPNCoreSource(args[0], uint32(os.Geteuid()), stdout)
	}
	if err == nil {
		return 0
	}
	code := vpnCode(err)
	if errors.Is(err, os.ErrPermission) {
		code = "source_unreadable"
	}
	_ = json.NewEncoder(stderr).Encode(struct {
		Code string `json:"code"`
	}{code})
	return 1
}

func streamVPNCoreSource(pkg string, uid uint32, stdout io.Writer) error {
	files, err := openVPNCorePackage(pkg, uid)
	if err != nil {
		return err
	}
	defer closeVPNCoreFiles(files)
	for i, file := range files {
		data, err := readVPNCoreBounded(file, vpnCoreFiles[i].cap)
		if err != nil {
			return err
		}
		if err := binary.Write(stdout, binary.BigEndian, uint64(len(data))); err != nil {
			return err
		}
		if _, err := stdout.Write(data); err != nil {
			return err
		}
	}
	return nil
}

// Fixed-order uint64 big-endian lengths, capped before creating each file.
// Hash verification remains a separate pass over the private staged copy.
func (s *vpnCoreService) receiveSource(reader io.Reader, tree string) error {
	for _, entry := range vpnCoreFiles {
		var size uint64
		if err := binary.Read(reader, binary.BigEndian, &size); err != nil {
			return vpnRefuse("source_stream", "truncated source frame")
		}
		if size > uint64(entry.cap) {
			return vpnRefuse("source_stream", "oversized source frame")
		}
		path := filepath.Join(tree, entry.path)
		out, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(out, reader, int64(size))
		syncErr, closeErr := out.Sync(), out.Close()
		if copyErr != nil {
			return vpnRefuse("source_stream", "truncated source payload")
		}
		if err := errors.Join(syncErr, closeErr); err != nil {
			return err
		}
		if err := s.ops.secure(path, false, entry.mode); err != nil {
			return err
		}
	}
	var extra [1]byte
	if n, err := io.ReadFull(reader, extra[:]); n != 0 || err != io.EOF {
		return vpnRefuse("source_stream", "trailing source data")
	}
	return nil
}
