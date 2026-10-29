package firewallwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Backend struct {
	pid      int
	socket   string
	done     <-chan struct{}
	stop     func()
	stopping atomic.Bool
}

func (b *Backend) alive() bool {
	if b == nil || b.stopping.Load() || b.pid <= 0 || b.done == nil {
		return false
	}
	select {
	case <-b.done:
		return false
	default:
		return true
	}
}
func (b *Backend) Stop() {
	if b != nil {
		b.stopping.Store(true)
		if b.stop != nil {
			b.stop()
		}
	}
}

func backendClient(b *Backend, timeout time.Duration) *http.Client {
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if !b.alive() {
			return nil, errors.New("classifier_unavailable: backend exited or unbound")
		}
		conn, e := (&net.Dialer{}).DialContext(ctx, "unix", b.socket)
		if e != nil {
			return nil, e
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			return nil, errors.New("classifier_unavailable: non-unix connection")
		}
		raw, e := uc.SyscallConn()
		if e != nil {
			conn.Close()
			return nil, e
		}
		pid := 0
		var peerErr error
		e = raw.Control(func(fd uintptr) { pid, peerErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID) })
		if e != nil || peerErr != nil || pid != b.pid || !b.alive() {
			conn.Close()
			return nil, fmt.Errorf("classifier_unavailable: peer PID mismatch or exited (expected %d, got %d)", b.pid, pid)
		}
		return conn, nil
	}}
	return &http.Client{Timeout: timeout, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
}

type childLog struct {
	mu   sync.Mutex
	data []byte
}

func (b *childLog) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := min(len(p), 64*1024-len(b.data))
	b.data = append(b.data, p[:n]...)
	return len(p), nil
}
func (b *childLog) String() string { b.mu.Lock(); defer b.mu.Unlock(); return string(b.data) }

// checkModel starts under the caller's startup deadline, never opens a FIFO in
// blocking mode, and returns the descriptor that the child will inherit as fd 3.
func checkModel(ctx context.Context, c Config) (*os.File, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	fd, e := unix.Open(c.Model, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, fmt.Errorf("model open: %w", e)
	}
	f := os.NewFile(uintptr(fd), c.Model)
	fail := func(e error) (*os.File, error) { f.Close(); return nil, e }
	info, e := f.Stat()
	if e != nil {
		return fail(e)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Size() > c.MaxModelBytes || c.MaxModelBytes < 1 || info.Mode().Perm()&0022 != 0 || (int(st.Uid) != os.Getuid() && st.Uid != 0) {
		return fail(errors.New("model must be a regular caller/root-owned file within max_model_bytes, without group/world writes"))
	}
	h := sha256.New()
	buf := make([]byte, 256*1024)
	var total int64
	for {
		if e = ctx.Err(); e != nil {
			return fail(e)
		}
		n, readErr := f.Read(buf)
		total += int64(n)
		if total > c.MaxModelBytes {
			return fail(errors.New("model exceeds max_model_bytes"))
		}
		if n > 0 {
			_, _ = h.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fail(readErr)
		}
	}
	if e = ctx.Err(); e != nil {
		return fail(e)
	}
	after, e := f.Stat()
	if e != nil {
		return fail(e)
	}
	// The descriptor pins pathname replacement. An in-place mutation during hashing
	// is refused; trusted owners must not mutate its contents after this check.
	if info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) || st.Ctimespec != after.Sys().(*syscall.Stat_t).Ctimespec {
		return fail(errors.New("model changed during verification"))
	}
	if !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), c.ModelSHA256) {
		return fail(errors.New("model sha256 mismatch"))
	}
	if _, e = f.Seek(0, io.SeekStart); e != nil {
		return fail(e)
	}
	return f, nil
}
func backendCommand(ctx context.Context, c Config, f *os.File) *exec.Cmd {
	cmd := exec.CommandContext(ctx, c.LlamaServer, "--offline", "--host", c.SocketPath(), "--embedding", "--pooling", "last", "-m", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{f}
	cmd.Env = []string{}
	return cmd
}
func prepareSocket(path string) error {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	if e != nil {
		return e
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || int(st.Uid) != os.Getuid() {
		return errors.New("refusing unsafe stale backend socket")
	}
	conn, e := net.DialTimeout("unix", path, 100*time.Millisecond)
	if e == nil {
		conn.Close()
		return errors.New("backend socket has a live listener")
	}
	// Only ECONNREFUSED proves an owned socket has no listener. Permission and
	// timeout errors do not authorize unlinking it.
	if !errors.Is(e, syscall.ECONNREFUSED) {
		return fmt.Errorf("cannot establish stale socket: %w", e)
	}
	return os.Remove(path)
}

// StartBackend owns the verified model descriptor and reaps exactly its child.
// There is no TCP listener, endpoint adoption, inherited environment or restart.
func StartBackend(ctx context.Context, c Config) (*Backend, error) {
	startup, cancelStartup := context.WithTimeout(ctx, duration(c.ClassifierTimeout))
	defer cancelStartup()
	f, e := checkModel(startup, c)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if e = safeDir(c.StateDir); e != nil {
		return nil, e
	}
	if e = prepareSocket(c.SocketPath()); e != nil {
		return nil, e
	}
	if e = startup.Err(); e != nil {
		return nil, e
	}
	childCtx, cancel := context.WithCancel(ctx)
	cmd := backendCommand(childCtx, c, f)
	logs := &childLog{}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if e = cmd.Start(); e != nil {
		cancel()
		return nil, e
	}
	done := make(chan struct{})
	var childErr error
	go func() { childErr = cmd.Wait(); close(done) }()
	b := &Backend{pid: cmd.Process.Pid, socket: c.SocketPath(), done: done}
	var once sync.Once
	b.stop = func() {
		once.Do(func() {
			select {
			case <-done:
			default:
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				cancel()
				<-done
			}
			cancel()
		})
	}
	client := backendClient(b, min(time.Second, duration(c.ClassifierTimeout)))
	defer client.CloseIdleConnections()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-startup.Done():
			b.Stop()
			return nil, startup.Err()
		case <-done:
			cancel()
			if e := startup.Err(); e != nil {
				return nil, e
			}
			return nil, fmt.Errorf("backend exited during startup: %v: %s", childErr, Sanitize(logs.String()))
		case <-tick.C:
			req, _ := http.NewRequestWithContext(startup, "GET", c.Backend()+"/health", nil)
			resp, e := client.Do(req)
			if e == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 && b.alive() && startup.Err() == nil {
					return b, nil
				}
			}
		}
	}
}
