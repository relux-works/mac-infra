package firewallwatch

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The standard subprocess-test pattern enters before the testing flag parser.
func init() {
	if os.Getenv("FW_WATCH_HELPER") != "1" {
		return
	}
	socket := ""
	model := ""
	for i, a := range os.Args {
		if i+1 < len(os.Args) {
			if a == "--host" {
				socket = os.Args[i+1]
			}
			if a == "-m" {
				model = os.Args[i+1]
			}
		}
	}
	data, e := os.ReadFile(model)
	if e != nil {
		os.Exit(12)
	}
	dir := filepath.Dir(socket)
	if os.WriteFile(filepath.Join(dir, "model.loaded"), data, 0600) != nil {
		os.Exit(13)
	}
	l, e := net.Listen("unix", socket)
	if e != nil {
		os.Exit(14)
	}
	if os.WriteFile(filepath.Join(dir, "child.pid"), []byte(strconv.Itoa(os.Getpid())), 0600) != nil {
		os.Exit(15)
	}
	_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			if _, e := os.Stat(filepath.Join(dir, "hold")); e == nil {
				w.WriteHeader(503)
			}
			return
		}
		embeddingHandler(w, r)
	}))
	os.Exit(0)
}
func fixtureBackend(t *testing.T) Config {
	t.Helper()
	c := testConfig(t)
	if e := safeDir(c.StateDir); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(c.Model, []byte("model"), 0600); e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256([]byte("model"))
	c.ModelSHA256 = hex.EncodeToString(h[:])
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c.LlamaServer = filepath.Join(filepath.Dir(c.Model), "server")
	// The fixture alone supplies a marker; production backendCommand inherits nothing.
	script := fmt.Sprintf("#!/bin/sh\nFW_WATCH_HELPER=1 exec '%s' \"$@\"\n", strings.ReplaceAll(binary, "'", "'\\''"))
	if e = os.WriteFile(c.LlamaServer, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	pool := `{"id":"one","app":"near","kind":"outbound","verdict":"allow","signer":"dev","remote":"internet","label":"noise"}` + "\n"
	if e = os.WriteFile(c.LabelledPool, []byte(pool), 0600); e != nil {
		t.Fatal(e)
	}
	return c
}
func waitPID(t *testing.T, dir string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(filepath.Join(dir, "child.pid"))
		if e == nil {
			pid, e := strconv.Atoi(string(b))
			if e != nil {
				t.Fatal(e)
			}
			return pid
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("fixture never acknowledged startup")
	return 0
}
func assertReaped(t *testing.T, pid int) {
	t.Helper()
	if e := syscall.Kill(pid, 0); !errors.Is(e, syscall.ESRCH) {
		t.Fatalf("child %d not reaped: %v", pid, e)
	}
}

// Acknowledged, live fixture cancellation returns context.Canceled and reaps its exact PID.
func TestBackendStartupCancellation(t *testing.T) {
	c := fixtureBackend(t)
	c.ClassifierTimeout = "10s"
	if e := os.WriteFile(filepath.Join(c.StateDir, "hold"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		b, e := StartBackend(ctx, c)
		if b != nil {
			b.Stop()
		}
		result <- e
	}()
	pid := waitPID(t, c.StateDir)
	if e := syscall.Kill(pid, 0); e != nil {
		t.Fatal("fixture already gone", e)
	}
	cancel()
	select {
	case e := <-result:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("wrong cancellation outcome: %v", e)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("cancel did not stop backend")
	}
	assertReaped(t, pid)
}

// Genuine child-owned UNIX service loads fd 3, reaches healthy, and is reaped after readiness; exit cannot be adopted away.
func TestBackendChildIdentityAndExit(t *testing.T) {
	c := fixtureBackend(t)
	c.ClassifierTimeout = "5s"
	b, e := StartBackend(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Stop()
	t.Cleanup(func() {
		select {
		case <-b.done:
		default:
			p, _ := os.FindProcess(b.pid)
			_ = p.Kill()
			<-b.done
		}
	})
	pid := waitPID(t, c.StateDir)
	if pid != b.pid {
		t.Fatal(pid, b.pid)
	}
	loaded, e := os.ReadFile(filepath.Join(c.StateDir, "model.loaded"))
	if e != nil || string(loaded) != "model" {
		t.Fatal("fd3 load", string(loaded), e)
	}
	cl, e := NewClassifier(c)
	if e != nil {
		t.Fatal(e)
	}
	cl.BindBackend(b)
	if e = cl.Init(context.Background()); e != nil {
		t.Fatal(e)
	}
	if !cl.CheckHealth(context.Background()) || cl.Classify(context.Background(), unmatched("near")).Label != "noise" {
		t.Fatal("healthy child rejected")
	}
	b.Stop()
	assertReaped(t, pid)
	if cl.Healthy() || cl.CheckHealth(context.Background()) || cl.Init(context.Background()) == nil {
		t.Fatal("dead child accepted")
	}
	// Even an answering replacement at the identical socket cannot revive this binding.
	if e = prepareSocket(c.SocketPath()); e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("unix", c.SocketPath())
	if e != nil {
		t.Fatal(e)
	}
	server := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(embeddingHandler)}}
	server.Start()
	defer server.Close()
	d := cl.Classify(context.Background(), unmatched("near"))
	if d.Label != "decide" || d.Reason != "classifier_unavailable" {
		t.Fatal(d)
	}
}

// An answering goroutine listener has this process's PID, not the expected child's; no HTTP item bytes are sent.
func TestBackendRejectsPeerMismatch(t *testing.T) {
	c := testConfig(t)
	if e := safeDir(c.StateDir); e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("unix", c.SocketPath())
	if e != nil {
		t.Fatal(e)
	}
	called := make(chan struct{}, 1)
	server := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called <- struct{}{}; embeddingHandler(w, r) })}}
	server.Start()
	defer server.Close()
	b := &Backend{pid: os.Getpid() + 100000, socket: c.SocketPath(), done: make(chan struct{})}
	client := backendClient(b, time.Second)
	r, e := client.Get(c.Backend() + "/health")
	if e == nil {
		r.Body.Close()
		t.Fatal("mismatched PID accepted")
	}
	if !strings.Contains(e.Error(), "peer PID mismatch") {
		t.Fatal(e)
	}
	select {
	case <-called:
		t.Fatal("HTTP leaked to wrong peer")
	default:
	}
	cl, _ := NewClassifier(c)
	cl.BindBackend(b)
	cl.pool = []Item{{ID: "n", Label: "noise"}}
	cl.vectors = [][]float64{{1, 0}}
	if d := cl.Classify(context.Background(), unmatched("near")); d.Reason != "classifier_unavailable" {
		t.Fatal(d)
	}
}

// Unsafe stale objects and live sockets stay untouched; only an owned refused socket is removed.
func TestBackendStaleSocket(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "live", "stale"} {
		t.Run(kind, func(t *testing.T) {
			c := testConfig(t)
			if e := safeDir(c.StateDir); e != nil {
				t.Fatal(e)
			}
			p := c.SocketPath()
			switch kind {
			case "file":
				_ = os.WriteFile(p, []byte("keep"), 0600)
			case "symlink":
				_ = os.Symlink(c.Model, p)
			default:
				l, e := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
				if e != nil {
					t.Fatal(e)
				}
				l.SetUnlinkOnClose(false)
				defer l.Close()
				if kind == "stale" {
					l.Close()
				}
			}
			e := prepareSocket(p)
			if kind == "stale" {
				if e != nil {
					t.Fatal(e)
				}
				if _, e = os.Lstat(p); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("not removed", e)
				}
			} else {
				if e == nil {
					t.Fatal("unsafe socket accepted")
				}
				if _, e = os.Lstat(p); e != nil {
					t.Fatal("object removed", e)
				}
			}
		})
	}
}

// Special files, symlinks, writable models and capped sizes fail promptly; valid regular model passes.
func TestModelFilePolicy(t *testing.T) {
	for _, kind := range []string{"fifo", "device", "symlink", "writable", "oversize", "valid"} {
		t.Run(kind, func(t *testing.T) {
			c := fixtureBackend(t)
			switch kind {
			case "fifo":
				_ = os.Remove(c.Model)
				if e := unix.Mkfifo(c.Model, 0600); e != nil {
					t.Fatal(e)
				}
			case "device":
				c.Model = "/dev/zero"
			case "symlink":
				target := c.Model + ".target"
				_ = os.Rename(c.Model, target)
				_ = os.Symlink(target, c.Model)
			case "writable":
				_ = os.Chmod(c.Model, 0620)
			case "oversize":
				c.MaxModelBytes = 4
			}
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			f, e := checkModel(ctx, c)
			if f != nil {
				f.Close()
			}
			if time.Since(start) > time.Second {
				t.Fatal("not prompt")
			}
			if (e == nil) != (kind == "valid") {
				t.Fatalf("%s: %v", kind, e)
			}
		})
	}
}

// Cancellation and the overall deadline interrupt a multi-chunk model hash, without starting a child.
func TestModelHashCancellation(t *testing.T) {
	c := testConfig(t)
	c.MaxModelBytes = 1 << 30
	f, e := os.Create(c.Model)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(512 << 20); e != nil {
		t.Fatal(e)
	}
	f.Close()
	for _, kind := range []string{"cancel", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var want error = context.Canceled
			if kind == "deadline" {
				ctx, cancel = context.WithTimeout(context.Background(), time.Millisecond)
				want = context.DeadlineExceeded
			} else {
				go func() { time.Sleep(time.Millisecond); cancel() }()
			}
			defer cancel()
			start := time.Now()
			f, e := checkModel(ctx, c)
			if f != nil {
				f.Close()
			}
			if !errors.Is(e, want) || time.Since(start) > time.Second {
				t.Fatal("hash did not respect context", e)
			}
		})
	}
}

// The checked descriptor, even after path replacement, is the file inherited by the fake child.
func TestModelSameDescriptor(t *testing.T) {
	c := fixtureBackend(t)
	f, e := checkModel(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = os.Rename(c.Model, c.Model+".old"); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(c.Model, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	cmd := backendCommand(context.Background(), c, f)
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = waitPID(t, c.StateDir)
	loaded, e := os.ReadFile(filepath.Join(c.StateDir, "model.loaded"))
	if e != nil || string(loaded) != "model" {
		t.Fatal("unchecked replacement loaded", string(loaded), e)
	}
}
