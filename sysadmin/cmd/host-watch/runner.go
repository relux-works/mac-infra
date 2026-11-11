package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// errChildHeld means an earlier child of the same kind has not finished yet; no second one starts.
var errChildHeld = errors.New("previous child still held")

// runner starts children with a hard deadline that also covers the launch stage, and never starts a
// second child of the same kind while an earlier one (possibly held at exec) is still alive.
// Children it starts and times out are its own to kill; it never signals any other process.
type runner struct {
	mu       sync.Mutex
	inflight map[string]bool
	start    func(cmd *exec.Cmd) error // replaced in tests to simulate a launch held before execve
	unlink   func(name string) error   // replaced in tests to simulate an unlink failure
}

func newRunner() *runner {
	return &runner{inflight: map[string]bool{}, start: func(cmd *exec.Cmd) error { return cmd.Start() }, unlink: os.Remove}
}

// run executes bin with args under key. It returns at the deadline even while the child is still
// being launched; a timed-out child is killed as soon as it exists, and its slot stays taken until
// it is gone.
func (r *runner) run(ctx context.Context, key, bin string, args ...string) (string, error) {
	r.mu.Lock()
	if r.inflight[key] {
		r.mu.Unlock()
		return "", fmt.Errorf("%s: %w", key, errChildHeld)
	}
	r.inflight[key] = true
	r.mu.Unlock()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	cmd := exec.Command(bin, args...)
	// Output goes to an unlinked temporary file, not a pipe: the child's exit is observed as soon as
	// it exits, even when a descendant keeps the output open, so a delivered post is never mistaken
	// for a failure because output collection was still waiting.
	out, err := os.CreateTemp("", "host-watch-out-*")
	if err != nil {
		r.mu.Lock()
		delete(r.inflight, key)
		r.mu.Unlock()
		return "", err
	}
	if err := r.unlink(out.Name()); err != nil {
		// Never start a child whose output could stay behind under a pathname.
		out.Close()
		r.mu.Lock()
		delete(r.inflight, key)
		r.mu.Unlock()
		return "", fmt.Errorf("output spool unlink: %w", err)
	}
	cmd.Stdout, cmd.Stderr = out, out

	var pmu sync.Mutex
	var proc *os.Process
	abandoned := false
	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.inflight, key)
			r.mu.Unlock()
		}()
		if err := r.start(cmd); err != nil {
			out.Close()
			done <- result{nil, err}
			return
		}
		pmu.Lock()
		proc = cmd.Process
		kill := abandoned
		pmu.Unlock()
		if kill {
			_ = proc.Kill()
		}
		err := cmd.Wait()
		collected, rerr := readSpool(out)
		out.Close()
		if err == nil && rerr != nil {
			err = rerr
		}
		done <- result{collected, err}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return string(res.out), fmt.Errorf("%s: %w", filepath.Base(bin), res.err)
		}
		return string(res.out), nil
	case <-ctx.Done():
		pmu.Lock()
		abandoned = true
		p := proc
		pmu.Unlock()
		if p != nil {
			_ = p.Kill() // our own child only
		}
		return "", fmt.Errorf("%s: %w", filepath.Base(bin), ctx.Err())
	}
}

// maxChildOutput bounds what a child may write; more is an incomplete observation, never a sample.
const maxChildOutput = 1 << 20

var errOutputIncomplete = errors.New("child output exceeded the bound; observation incomplete")

// readSpool reads the spool at an independent offset (pread), so descriptors that descendants
// share are not moved, and refuses output beyond the bound instead of truncating it.
func readSpool(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxChildOutput {
		return nil, errOutputIncomplete
	}
	buf := make([]byte, fi.Size())
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// busy reports whether a child of this kind is still alive.
func (r *runner) busy(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inflight[key]
}

// boundedWait waits for wg at most d and reports whether everything finished.
func boundedWait(wg *sync.WaitGroup, d time.Duration) bool {
	ch := make(chan struct{})
	go func() { wg.Wait(); close(ch) }()
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
}
