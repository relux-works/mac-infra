package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
}

func newRunner() *runner {
	return &runner{inflight: map[string]bool{}, start: func(cmd *exec.Cmd) error { return cmd.Start() }}
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
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	cmd.WaitDelay = 2 * time.Second // a lingering descendant holding our pipes cannot keep the slot

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
		done <- result{buf.Bytes(), err}
	}()
	select {
	case res := <-done:
		// ErrWaitDelay after a successful exit means only output collection timed out because a
		// descendant kept the pipes; the child itself succeeded.
		if res.err != nil && !(errors.Is(res.err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.Success()) {
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
