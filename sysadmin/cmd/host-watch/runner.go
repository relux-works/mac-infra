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
	// Output goes through a pipe this runner owns, not one os/exec copies: Wait returns at the
	// child's exit even when a descendant keeps the write end, and a bounded reader keeps at most
	// maxChildOutput bytes in memory and discards the rest, so nothing grows on disk.
	pr, pw, err := os.Pipe()
	if err != nil {
		r.mu.Lock()
		delete(r.inflight, key)
		r.mu.Unlock()
		return "", err
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	col := newCollector(pr)

	exited := make(chan struct{}) // closed once the child's exit has been observed
	var pmu sync.Mutex
	var proc *os.Process
	abandoned := false
	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.inflight, key)
			r.mu.Unlock()
		}()
		err := r.start(cmd)
		pw.Close() // the parent keeps no write end; EOF comes when every writer is gone
		if err != nil {
			pr.Close()
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
		werr := cmd.Wait()
		close(exited)
		collected, complete := col.finish(drainAfterExit)
		pr.Close()
		if werr == nil && !complete {
			werr = errOutputIncomplete
		}
		done <- result{collected, werr}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return string(res.out), fmt.Errorf("%s: %w", filepath.Base(bin), res.err)
		}
		return string(res.out), nil
	case <-ctx.Done():
		select {
		case <-exited:
			// The exit is already observed: the deadline cannot turn it into a failure. Only the
			// bounded output drain remains.
			res := <-done
			if res.err != nil {
				return string(res.out), fmt.Errorf("%s: %w", filepath.Base(bin), res.err)
			}
			return string(res.out), nil
		default:
		}
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

// maxChildOutput bounds what is kept of a child's output; more is an incomplete observation,
// never a sample. drainAfterExit bounds how long output already written is read after the exit.
const (
	maxChildOutput = 1 << 20
	drainAfterExit = 500 * time.Millisecond
)

var errOutputIncomplete = errors.New("child output exceeded the bound or was not fully read; observation incomplete")

// collector reads a pipe into a bounded buffer and discards everything beyond the bound.
type collector struct {
	mu       sync.Mutex
	buf      []byte
	overflow bool
	readErr  error // the error that ended reading; complete only when it is io.EOF
	eof      chan struct{}
}

func newCollector(r io.Reader) *collector {
	c := &collector{eof: make(chan struct{})}
	go func() {
		defer close(c.eof)
		chunk := make([]byte, 32*1024)
		for {
			n, err := r.Read(chunk)
			if n > 0 {
				c.mu.Lock()
				if room := maxChildOutput - len(c.buf); room > 0 {
					take := n
					if take > room {
						take = room
						c.overflow = true
					}
					c.buf = append(c.buf, chunk[:take]...)
				} else {
					c.overflow = true
				}
				c.mu.Unlock()
			}
			if err != nil {
				c.mu.Lock()
				c.readErr = err
				c.mu.Unlock()
				return
			}
		}
	}()
	return c
}

// finish waits up to d for EOF and reports the output and whether it is complete: no overflow and
// EOF reached (a descendant still holding the pipe leaves it incomplete).
func (c *collector) finish(d time.Duration) ([]byte, bool) {
	eof := false
	select {
	case <-c.eof:
		eof = true
	case <-time.After(d):
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf...), eof && !c.overflow && errors.Is(c.readErr, io.EOF)
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
