package firewallwatch

import (
	"sync"
	"time"
)

// flagWriteGap is the pause after each flag write before the next one. The
// flag's full sync otherwise competes with the journal's appends for the
// drive during a flood of new items; a stop does not wait for it.
const flagWriteGap = 100 * time.Millisecond

// flagWriter owns new-events.flag while the watcher runs. The run loop posts
// the latest event stamp and continues; one writer goroutine writes the newest
// stamp posted. The flag's own full sync therefore never runs on the run
// loop, and the flag lags the journal by at most the write in progress,
// flagWriteGap and one more write, whatever the loop is doing (a slow
// classification, a snapshot).
// Each emitted event still has its own durable journal append; the flag only
// tells that something new exists. A write error is kept: every later post
// and stop return it, so it ends the run as a synchronous flag error did.
type flagWriter struct {
	write   func(stamp []byte) error
	mu      sync.Mutex
	pending []byte
	err     error
	wake    chan struct{}
	quit    chan struct{}
	done    chan struct{}
	// failed is closed on the first write error, so the run loop ends the
	// run even when no further stamp is posted.
	failed chan struct{}
}

func startFlagWriter(write func(stamp []byte) error) *flagWriter {
	w := &flagWriter{write: write, wake: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{}), failed: make(chan struct{})}
	go w.run()
	return w
}

// post hands the writer a stamp to write, replacing any stamp not written
// yet, and returns at once.
func (w *flagWriter) post(stamp []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return w.err
	}
	w.pending = stamp
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return nil
}

func (w *flagWriter) run() {
	defer close(w.done)
	for {
		select {
		case <-w.wake:
			if !w.flush() {
				<-w.quit
				return
			}
			select {
			case <-time.After(flagWriteGap):
			case <-w.quit:
				w.flush()
				return
			}
		case <-w.quit:
			w.flush()
			return
		}
	}
}

// flush writes the pending stamp, if any, and reports false after a write
// error, now or earlier.
func (w *flagWriter) flush() bool {
	w.mu.Lock()
	stamp, failed := w.pending, w.err != nil
	w.pending = nil
	w.mu.Unlock()
	if failed {
		return false
	}
	if stamp == nil {
		return true
	}
	if e := w.write(stamp); e != nil {
		w.mu.Lock()
		w.err = e
		w.mu.Unlock()
		close(w.failed)
		return false
	}
	return true
}

// stop writes the last stamp posted, ends the writer and returns its first
// write error.
func (w *flagWriter) stop() error {
	close(w.quit)
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

// failure is closed once a write has failed; error then returns the error.
func (w *flagWriter) failure() <-chan struct{} { return w.failed }

func (w *flagWriter) error() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}
