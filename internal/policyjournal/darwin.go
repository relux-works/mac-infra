//go:build darwin

package policyjournal

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Watcher struct {
	queue int
	paths map[string]int
	byFD  map[int]string
	ids   map[string][2]uint64
}

func NewWatcher() (*Watcher, error) {
	q, e := unix.Kqueue()
	if e != nil {
		return nil, e
	}
	unix.CloseOnExec(q)
	return &Watcher{queue: q, paths: map[string]int{}, byFD: map[int]string{}, ids: map[string][2]uint64{}}, nil
}

func (w *Watcher) Close() {
	for _, fd := range w.paths {
		_ = unix.Close(fd)
	}
	_ = unix.Close(w.queue)
}

func (w *Watcher) Sync(paths []string) (gap bool) {
	keep := map[string]bool{}
	for _, p := range paths {
		keep[p] = true
		var st unix.Stat_t
		if e := unix.Lstat(p, &st); e != nil {
			if !errors.Is(e, fs.ErrNotExist) {
				gap = true
			}
			continue
		}
		id := [2]uint64{uint64(st.Dev), st.Ino}
		if fd, ok := w.paths[p]; ok {
			if w.ids[p] == id {
				continue
			}
			_ = unix.Close(fd)
			delete(w.byFD, fd)
			delete(w.paths, p)
			delete(w.ids, p)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG && st.Mode&unix.S_IFMT != unix.S_IFDIR {
			gap = true
			continue
		}
		// O_EVTONLY requests vnode notifications; it is not OS read isolation.
		// This implementation never invokes a data read on the descriptor.
		// NOFOLLOW refuses a symlink at the exact policy filename.
		fd, e := unix.Open(p, unix.O_EVTONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			gap = true
			continue
		}
		var actual unix.Stat_t
		if unix.Fstat(fd, &actual) != nil || actual.Dev != st.Dev || actual.Ino != st.Ino {
			_ = unix.Close(fd)
			gap = true
			continue
		}
		ev := unix.Kevent_t{Ident: uint64(fd), Filter: unix.EVFILT_VNODE, Flags: unix.EV_ADD | unix.EV_CLEAR, Fflags: unix.NOTE_WRITE | unix.NOTE_EXTEND | unix.NOTE_ATTRIB | unix.NOTE_RENAME | unix.NOTE_DELETE | unix.NOTE_REVOKE}
		if _, e = unix.Kevent(w.queue, []unix.Kevent_t{ev}, nil, nil); e != nil {
			_ = unix.Close(fd)
			gap = true
			continue
		}
		w.paths[p] = fd
		w.byFD[fd] = p
		w.ids[p] = id
	}
	for p, fd := range w.paths {
		if !keep[p] {
			_ = unix.Close(fd)
			delete(w.byFD, fd)
			delete(w.paths, p)
			delete(w.ids, p)
		}
	}
	return
}

func (w *Watcher) Wait() (map[string]bool, error) {
	events := make([]unix.Kevent_t, 128)
	timeout := unix.NsecToTimespec(int64(time.Second))
	n, e := unix.Kevent(w.queue, nil, events, &timeout)
	if errors.Is(e, unix.EINTR) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	changed := map[string]bool{}
	for _, ev := range events[:n] {
		if ev.Flags&unix.EV_ERROR != 0 {
			return nil, errors.New("vnode notification failed")
		}
		if p, ok := w.byFD[int(ev.Ident)]; ok {
			changed[p] = true
			if ev.Fflags&unix.NOTE_REVOKE != 0 || ev.Flags&unix.EV_EOF != 0 {
				fd := w.paths[p]
				_ = unix.Close(fd)
				delete(w.paths, p)
				delete(w.ids, p)
				delete(w.byFD, fd)
			}
		}
	}
	return changed, nil
}

func Run(ctx context.Context, user string, extra []string, rescan time.Duration, o *Observer) error {
	w, e := NewWatcher()
	if e != nil {
		return e
	}
	defer w.Close()
	at := time.Now()
	if e = o.Emit(Record{At: at.UTC().Format(time.RFC3339Nano), Kind: "observer_start"}); e != nil {
		return e
	}
	var notified map[string]bool
	last := time.Time{}
	for {
		if ctx.Err() != nil {
			return o.Emit(Record{At: time.Now().UTC().Format(time.RFC3339Nano), Kind: "observer_stop"})
		}
		if last.IsZero() || len(notified) > 0 || time.Since(last) >= rescan {
			homes, dirs, gap := Discover(o.FS, user, extra)
			// Arm directory watches first; a following scan captures current state.
			gap = w.Sync(append(dirs, knownFiles(o)...)) || gap
			files, e := o.Scan(time.Now(), homes, notified)
			if e != nil {
				return e
			}
			gap = w.Sync(append(dirs, files...)) || gap
			if gap {
				if e = o.Emit(Record{At: time.Now().UTC().Format(time.RFC3339Nano), Kind: "coverage_gap"}); e != nil {
					return e
				}
			}
			last = time.Now()
		}
		notified, e = w.Wait()
		if e != nil {
			return e
		}
	}
}

func knownFiles(o *Observer) []string {
	var p []string
	for k, v := range o.previous {
		if v.State == "present" {
			p = append(p, k)
		}
	}
	return p
}

// OpenJournal opens only the journal output, never a monitored input. Its lock
// lasts for the entire observer process, preventing duplicate writers.
func OpenJournal(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("absolute clean journal path required")
	}
	for _, n := range Names {
		if filepath.Base(path) == n {
			return nil, errors.New("journal cannot be a policy file")
		}
	}
	parent := filepath.Dir(path)
	for p := parent; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&fs.ModeSymlink != 0 {
			return nil, errors.New("journal directory unsafe")
		}
		if p == parent {
			st := i.Sys().(*syscall.Stat_t)
			if st.Uid != uint32(os.Getuid()) || i.Mode().Perm()&0077 != 0 {
				return nil, errors.New("private owned journal directory required")
			}
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	fd, e := unix.Open(path, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0600)
	if e != nil {
		return nil, errors.New("journal open refused")
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Getuid()) || st.Mode&0077 != 0 || st.Nlink != 1 {
		_ = f.Close()
		return nil, errors.New("journal must be private owned regular file with one link")
	}
	if unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB) != nil {
		_ = f.Close()
		return nil, errors.New("journal already locked")
	}
	return f, nil
}
