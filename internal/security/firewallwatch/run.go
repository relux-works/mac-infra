package firewallwatch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/relux-works/mac-infra/internal/security/journal"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("collector output limit")
	}
	return b.Buffer.Write(p)
}
func ParseSigner(output string, failed bool) string {
	switch {
	case strings.Contains(output, "not signed at all"):
		return "unsigned"
	case strings.Contains(output, "Signature=adhoc"):
		return "ad-hoc"
	case strings.Contains(output, "no designated requirement"):
		return "no designated requirement"
	case failed:
		return "unknown"
	case strings.Contains(output, "Authority=Developer ID Application:"):
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "Authority=Developer ID Application:") {
				return Sanitize("Developer ID: " + strings.TrimSpace(strings.TrimPrefix(line, "Authority=Developer ID Application:")))
			}
		}
	case strings.Contains(output, "Authority=Apple Mac OS Application Signing") || strings.Contains(output, "Authority=Mac App Store Application Signing"):
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, "TeamIdentifier=") {
				return Sanitize("App Store: " + strings.TrimPrefix(line, "TeamIdentifier="))
			}
		}
		return "App Store"
	case strings.Contains(output, "Authority=Software Signing") && strings.Contains(output, "Authority=Apple Root CA"):
		return "Apple"
	}
	return "no designated requirement"
}

var childEnv = []string{"PATH=/usr/bin:/bin", "LANG=C"}

func collectorCommand(ctx context.Context, name string) *exec.Cmd {
	var cmd *exec.Cmd
	switch name {
	case "log":
		cmd = exec.CommandContext(ctx, "/usr/bin/log", "stream", "--style", "ndjson", "--info", "--predicate", `subsystem == "com.apple.ALF.ApplicationFirewall"`)
	case "nettop":
		cmd = exec.CommandContext(ctx, "/usr/bin/nettop", "-L", "1", "-n", "-x", "-J", "bytes_out")
	case SourceNetfilter:
		cmd = exec.CommandContext(ctx, "/usr/bin/log", "stream", "--style", "ndjson", "--level", "info", "--predicate", NetfilterPredicate)
	}
	cmd.Env = append([]string{}, childEnv...)
	return cmd
}
func codesignCommand(ctx context.Context, path string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=2", path)
	cmd.Env = append([]string{}, childEnv...)
	return cmd
}
func inspectSigner(ctx context.Context, path string) (string, error) {
	cmd := codesignCommand(ctx, path)
	output := &cappedBuffer{limit: 64 * 1024}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	v := ParseSigner(output.String(), err != nil)
	if v != "unknown" {
		err = nil
	}
	return v, err
}
func (s *Store) signer(ctx context.Context, path string) string {
	if !filepath.IsAbs(path) || len(path) > LineLimit {
		return "unknown"
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "unknown"
	}
	info, err := os.Lstat(real)
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		return "unknown"
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown"
	}
	identity := fmt.Sprintf("%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Size, st.Mtimespec.Nano(), st.Ctimespec.Nano())
	// Hash the operational path for persistence: even cache keys must not retain IP literals.
	cacheKey := fmt.Sprintf("%x", sha256.Sum256([]byte(path)))
	now := time.Now()
	if s.clock != nil {
		now = s.clock()
	}
	// A bundle directory identity cannot attest its inner code. Re-inspect successes;
	// failed inspections still use the bounded failure TTL.
	if v, ok := s.State.Signers[cacheKey]; ok && v.Identity == identity && (info.Mode().IsRegular() || v.Failed) && (!v.Failed || now.Before(v.Inspected.Add(duration(s.Config.SignerFailureTTL)))) {
		v.LastSeen = now
		s.State.Signers[cacheKey] = v
		s.signerChanged(cacheKey)
		return v.Value
	}
	childCtx, cancel := context.WithTimeout(ctx, duration(s.Config.ClassifierTimeout))
	defer cancel()
	inspect := s.inspectSigner
	if inspect == nil {
		inspect = inspectSigner
	}
	v, err := inspect(childCtx, path)
	if err != nil {
		v = "unknown"
	}
	entry := SignerEntry{Value: Sanitize(v), LastSeen: now, Identity: identity, Failed: err != nil, Inspected: now}
	// A new or changed result is journaled at once; re-inspections with the
	// same result (bundle directories, failure retries) only refresh times,
	// which follow with the next append.
	if prev, ok := s.State.Signers[cacheKey]; !ok || prev.Value != entry.Value || prev.Identity != entry.Identity || prev.Failed != entry.Failed {
		s.delta.urgent = true
	}
	s.State.Signers[cacheKey] = entry
	s.signerChanged(cacheKey)
	s.dirty = true
	return Sanitize(v)
}

// scanLines bounds line storage even when the source emits an unterminated
// oversized line, and resumes at the next newline rather than losing the stream.
// collectionObserver receives collector liveness from the feeder goroutine.
type collectionObserver interface {
	StallCoverage(time.Time)
	ResumeCoverage(time.Time)
	EndCoverage(time.Time)
}

// feedLines queues collector lines for the run loop. A full queue is reported
// as a stall until the line is accepted, because the feeder cannot observe the
// collector meanwhile; the end of the stream (EOF, error or cancellation) is
// reported before lines is closed, so the run loop's final save sees it.
func feedLines(ctx context.Context, r io.Reader, lines chan<- []byte, observer collectionObserver) error {
	queueDepth := func(n int) {
		if o, ok := observer.(interface{ QueueDepth(int) }); ok {
			o.QueueDepth(n)
		}
	}
	e := scanLines(ctx, r, func(line []byte) error {
		copyLine := append([]byte(nil), line...)
		select {
		case lines <- copyLine:
			queueDepth(len(lines))
			return nil
		default:
		}
		queueDepth(cap(lines))
		observer.StallCoverage(time.Now())
		select {
		case lines <- copyLine:
			queueDepth(len(lines))
			observer.ResumeCoverage(time.Now())
			return nil
		case <-ctx.Done():
			if o, ok := observer.(interface{ DropLines(uint64) }); ok {
				o.DropLines(1)
			}
			return ctx.Err()
		}
	})
	observer.EndCoverage(time.Now())
	close(lines)
	return e
}
func scanLines(ctx context.Context, r io.Reader, consume func([]byte) error) error {
	br := bufio.NewReaderSize(r, LineLimit)
	var line []byte
	oversized := false
	for {
		fragment, e := br.ReadSlice('\n')
		if len(line)+len(fragment) > LineLimit {
			oversized = true
			line = nil
		} else if !oversized {
			line = append(line, fragment...)
		}
		if e == bufio.ErrBufferFull {
			continue
		}
		if len(fragment) > 0 || len(line) > 0 || oversized {
			if oversized {
				line = []byte("{")
			}
			if err := consume(bytes.TrimSpace(line)); err != nil {
				return err
			}
		}
		line = nil
		oversized = false
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
	}
}

// discardLines runs after the feeder has closed lines, so teardown accounts
// for every buffered line without parsing or starting any more inspection.
func discardLines(lines <-chan []byte, coverage *SourceCoverage) {
	var n uint64
	for range lines {
		n++
	}
	coverage.DropLines(n)
}

func (s *Store) collect(ctx context.Context, cl *Classifier, it Item) bool {
	path := it.InspectionPath
	if path == "" {
		path = it.App
	}
	// Netfilter items carry the extension's verified signing facts. Shutdown
	// rows need no signer inspection: Classify records backend_shutdown.
	if it.Source != SourceNetfilter && !cl.shuttingDown(ctx) {
		it.Signer = s.signer(ctx, path)
	}
	return len(s.observe(it, time.Now(), func(it Item) Decision {
		return cl.Classify(ctx, it)
	}, func() bool { return cl.shuttingDown(ctx) })) > 0
}

// collectSample observes one nettop sample and reports whether it emitted.
// sampleTick checkpoints it afterwards. flush runs after every row, emitting or
// not: it appends at once whatever the row made urgent (an emitted event, a
// deny-window change, a changed signer result; PR69 review r2) and a heartbeat
// once save_interval has passed, and does nothing otherwise. The save timer
// does not interrupt a classification. drain runs before each item and handles
// collector lines already queued, so a sample of many slow classifications
// does not stall the ALF and netfilter feeders (BUG-261029-kpyw8s).
func collectSample(items []Item, collect func(Item) bool, flush func(emitted bool) error, drain func() error) (bool, error) {
	emitted := false
	for _, it := range items {
		if e := drain(); e != nil {
			return emitted, e
		}
		row := collect(it)
		emitted = emitted || row
		if e := flush(row); e != nil {
			return emitted, e
		}
	}
	return emitted, nil
}

// drainQueued handles the collector lines already queued, at most one queue's
// worth per source, without waiting. After cancellation it does nothing: the
// sample then finishes with backend_shutdown rows as before. onNetfilter may
// set *netfilter to nil when that stream ends; a nil queue is never selected.
// Each source has its own budget; a source that spent it is not selected
// again in this drain (PR67 review r1).
func drainQueued(ctx context.Context, alf <-chan []byte, netfilter *chan []byte, onALF func([]byte, bool) (bool, error), onNetfilter func([]byte, bool) error) error {
	alfLeft, netLeft := cap(alf), cap(*netfilter)
	for ctx.Err() == nil {
		alfQueue, netQueue := alf, *netfilter
		if alfLeft == 0 {
			alfQueue = nil
		}
		if netLeft == 0 {
			netQueue = nil
		}
		if alfQueue == nil && netQueue == nil {
			return nil
		}
		select {
		case line, ok := <-alfQueue:
			alfLeft--
			if done, e := onALF(line, ok); done || e != nil {
				return e
			}
		case line, ok := <-netQueue:
			netLeft--
			if e := onNetfilter(line, ok); e != nil {
				return e
			}
		default:
			return nil
		}
	}
	return nil
}

// sampleNettop runs one nettop sample through run, the collector command,
// and collects its rows. A failed or timed-out command records nettop_error
// and emits nothing. The sample is a slow-operation candidate on every exit,
// including a failed command, with the parsed row count (zero when the command
// failed; PR67 review r1).
func (s *Store) sampleNettop(run func(io.Writer) error, collect func(Item) bool, flush func(emitted bool) error, drain func() error) (bool, error) {
	start, rows := time.Now(), 0
	defer func() { s.State.Health.recordSlow(SlowNettopSample, time.Since(start), time.Now(), rows) }()
	output := &cappedBuffer{limit: 4 << 20}
	if e := run(output); e != nil {
		s.State.NettopError = "nettop sample failed"
		return false, nil
	}
	s.State.NettopError = ""
	items, unknown := ParseNettop(output.String())
	s.State.NettopUnrecognized += unknown
	rows = len(items)
	return collectSample(items, collect, flush, drain)
}

// sampleTick runs one nettop tick. Backend maintenance (health check, Init)
// can block for the backend timeout, so a sample that emitted is saved before
// it (PR65 review r1); the closing save records the backend's health.
func sampleTick(sample func() (bool, error), save func() error, maintain func()) error {
	emitted, e := sample()
	if e != nil {
		return e
	}
	if emitted {
		if e = save(); e != nil {
			return e
		}
	}
	maintain()
	return save()
}

func Run(ctx context.Context, c Config, cl *Classifier) (err error) {
	if e := safeDir(c.StateDir); e != nil {
		return e
	}
	lockStore := &Store{Config: c}
	unlock, e := lockStore.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	s, e := OpenStore(c)
	if e != nil {
		return e
	}
	// The startup snapshot folds a replayed journal, a torn tail included,
	// into state.json and starts a fresh journal.
	if e = s.Save(time.Now()); e != nil {
		return e
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := collectorCommand(childCtx, "log")
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		return e
	}
	if e = cmd.Start(); e != nil {
		return e
	}
	// Registered before collector cleanup: the final save runs after both
	// feeders end and discarded queue lines have been counted.
	defer func() {
		s.State.BackendHealthy = cl.Healthy()
		err = errors.Join(err, s.Save(time.Now()))
	}()
	// A bounded queue provides backpressure while classification is slow.
	lines := make(chan []byte, 64)
	scanDone := make(chan error, 1)
	s.BeginCoverage(time.Now())
	alfCoverage := s.Coverage("")
	go func() { scanDone <- feedLines(childCtx, pipe, lines, alfCoverage) }()
	defer func() {
		cancel()
		pipe.Close()
		_ = cmd.Wait()
		<-scanDone
		discardLines(lines, alfCoverage)
	}()
	// The netfilter stream is optional (config netfilter_source). Its end does
	// not stop the watcher: ALF and nettop continue, the stream's coverage
	// ends, and health reports netfilter_error.
	var netLines chan []byte
	var netJournal *journal.Journal
	if *c.NetfilterSource {
		if netJournal, e = journal.Open(c.NetfilterJournalDir, journal.Capacity); e != nil {
			return fmt.Errorf("netfilter journal: %w", e)
		}
		netCmd := collectorCommand(childCtx, SourceNetfilter)
		netPipe, e := netCmd.StdoutPipe()
		if e != nil {
			return e
		}
		if e = netCmd.Start(); e != nil {
			return e
		}
		netLines = make(chan []byte, 64)
		netDone := make(chan error, 1)
		s.BeginSourceCoverage(SourceNetfilter, time.Now())
		netCoverage := s.Coverage(SourceNetfilter)
		go func() { netDone <- feedLines(childCtx, netPipe, netLines, netCoverage) }()
		defer func(queue <-chan []byte) {
			cancel()
			netPipe.Close()
			_ = netCmd.Wait()
			<-netDone
			discardLines(queue, netCoverage)
		}(netLines)
		s.State.NetfilterError = ""
	}
	collect := func(it Item) bool { return s.collect(ctx, cl, it) }
	// Startup metadata is dirty, but only an emitted event may flush it early.
	s.dirty = true
	s.lastSave = time.Now()
	saveTick := time.NewTicker(duration(c.SaveInterval))
	defer saveTick.Stop()
	// save is the tick's and the netfilter end's durable write: a heartbeat
	// with any pending records, or a snapshot when due.
	save := func() error {
		s.State.BackendHealthy = cl.Healthy()
		e := s.Checkpoint(time.Now())
		if e == nil {
			saveTick.Reset(duration(c.SaveInterval))
		}
		return e
	}
	flush := func(emitted bool) error {
		previous := s.lastSave
		s.State.BackendHealthy = cl.Healthy()
		e := s.Flush(time.Now(), emitted, false)
		if !s.lastSave.Equal(previous) {
			saveTick.Reset(duration(c.SaveInterval))
		}
		return e
	}
	// onALF handles one receive from the ALF queue. A closed queue ends the run:
	// cleanly after cancellation, with an error otherwise.
	onALF := func(line []byte, ok bool) (bool, error) {
		if !ok {
			if ctx.Err() != nil {
				return true, nil
			}
			return true, errors.New("ALF log stream ended")
		}
		s.dirty = true
		emitted := false
		if it := s.State.Parser.Parse(line); it != nil {
			emitted = collect(*it)
		}
		return false, flush(emitted)
	}
	onNetfilter := func(line []byte, ok bool) error {
		if !ok {
			netLines = nil
			s.State.NetfilterError = "netfilter log stream ended"
			return save()
		}
		s.dirty = true
		emitted := false
		it, action := s.State.Netfilter.ParseRecord(line)
		if it != nil {
			emitted = collect(*it)
		}
		if action != nil {
			if _, err := ReconcileAction(netJournal, *action, time.Now()); err != nil {
				s.State.NetfilterError = "reconcile: " + Sanitize(err.Error())
			}
		}
		return flush(emitted)
	}
	drain := func() error { return drainQueued(ctx, lines, &netLines, onALF, onNetfilter) }
	sample := func() (bool, error) {
		sampleCtx, stop := context.WithTimeout(ctx, duration(c.NettopInterval))
		defer stop()
		return s.sampleNettop(func(out io.Writer) error {
			nettop := collectorCommand(sampleCtx, "nettop")
			nettop.Stdout = out
			return nettop.Run()
		}, collect, flush, drain)
	}
	maintain := func() {
		start, pool := time.Now(), 0
		if ctx.Err() == nil && !cl.CheckHealth(ctx) && cl.Init(ctx) == nil {
			pool = len(cl.pool)
		}
		d, now := time.Since(start), time.Now()
		s.State.Health.Maintenance.observe(d, now)
		s.State.Health.recordSlow(SlowMaintenance, d, now, pool)
	}
	tick := time.NewTicker(duration(c.NettopInterval))
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-saveTick.C:
			if e = flush(false); e != nil {
				return e
			}
		case line, ok := <-lines:
			if done, e := onALF(line, ok); done || e != nil {
				return e
			}
		case line, ok := <-netLines:
			if e = onNetfilter(line, ok); e != nil {
				return e
			}
		case <-tick.C:
			if e = sampleTick(sample, save, maintain); e != nil {
				return e
			}
		}
	}
}
