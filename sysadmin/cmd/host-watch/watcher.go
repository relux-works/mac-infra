package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

// Thresholds of the watchdog set.
const (
	probeWarn      = 2 * time.Second
	probeAlert     = 5 * time.Second
	probeTimeout   = 15 * time.Second
	controlMax     = 500 * time.Millisecond
	stuckMinAge    = 30 * time.Second
	stuckMaxRSSKB  = 256
	stuckAlert     = 3
	stuckCritical  = 20
	diskWarnPct    = 10.0
	diskAlertPct   = 5.0
	swapWarnRatio  = 0.5
	swapAlertRatio = 0.9
	observeTimeout = 10 * time.Second
	notifyTimeout  = 10 * time.Second
	reportThrottle = 5 * time.Minute
	postMaxEntries = 20
	postMaxBytes   = 3000
)

const (
	lvOK       = "ok"
	lvWarn     = "warn"
	lvAlert    = "alert"
	lvCritical = "critical"
	lvUnknown  = "unknown"
)

type alert struct {
	Seq  int64  `json:"seq"`
	At   string `json:"at"`
	Key  string `json:"key"`
	Text string `json:"text"`
}

// stateVersion is the only state format host-watch reads; there is no migration from any other.
const stateVersion = 1

// state persists across ticks and restarts.
type state struct {
	Version       int                 `json:"version"` // stateVersion; any other content is refused
	Seen          map[string]bool     `json:"seen"`
	SeededSources map[string]bool     `json:"seeded_sources"`
	Levels        map[string]string   `json:"levels"`
	Service       *serviceState       `json:"service,omitempty"`
	Pending       []alert             `json:"pending,omitempty"`
	NextSeq       int64               `json:"next_seq"`
	Acked         int64               `json:"acked"`               // highest delivered sequence
	InFlight      *span               `json:"in_flight,omitempty"` // batch being posted by the current tick
	DegradedSince string              `json:"degraded_since,omitempty"`
	HealthySince  string              `json:"healthy_since,omitempty"`
	StuckRising   int                 `json:"stuck_rising"`
	LastStuck     int                 `json:"last_stuck"`
	LastTick      string              `json:"last_tick,omitempty"` // end of the last saved tick, RFC 3339 with nanoseconds
	ClassAlerted  map[string]string   `json:"class_alerted,omitempty"`
	HeldReports   map[string][]string `json:"held_reports,omitempty"`
}

type probeResult struct {
	probe, control time.Duration
	err            error
	launchedAt     time.Time // tick time at launch
}

type watcher struct {
	o   options
	sys system
	pid int

	mu            sync.Mutex
	probeBusy     bool
	scanBusy      bool // a report scan is still running
	probeLaunchAt time.Time
	lastProbe     *probeResult
	stateMu       sync.Mutex                    // held by the tick from load to save; the tick alone owns the queue
	beforeSave    func() error                  // tests only: inject a storage failure at the durable record
	since         func(time.Time) time.Duration // elapsed real time within a tick; tests model long ticks
	mem           *state                        // dry-run keeps its state here and never writes the state directory
	wg            sync.WaitGroup
}

func newWatcher(o options, sys system) *watcher {
	return &watcher{o: o, sys: sys, pid: os.Getpid(), since: time.Since}
}

func (w *watcher) statePath() string     { return filepath.Join(w.o.stateDir, "state.json") }
func (w *watcher) eventsPath() string    { return filepath.Join(w.o.stateDir, "events.jsonl") }
func (w *watcher) heartbeatPath() string { return filepath.Join(w.o.stateDir, "heartbeat") }

func (w *watcher) load() (state, error) {
	if w.readOnly() && w.mem != nil {
		return *w.mem, nil
	}
	s := state{Version: stateVersion}
	raw, err := os.ReadFile(w.statePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	if err == nil {
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var got state
		if err := dec.Decode(&got); err != nil {
			return s, fmt.Errorf("state %s: refusing a state file that is not the current format: %w", w.statePath(), err)
		}
		if _, err := dec.Token(); !errors.Is(err, io.EOF) {
			return s, fmt.Errorf("state %s: refusing trailing content after the state object", w.statePath())
		}
		if got.Version != stateVersion {
			return s, fmt.Errorf("state %s: refusing state version %d (want %d); no migration exists", w.statePath(), got.Version, stateVersion)
		}
		s = got
	}
	if s.Seen == nil {
		s.Seen = map[string]bool{}
	}
	if s.SeededSources == nil {
		s.SeededSources = map[string]bool{}
	}
	if s.Levels == nil {
		s.Levels = map[string]string{}
	}
	if s.ClassAlerted == nil {
		s.ClassAlerted = map[string]string{}
	}
	if s.HeldReports == nil {
		s.HeldReports = map[string][]string{}
	}
	return s, nil
}

func (w *watcher) save(s state) error {
	s.Version = stateVersion
	if w.beforeSave != nil {
		if err := w.beforeSave(); err != nil {
			return err
		}
	}
	if w.readOnly() {
		w.mem = &s // never written: a dry run leaves the live state untouched
		return nil
	}
	dropAcked(&s)
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(w.statePath(), raw, 0o600)
}

func (w *watcher) record(a alert) error {
	if w.readOnly() {
		return nil
	}
	// O_NOFOLLOW: a symlink planted at events.jsonl is refused, never followed.
	f, err := os.OpenFile(w.eventsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("events file %s is not a regular file", w.eventsPath())
	}
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	line, _ := json.Marshal(a)
	_, err = f.Write(append(line, '\n'))
	return err
}

// setLevel raises an alert when a check changes level, including the return to ok.
func setLevel(s *state, out *[]alert, stamp, key, level, text string) {
	prev, had := s.Levels[key]
	if !had {
		prev = lvOK
	}
	s.Levels[key] = level
	if prev == level {
		return
	}
	if level == lvOK {
		*out = append(*out, alert{At: stamp, Key: key, Text: "cleared: " + key})
		return
	}
	*out = append(*out, alert{At: stamp, Key: key, Text: fmt.Sprintf("%s %s: %s", strings.ToUpper(level), key, text)})
}

// tick runs one observation round. Observations use Apple binaries with bounded deadlines; the
// exec probe runs in the background with at most one outstanding; the a2a post is synchronous and
// bounded by the post timeout, which config validation keeps inside the recovery gap limit.
func (w *watcher) tick(now time.Time) error {
	realStart := time.Now()
	if !w.readOnly() {
		if err := ensurePrivateDir(w.o.stateDir); err != nil {
			return err
		}
		if err := atomicWrite(w.heartbeatPath(), []byte(now.Format(time.RFC3339)+"\n"), 0o600); err != nil {
			return err
		}
	}
	w.stateMu.Lock()
	locked := true
	defer func() {
		if locked {
			w.stateMu.Unlock()
		}
	}()
	s, err := w.load()
	if err != nil {
		return err
	}
	// The post is synchronous inside the tick, so a stored in-flight span always comes from a tick
	// that did not finish (a crash, or a failed save after the post): release it, and the batch is
	// sent again with the same delivery ids. Delivery is at least once.
	s.InFlight = nil
	// An unobserved gap (sleep, a stopped process, a hung tick) is never counted as health.
	gap := false
	// The gap runs from the END of the previous tick to the start of this one: time spent observing
	// and posting is observed time, never an outage. Full precision on both sides.
	if last, err := time.Parse(time.RFC3339Nano, s.LastTick); err == nil && now.Sub(last) > 2*w.o.interval+observeTimeout {
		gap = true
	}
	stamp := now.Format("15:04:05Z")
	var alerts []alert
	execBad := false
	healthy := true // positive evidence that non-Apple execs work; any missing evidence clears it

	// 1) syspolicyd service.
	ctx, cancel := context.WithTimeout(context.Background(), observeTimeout)
	svc, perr := w.sys.syspolicy(ctx)
	cancel()
	switch {
	case perr != nil:
		setLevel(&s, &alerts, stamp, "syspolicyd.state", lvUnknown, perr.Error())
		healthy = false
	case svc.State != "running":
		setLevel(&s, &alerts, stamp, "syspolicyd.state", lvAlert, fmt.Sprintf("state=%s runs=%d", svc.State, svc.Runs))
		execBad = true
	default:
		setLevel(&s, &alerts, stamp, "syspolicyd.state", lvOK, "")
		if s.Service != nil && s.Service.State == "running" && svc.Runs > s.Service.Runs {
			alerts = append(alerts, alert{At: stamp, Key: "syspolicyd.restart", Text: fmt.Sprintf("ALERT syspolicyd restarted: runs %d -> %d, pid %d", s.Service.Runs, svc.Runs, svc.PID)})
			execBad = true
		}
	}
	if perr == nil {
		sv := svc
		s.Service = &sv
	}

	// 2) crash reports, seeded per source on its first successful scan, throttled per class.
	if syspolicyNew, ok := w.reportChecks(&s, &alerts, now, stamp); !ok {
		healthy = false // a report scan that missed its deadline is no evidence of health
	} else if syspolicyNew {
		execBad = true
	}

	// 3) exec latency.
	w.mu.Lock()
	busy, launched, last := w.probeBusy, w.probeLaunchAt, w.lastProbe
	w.mu.Unlock()
	switch {
	case busy && now.Sub(launched) > probeTimeout:
		setLevel(&s, &alerts, stamp, "exec.probe", lvAlert, fmt.Sprintf("probe of a non-Apple exec still not finished after %s", now.Sub(launched).Round(time.Second)))
		execBad, healthy = true, false
	case last == nil || now.Sub(last.launchedAt) > 2*w.o.probeEvery+probeTimeout:
		healthy = false // no fresh probe from this process yet
	case probeBeforeIncident(s.DegradedSince, last.launchedAt):
		healthy = false // only a probe launched after the incident began is evidence of recovery
		lv, text := judgeProbe(*last)
		setLevel(&s, &alerts, stamp, "exec.probe", lv, text)
	default:
		lv, text := judgeProbe(*last)
		setLevel(&s, &alerts, stamp, "exec.probe", lv, text)
		if lv == lvAlert {
			execBad = true
		}
		if lv != lvOK {
			healthy = false
		}
	}

	// 4) processes held at exec.
	ctx, cancel = context.WithTimeout(context.Background(), observeTimeout)
	psOut, err := w.sys.ps(ctx)
	cancel()
	if err == nil {
		var n int
		n, err = countStuckExecs(psOut, stuckMinAge, stuckMaxRSSKB)
		if err == nil {
			if n > s.LastStuck && n > 0 {
				s.StuckRising++
			} else if n <= s.LastStuck {
				s.StuckRising = 0
			}
			s.LastStuck = n
			lv := lvOK
			switch {
			case n >= stuckCritical || (n >= stuckAlert && s.StuckRising >= 3):
				lv = lvCritical
			case n >= stuckAlert:
				lv = lvAlert
			}
			setLevel(&s, &alerts, stamp, "exec.stuck", lv, fmt.Sprintf("%d processes look held at exec (rising %d ticks); GUI at risk when critical", n, s.StuckRising))
			if lv != lvOK {
				execBad, healthy = true, false
			}
		}
	}
	if err != nil {
		setLevel(&s, &alerts, stamp, "exec.stuck", lvUnknown, err.Error())
		healthy = false
	}

	// Resource checks, alert-only.
	w.resourceChecks(&s, &alerts, stamp)

	// The degraded flag: the single automatic action.
	// An observation phase that itself ran longer than the gap limit (a stalled scan or probe call) is
	// an unobserved stretch too: it can never count toward recovery. The post comes later and is not
	// part of this measurement.
	if w.since(realStart) > 2*w.o.interval+observeTimeout {
		gap = true
	}
	w.updateDegraded(&s, &alerts, now, stamp, execBad, healthy && !gap)

	for i := range alerts {
		s.NextSeq++
		alerts[i].Seq = s.NextSeq
		if w.sys.notify != nil {
			nctx, ncancel := context.WithTimeout(context.Background(), notifyTimeout)
			_ = w.sys.notify(nctx, alerts[i].Text)
			ncancel()
		}
		s.Pending = append(s.Pending, alerts[i])
	}

	postAllowed := !w.o.once && healthy && (s.DegradedSince == "" || s.HealthySince != "")
	var batch []alert
	if postAllowed {
		batch = w.selectBatch(&s) // records the in-flight span in s before the save
	}
	s.LastTick = now.Add(w.since(realStart)).Format(time.RFC3339Nano)
	if err := w.save(s); err != nil {
		return err // nothing is logged or sent unless the queue and in-flight record are durable
	}
	// events.jsonl is a log written only after the queue holding these alerts is committed; a log
	// failure never loses a notice.
	for _, a := range alerts {
		if err := w.record(a); err != nil {
			fmt.Fprintln(os.Stderr, "host-watch: event log write failed:", err)
		}
	}
	if len(batch) > 0 {
		w.postBatch(&s, batch)
		s.LastTick = now.Add(w.since(realStart)).Format(time.RFC3339Nano)
		if err := w.save(s); err != nil {
			// The in-flight record stays durable; the next tick releases it and sends again.
			return err
		}
	}
	w.stateMu.Unlock()
	locked = false
	if !w.o.once {
		w.maybeStartProbe(now.Add(w.since(realStart)))
	}
	return nil
}

// reportChecks scans the report directories and returns true when a new syspolicyd report appeared.
func (w *watcher) reportChecks(s *state, alerts *[]alert, now time.Time, stamp string) (bool, bool) {
	reports, errs, scanned, ok := w.boundedScan()
	if !ok {
		setLevel(s, alerts, stamp, "reports.scan", lvUnknown, fmt.Sprintf("report scan did not finish within %s", scanTimeout))
		return false, false
	}
	setLevel(s, alerts, stamp, "reports.scan", lvOK, "")
	sources := reportSources(w.o.reportsDirs)
	sort.Strings(sources)
	for _, src := range sources {
		key := "reports.source." + src
		if e, bad := errs[src]; bad {
			setLevel(s, alerts, stamp, key, lvUnknown, e.Error())
		} else {
			setLevel(s, alerts, stamp, key, lvOK, "")
		}
	}
	fresh := map[string][]string{}
	for _, r := range reports {
		if s.Seen[r.Name] {
			continue
		}
		s.Seen[r.Name] = true
		if !s.SeededSources[r.Source] {
			continue // first successful scan of this source: history, not news
		}
		label := r.Name
		if r.Class == "tool" && reportIsCodesign(r.Path) {
			label += " (CODESIGNING)"
		}
		fresh[r.Class] = append(fresh[r.Class], label)
	}
	for _, src := range sources {
		if scanned[src] {
			s.SeededSources[src] = true
		}
	}
	texts := map[string]string{
		"syspolicyd": "new syspolicyd crash report(s); owner recovery: sudo /bin/launchctl kickstart -k " + syspolicyJob,
		"gui":        "new WindowServer hang/crash report(s), GUI at risk",
		"tool":       "new crash report(s) of configured host tools",
	}
	syspolicyNew := len(fresh["syspolicyd"]) > 0
	for _, c := range []string{"syspolicyd", "gui", "tool"} {
		s.HeldReports[c] = append(s.HeldReports[c], fresh[c]...)
		if len(s.HeldReports[c]) == 0 {
			continue
		}
		if last, err := time.Parse(time.RFC3339, s.ClassAlerted[c]); err == nil && now.Sub(last) < reportThrottle {
			continue // throttled: held reports go out with the next alert of this class
		}
		*alerts = append(*alerts, alert{At: stamp, Key: "reports." + c, Text: fmt.Sprintf("ALERT %s: %s", texts[c], strings.Join(s.HeldReports[c], ", "))})
		s.ClassAlerted[c] = now.Format(time.RFC3339)
		s.HeldReports[c] = nil
	}
	return syspolicyNew, true
}

func judgeProbe(r probeResult) (string, string) {
	switch {
	case r.err != nil && r.control > controlMax:
		return lvUnknown, fmt.Sprintf("Apple control exec slow too (%s): %v", r.control.Round(time.Millisecond), r.err)
	case r.err != nil:
		return lvAlert, fmt.Sprintf("non-Apple exec failed: %v", r.err)
	case r.control > controlMax:
		return lvWarn, fmt.Sprintf("all execs slow: Apple control %s, non-Apple %s", r.control.Round(time.Millisecond), r.probe.Round(time.Millisecond))
	case r.probe > probeAlert:
		return lvAlert, fmt.Sprintf("non-Apple exec took %s (Apple control %s)", r.probe.Round(time.Millisecond), r.control.Round(time.Millisecond))
	case r.probe > probeWarn:
		return lvWarn, fmt.Sprintf("non-Apple exec took %s (Apple control %s)", r.probe.Round(time.Millisecond), r.control.Round(time.Millisecond))
	}
	return lvOK, ""
}

func (w *watcher) resourceChecks(s *state, alerts *[]alert, stamp string) {
	ctx, cancel := context.WithTimeout(context.Background(), observeTimeout)
	defer cancel()
	if lvl, err := w.sys.pressure(ctx); err != nil {
		setLevel(s, alerts, stamp, "mem.pressure", lvUnknown, err.Error())
	} else {
		lv := map[int]string{1: lvOK, 2: lvWarn, 4: lvAlert}[lvl]
		if lv == "" {
			lv = lvUnknown
		}
		setLevel(s, alerts, stamp, "mem.pressure", lv, fmt.Sprintf("kern.memorystatus_vm_pressure_level=%d", lvl))
	}
	if used, total, err := w.sys.swap(ctx); err != nil {
		setLevel(s, alerts, stamp, "mem.swap", lvUnknown, err.Error())
	} else {
		lv := lvOK
		if total > 0 && used/total >= swapAlertRatio {
			lv = lvAlert
		} else if total > 0 && used/total >= swapWarnRatio {
			lv = lvWarn
		}
		setLevel(s, alerts, stamp, "mem.swap", lv, fmt.Sprintf("swap used %.0fM of %.0fM", used, total))
	}
	if pct, err := w.sys.diskFreePct(); err != nil {
		setLevel(s, alerts, stamp, "disk.free", lvUnknown, err.Error())
	} else {
		lv := lvOK
		if pct < diskAlertPct {
			lv = lvAlert
		} else if pct < diskWarnPct {
			lv = lvWarn
		}
		setLevel(s, alerts, stamp, "disk.free", lv, fmt.Sprintf("data volume %.1f%% free", pct))
	}
	if problem, err := w.sys.fsevents(ctx); err != nil {
		setLevel(s, alerts, stamp, "fseventsd.watchdog", lvUnknown, err.Error())
	} else if problem != "" {
		setLevel(s, alerts, stamp, "fseventsd.watchdog", lvAlert, problem)
	} else {
		setLevel(s, alerts, stamp, "fseventsd.watchdog", lvOK, "")
	}
}

// updateDegraded keeps the flag published for the whole incident (re-publishing it whenever it is
// missing) and removes it only after clearAfter of continuous positive health evidence.
func (w *watcher) updateDegraded(s *state, alerts *[]alert, now time.Time, stamp string, execBad, healthy bool) {
	if execBad && s.DegradedSince == "" {
		s.DegradedSince = now.Format(time.RFC3339)
		*alerts = append(*alerts, alert{At: stamp, Key: "degraded", Text: "exec-degraded: do not start new heavy lanes (" + degradedReason(s) + ")"})
	}
	if s.DegradedSince == "" {
		return
	}
	if execBad || !healthy {
		s.HealthySince = ""
	} else if s.HealthySince == "" {
		s.HealthySince = now.Format(time.RFC3339)
	} else if since, err := time.Parse(time.RFC3339, s.HealthySince); err == nil && now.Sub(since) >= w.o.clearAfter {
		if err := w.sys.removeFlag(w.o.flagPath); err != nil {
			setLevel(s, alerts, stamp, "degraded.flag", lvUnknown, "flag removal failed: "+err.Error())
			return
		}
		setLevel(s, alerts, stamp, "degraded.flag", lvOK, "")
		*alerts = append(*alerts, alert{At: stamp, Key: "degraded", Text: fmt.Sprintf("exec-degraded CLEARED after %s of continuous health (degraded since %s)", w.o.clearAfter, s.DegradedSince)})
		s.DegradedSince, s.HealthySince = "", ""
		return
	}
	if !w.sys.flagPresent(w.o.flagPath) {
		if err := w.sys.writeFlag(w.o.flagPath, degradedFlag{Reason: degradedReason(s), Since: s.DegradedSince, HostWatchPID: w.pid}); err != nil {
			setLevel(s, alerts, stamp, "degraded.flag", lvUnknown, "flag write failed, retrying every tick: "+err.Error())
			return
		}
	}
	setLevel(s, alerts, stamp, "degraded.flag", lvOK, "")
}

func degradedReason(s *state) string {
	var reason []string
	for k, v := range s.Levels {
		if v != lvOK && (strings.HasPrefix(k, "syspolicyd") || strings.HasPrefix(k, "exec")) {
			reason = append(reason, k+"="+v)
		}
	}
	sort.Strings(reason)
	if len(reason) == 0 {
		return "syspolicyd crash or restart"
	}
	return strings.Join(reason, ", ")
}

// dropAcked removes pending alerts already confirmed delivered.
func dropAcked(s *state) {
	keep := make([]alert, 0, len(s.Pending)) // new storage: a caller's slice is never rewritten
	for _, a := range s.Pending {
		if a.Seq > s.Acked {
			keep = append(keep, a)
		}
	}
	s.Pending = keep
}

// maybeStartProbe starts one exec-latency probe when due and none is outstanding.
func (w *watcher) maybeStartProbe(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.probeBusy || (!w.probeLaunchAt.IsZero() && now.Sub(w.probeLaunchAt) < w.o.probeEvery) {
		return
	}
	w.probeBusy, w.probeLaunchAt = true, now
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		p, c, err := w.sys.execProbe(ctx)
		cancel()
		w.mu.Lock()
		w.lastProbe = &probeResult{probe: p, control: c, err: err, launchedAt: now}
		w.probeBusy = false
		w.mu.Unlock()
	}()
}

type span struct {
	First int64 `json:"first"`
	Last  int64 `json:"last"`
}

// selectBatch picks the oldest undelivered alerts as one bounded batch and records it as in
// flight in s. It runs inside the tick under stateMu; nothing is selected while a batch is in flight.
func (w *watcher) selectBatch(s *state) []alert {
	if w.sys.post == nil {
		return nil
	}
	if s.InFlight != nil {
		return nil
	}
	var batch []alert
	size := 0
	for _, a := range s.Pending {
		if a.Seq <= s.Acked {
			continue
		}
		line := truncateLine(fmt.Sprintf("[host-watch %s #%d] %s", a.At, a.Seq, oneLine.Replace(a.Text)), postMaxBytes)
		if len(batch) > 0 && (len(batch) >= postMaxEntries || size+len(line)+1 > postMaxBytes) {
			break
		}
		a.Text = line
		batch = append(batch, a)
		size += len(line) + 1
	}
	if len(batch) > 0 {
		s.InFlight = &span{First: batch[0].Seq, Last: batch[len(batch)-1].Seq}
	}
	return batch
}

// postBatch sends one batch synchronously inside the tick, bounded by the post timeout. Exit 0
// means delivered: the watermark advances and the in-flight record is cleared. Any failure keeps
// the batch pending for a later tick.
func (w *watcher) postBatch(s *state, batch []alert) {
	lines := make([]string, len(batch))
	for i, a := range batch {
		lines[i] = a.Text
	}
	ctx, cancel := context.WithTimeout(context.Background(), w.o.postTimeout)
	err := w.sys.post(ctx, strings.Join(lines, "\n"))
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "host-watch: post deferred:", err)
		s.InFlight = nil
		return
	}
	if last := batch[len(batch)-1].Seq; last > s.Acked {
		s.Acked = last
	}
	s.InFlight = nil
	dropAcked(s)
}

// drain waits, bounded, for background work before a one-shot exit. --once starts neither a probe
// nor a post, so there is normally nothing to wait for.
func (w *watcher) drain() {
	if !boundedWait(&w.wg, w.o.postTimeout+probeTimeout+5*time.Second) {
		fmt.Fprintln(os.Stderr, "host-watch: background work still running at exit")
	}
}

const truncMark = " …[truncated; full text in events.jsonl]"

// truncateLine shortens line to at most max bytes on a UTF-8 boundary and says so, so a delivered
// notice is never a silently cut name; the full text stays in events.jsonl.
func truncateLine(line string, max int) string {
	if len(line) <= max {
		return line
	}
	cut := max - len(truncMark)
	if cut < 0 {
		cut = 0
	}
	for cut > 0 && !utf8.RuneStart(line[cut]) {
		cut--
	}
	return line[:cut] + truncMark
}

// probeBeforeIncident reports whether a probe was launched no later than the incident began.
func probeBeforeIncident(degradedSince string, launchedAt time.Time) bool {
	if degradedSince == "" {
		return false
	}
	since, err := time.Parse(time.RFC3339, degradedSince)
	if err != nil {
		return true
	}
	return !launchedAt.After(since)
}

// oneLine keeps every notice on one physical line, so every line of a post carries its delivery id.
var oneLine = strings.NewReplacer("\r\n", " \u23ce ", "\n", " \u23ce ", "\r", " \u23ce ")

// readOnly is true for --dry-run and --once: such a run never writes the state directory (state,
// events, heartbeat), the flag or a2a, so it cannot race a live watcher on the same state.
func (w *watcher) readOnly() bool { return w.o.dryRun || w.o.once }

// scanTimeout bounds one report scan; a var so tests can shorten it.
var scanTimeout = observeTimeout

type scanResult struct {
	reports []report
	errs    map[string]error
	scanned map[string]bool
}

// boundedScan runs the report scan with a deadline and at most one scan outstanding: a scan that
// is still running from an earlier tick counts as a miss without starting another one.
func (w *watcher) boundedScan() ([]report, map[string]error, map[string]bool, bool) {
	w.mu.Lock()
	if w.scanBusy {
		w.mu.Unlock()
		return nil, nil, nil, false
	}
	w.scanBusy = true
	w.mu.Unlock()
	ch := make(chan scanResult, 1)
	go func() {
		r, e, sc := w.sys.reports()
		w.mu.Lock()
		w.scanBusy = false
		w.mu.Unlock()
		ch <- scanResult{r, e, sc}
	}()
	select {
	case res := <-ch:
		return res.reports, res.errs, res.scanned, true
	case <-time.After(scanTimeout):
		return nil, nil, nil, false
	}
}
