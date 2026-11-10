package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
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
)

const (
	lvOK       = "ok"
	lvWarn     = "warn"
	lvAlert    = "alert"
	lvCritical = "critical"
	lvUnknown  = "unknown"
)

type alert struct {
	At   string `json:"at"`
	Key  string `json:"key"`
	Text string `json:"text"`
}

// state persists across ticks and restarts.
type state struct {
	Seeded        bool              `json:"seeded"`
	Seen          map[string]bool   `json:"seen"`
	Levels        map[string]string `json:"levels"`
	Service       *serviceState     `json:"service,omitempty"`
	Pending       []alert           `json:"pending,omitempty"`
	DegradedSince string            `json:"degraded_since,omitempty"`
	HealthySince  string            `json:"healthy_since,omitempty"`
	StuckRising   int               `json:"stuck_rising"`
	LastStuck     int               `json:"last_stuck"`
}

type probeResult struct {
	probe, control time.Duration
	err            error
	finished       time.Time
}

type watcher struct {
	o   options
	sys system
	pid int

	mu          sync.Mutex
	probeBusy   bool
	probeStart  time.Time
	lastProbeAt time.Time
	lastProbe   *probeResult
	postBusy    bool
	posted      int // count of pending alerts delivered by the outstanding post, applied on next tick
	wg          sync.WaitGroup
}

func newWatcher(o options, sys system) *watcher {
	return &watcher{o: o, sys: sys, pid: os.Getpid()}
}

func (w *watcher) statePath() string     { return filepath.Join(w.o.stateDir, "state.json") }
func (w *watcher) eventsPath() string    { return filepath.Join(w.o.stateDir, "events.jsonl") }
func (w *watcher) heartbeatPath() string { return filepath.Join(w.o.stateDir, "heartbeat") }

func (w *watcher) load() (state, error) {
	s := state{Seen: map[string]bool{}, Levels: map[string]string{}}
	raw, err := os.ReadFile(w.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, fmt.Errorf("state %s: %w", w.statePath(), err)
	}
	if s.Seen == nil {
		s.Seen = map[string]bool{}
	}
	if s.Levels == nil {
		s.Levels = map[string]string{}
	}
	return s, nil
}

func (w *watcher) save(s state) error {
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := w.statePath() + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, w.statePath())
}

func (w *watcher) record(a alert) error {
	f, err := os.OpenFile(w.eventsPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	line, _ := json.Marshal(a)
	_, err = f.Write(append(line, '\n'))
	return err
}

// level transitions: an alert is raised when a check changes level, including the return to ok.
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

// tick runs one observation round. It never blocks on a non-Apple exec: the exec probe and the
// a2a post run in the background with at most one of each outstanding.
func (w *watcher) tick(now time.Time) error {
	if err := os.MkdirAll(w.o.stateDir, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(w.heartbeatPath(), []byte(now.Format(time.RFC3339)+"\n"), 0o644); err != nil {
		return err
	}
	s, err := w.load()
	if err != nil {
		return err
	}
	stamp := now.Format("15:04:05Z")
	var alerts []alert
	execBad := false

	// Deliveries confirmed by a finished background post.
	w.mu.Lock()
	if w.posted > 0 && w.posted <= len(s.Pending) {
		s.Pending = s.Pending[w.posted:]
	}
	w.posted = 0
	w.mu.Unlock()

	// 1) syspolicyd service and crash reports.
	ctx, cancel := context.WithTimeout(context.Background(), observeTimeout)
	svc, perr := w.sys.syspolicy(ctx)
	cancel()
	switch {
	case perr != nil:
		setLevel(&s, &alerts, stamp, "syspolicyd.state", lvUnknown, perr.Error())
		execBad = true
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

	reports, rerr := w.sys.reports()
	if rerr != nil {
		setLevel(&s, &alerts, stamp, "reports.list", lvUnknown, rerr.Error())
	} else {
		setLevel(&s, &alerts, stamp, "reports.list", lvOK, "")
		fresh := map[string][]string{}
		for _, r := range reports {
			if s.Seen[r.Name] {
				continue
			}
			s.Seen[r.Name] = true
			if !s.Seeded {
				continue
			}
			label := r.Name
			if r.Class == "tool" && reportIsCodesign(r.Path) {
				label += " (CODESIGNING)"
			}
			fresh[r.Class] = append(fresh[r.Class], label)
		}
		texts := map[string]string{"syspolicyd": "new syspolicyd crash report(s); owner recovery: sudo /bin/launchctl kickstart -k " + syspolicyJob, "gui": "new WindowServer hang/crash report(s), GUI at risk", "tool": "new crash report(s) of our host tools"}
		classes := make([]string, 0, len(fresh))
		for c := range fresh {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		for _, c := range classes {
			alerts = append(alerts, alert{At: stamp, Key: "reports." + c, Text: fmt.Sprintf("ALERT %s: %s", texts[c], strings.Join(fresh[c], ", "))})
			if c == "syspolicyd" {
				execBad = true
			}
		}
	}
	s.Seeded = true

	// 2) exec latency.
	w.mu.Lock()
	if w.probeBusy && now.Sub(w.probeStart) > probeTimeout {
		w.mu.Unlock()
		setLevel(&s, &alerts, stamp, "exec.probe", lvAlert, fmt.Sprintf("probe of a non-Apple exec still not finished after %s", now.Sub(w.probeStart).Round(time.Second)))
		execBad = true
	} else {
		last := w.lastProbe
		w.mu.Unlock()
		if last != nil {
			lv, text := judgeProbe(*last)
			setLevel(&s, &alerts, stamp, "exec.probe", lv, text)
			if lv == lvAlert {
				execBad = true
			}
		}
	}

	// 3) processes held at exec.
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
				execBad = true
			}
		}
	}
	if err != nil {
		setLevel(&s, &alerts, stamp, "exec.stuck", lvUnknown, err.Error())
	}

	// Resource checks, alert-only.
	w.resourceChecks(&s, &alerts, stamp)

	// The degraded flag: the single automatic action.
	w.updateDegraded(&s, &alerts, now, stamp, execBad)

	for _, a := range alerts {
		if err := w.record(a); err != nil {
			return err
		}
		if w.sys.notify != nil {
			nctx, ncancel := context.WithTimeout(context.Background(), notifyTimeout)
			_ = w.sys.notify(nctx, a.Text)
			ncancel()
		}
		s.Pending = append(s.Pending, a)
	}

	w.maybeStartProbe(now)
	if err := w.save(s); err != nil {
		return err
	}
	w.maybeStartPost(s)
	return nil
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

func (w *watcher) updateDegraded(s *state, alerts *[]alert, now time.Time, stamp string, execBad bool) {
	if execBad {
		s.HealthySince = ""
		if s.DegradedSince == "" {
			s.DegradedSince = now.Format(time.RFC3339)
			reason := []string{}
			for k, v := range s.Levels {
				if v != lvOK && (strings.HasPrefix(k, "syspolicyd") || strings.HasPrefix(k, "exec")) {
					reason = append(reason, k+"="+v)
				}
			}
			sort.Strings(reason)
			if len(reason) == 0 {
				reason = []string{"syspolicyd crash or restart"}
			}
			if err := w.sys.writeFlag(w.o.flagPath, degradedFlag{Reason: strings.Join(reason, ", "), Since: s.DegradedSince, HostWatchPID: w.pid}); err != nil {
				*alerts = append(*alerts, alert{At: stamp, Key: "degraded.flag", Text: "UNKNOWN degraded flag write failed: " + err.Error()})
			} else {
				*alerts = append(*alerts, alert{At: stamp, Key: "degraded.flag", Text: "exec-degraded flag SET: do not start new heavy lanes (" + strings.Join(reason, ", ") + ")"})
			}
		}
		return
	}
	if s.DegradedSince == "" {
		return
	}
	if s.HealthySince == "" {
		s.HealthySince = now.Format(time.RFC3339)
		return
	}
	since, err := time.Parse(time.RFC3339, s.HealthySince)
	if err != nil || now.Sub(since) < w.o.clearAfter {
		return
	}
	if err := w.sys.removeFlag(w.o.flagPath); err != nil {
		*alerts = append(*alerts, alert{At: stamp, Key: "degraded.flag", Text: "UNKNOWN degraded flag removal failed: " + err.Error()})
		return
	}
	*alerts = append(*alerts, alert{At: stamp, Key: "degraded.flag", Text: fmt.Sprintf("exec-degraded flag CLEARED after %s healthy (degraded since %s)", w.o.clearAfter, s.DegradedSince)})
	s.DegradedSince, s.HealthySince = "", ""
}

// maybeStartProbe starts one exec-latency probe when due and none is outstanding.
func (w *watcher) maybeStartProbe(now time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.probeBusy || (!w.lastProbeAt.IsZero() && now.Sub(w.lastProbeAt) < w.o.probeEvery) {
		return
	}
	w.probeBusy, w.probeStart, w.lastProbeAt = true, now, now
	run := func() {
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		p, c, err := w.sys.execProbe(ctx)
		cancel()
		w.mu.Lock()
		w.lastProbe = &probeResult{probe: p, control: c, err: err, finished: time.Now()}
		w.probeBusy = false
		w.mu.Unlock()
	}
	w.wg.Add(1)
	go func() { defer w.wg.Done(); run() }()
}

// maybeStartPost sends pending alerts to a2a in one post, only while execs are not degraded and
// no other post is outstanding. a2a is a non-Apple binary: it hangs exactly while the gate is shut.
func (w *watcher) maybeStartPost(s state) {
	if w.sys.post == nil || len(s.Pending) == 0 || s.DegradedSince != "" && s.HealthySince == "" {
		return
	}
	w.mu.Lock()
	if w.postBusy {
		w.mu.Unlock()
		return
	}
	w.postBusy = true
	w.mu.Unlock()
	batch := append([]alert(nil), s.Pending...)
	var b strings.Builder
	for _, a := range batch {
		fmt.Fprintf(&b, "[host-watch %s] %s\n", a.At, a.Text)
	}
	text := strings.TrimSuffix(b.String(), "\n")
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), w.o.postTimeout)
		err := w.sys.post(ctx, text)
		cancel()
		w.mu.Lock()
		if err == nil {
			w.posted = len(batch)
		} else {
			fmt.Fprintln(os.Stderr, "host-watch: post deferred:", err)
		}
		w.postBusy = false
		w.mu.Unlock()
	}()
}

// drain waits for background work (used with --once and in tests) and applies a finished post.
func (w *watcher) drain() {
	w.wg.Wait()
	s, err := w.load()
	if err != nil {
		return
	}
	w.mu.Lock()
	if w.posted > 0 && w.posted <= len(s.Pending) {
		s.Pending = s.Pending[w.posted:]
	}
	w.posted = 0
	w.mu.Unlock()
	_ = w.save(s)
}
