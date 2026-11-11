package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

const runningDump = "system/com.apple.security.syspolicy = {\n\tactive count = 3\n\tstate = running\n\n\tprogram = /usr/libexec/syspolicyd\n\tendpoints = {\n\t\t\"com.apple.security.syspolicy\" = {\n\t\t\tstate = active\n\t\t}\n\t}\n\truns = 1\n\tpid = 549\n}\n"
const throttledDump = "system/com.apple.security.syspolicy = {\n\tstate = spawn scheduled\n\truns = 23\n\tendpoints = {\n\t\tstate = active\n\t}\n}\n"

// parseLaunchctl reads only top-level keys: nested endpoint states must not mask the service state.
func TestParseLaunchctl(t *testing.T) {
	s, err := parseLaunchctl(runningDump)
	if err != nil || s.State != "running" || s.Runs != 1 || s.PID != 549 {
		t.Fatalf("running dump: %+v %v", s, err)
	}
	s, err = parseLaunchctl(throttledDump)
	if err != nil || s.State != "spawn scheduled" || s.Runs != 23 || s.PID != 0 {
		t.Fatalf("throttled dump: %+v %v", s, err)
	}
	if _, err := parseLaunchctl("x = {\n\t\tstate = running\n}\n"); err == nil {
		t.Fatal("nested-only state accepted")
	}
	if _, err := parseLaunchctl("x = {\n\tstate = running\n\truns = many\n}\n"); err == nil {
		t.Fatal("non-numeric runs accepted")
	}
}

// The held-exec count takes old, tiny rows with a known absolute non-OS path only; OS binaries,
// bare argv[0] names, parenthesized names, young, large and zombie rows do not count.
func TestCountStuckExecs(t *testing.T) {
	ps := strings.Join([]string{
		"24543 12:36 112 S ugrep",                       // counts: known argv0, not an OS path
		"20380 1-20:40:09 112 SN /opt/example/bin/tool", // counts (days format)
		"40791 00:10 112 S ugrep",                       // too young
		"432 25-06:28:11 900000 Ss /System/Library/WS",  // large and OS
		"99 05:00 100 S /usr/libexec/tiny",              // OS binary
		"98 05:00 100 S (launchd_helper)",               // path unavailable: not counted
		"97 05:00 100 S (another helper)",               // path unavailable, with a space
		"77 05:00 0 Z /opt/example/zombie",              // zombie
		"78 05:00 4000 S /opt/example/bin/large",        // large
	}, "\n")
	n, err := countStuckExecs(ps, 30*time.Second, 256)
	if err != nil || n != 1 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	if _, err := countStuckExecs("1 xx 112 S a", 30*time.Second, 256); err == nil {
		t.Fatal("bad etime accepted")
	}
}

// Swap parsing accepts real output, including zero swap, and refuses malformed numbers instead of
// reporting them as zero; etime parsing handles the days form.
func TestParseSwapAndEtime(t *testing.T) {
	u, tot, err := parseSwap("total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted)")
	if err != nil || u != 1024.5 || tot != 2048 {
		t.Fatalf("swap %v %v %v", u, tot, err)
	}
	if u, tot, err := parseSwap("total = 0.00M  used = 0.00M  free = 0.00M  (encrypted)"); err != nil || u != 0 || tot != 0 {
		t.Fatalf("zero swap %v %v %v", u, tot, err)
	}
	for _, bad := range []string{"garbage", "total = .M  used = .M  free = .M", "total = 1.00M  used = 2.00M"} {
		if _, _, err := parseSwap(bad); err == nil {
			t.Fatalf("malformed swap accepted: %q", bad)
		}
	}
	d, err := parseEtime("01-02:03:04")
	if err != nil || d != 26*time.Hour+3*time.Minute+4*time.Second {
		t.Fatalf("etime %v %v", d, err)
	}
}

// fake is a controllable system for watcher tests.
type fake struct {
	mu        sync.Mutex
	svc       serviceState
	svcErr    error
	reports   []report
	repErrs   map[string]error
	absent    map[string]bool
	ps        string
	psErr     error
	probe     time.Duration
	control   time.Duration
	probeErr  error
	postErr   error
	postHang  chan struct{}
	posts     []string
	attempts  int
	notes     []string
	flag      *degradedFlag
	writeErr  error
	writes    int
	disk      float64
	pressure  int
	fsev      string
	swapUsed  float64
	swapTotal float64
}

func (f *fake) system() system {
	return system{
		syspolicy: func(context.Context) (serviceState, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.svc, f.svcErr },
		reports: func() ([]report, map[string]error, map[string]bool) {
			f.mu.Lock()
			defer f.mu.Unlock()
			errs := map[string]error{}
			for k, v := range f.repErrs {
				errs[k] = v
			}
			scanned := map[string]bool{}
			for _, src := range reportSources([]string{"/sys-reports", "/user-reports"}) {
				if errs[src] == nil && !f.absent[src] {
					scanned[src] = true
				}
			}
			return append([]report(nil), f.reports...), errs, scanned
		},
		ps:          func(context.Context) (string, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.ps, f.psErr },
		pressure:    func(context.Context) (int, error) { return f.pressure, nil },
		swap:        func(context.Context) (float64, float64, error) { return f.swapUsed, f.swapTotal, nil },
		diskFreePct: func() (float64, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.disk, nil },
		fsevents:    func(context.Context) (string, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.fsev, nil },
		execProbe: func(ctx context.Context) (time.Duration, time.Duration, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.probe, f.control, f.probeErr
		},
		notify: func(_ context.Context, text string) error {
			f.mu.Lock()
			f.notes = append(f.notes, text)
			f.mu.Unlock()
			return nil
		},
		post: func(ctx context.Context, text string) error {
			f.mu.Lock()
			f.attempts++
			h := f.postHang
			f.mu.Unlock()
			if h != nil {
				<-h
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.postErr != nil {
				return f.postErr
			}
			f.posts = append(f.posts, text)
			return nil
		},
		flagPresent: func(string) bool { f.mu.Lock(); defer f.mu.Unlock(); return f.flag != nil },
		writeFlag: func(_ string, d degradedFlag) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.writes++
			if f.writeErr != nil {
				return f.writeErr
			}
			f.flag = &d
			return nil
		},
		removeFlag: func(string) error { f.mu.Lock(); f.flag = nil; f.mu.Unlock(); return nil },
	}
}

func newFake() *fake {
	return &fake{svc: serviceState{State: "running", Runs: 1, PID: 549}, probe: 10 * time.Millisecond, control: time.Millisecond, disk: 50, pressure: 1}
}

func testOptions(t *testing.T) options {
	t.Helper()
	dir := t.TempDir()
	return options{reportsDirs: []string{"/sys-reports", "/user-reports"}, stateDir: filepath.Join(dir, "state"), flagPath: filepath.Join(dir, "flag"), postTimeout: time.Second, interval: 15 * time.Second, probeEvery: 15 * time.Second, clearAfter: 10 * time.Minute}
}

func newTestWatcher(t *testing.T, f *fake) *watcher {
	t.Helper()
	return newWatcher(testOptions(t), f.system())
}

var t0 = time.Date(2026, 11, 10, 22, 0, 0, 0, time.UTC)

// step runs one tick and waits for its background probe and post.
func step(t *testing.T, w *watcher, at time.Time) {
	t.Helper()
	if err := w.tick(at); err != nil {
		t.Fatal(err)
	}
	w.wg.Wait()
}

func (f *fake) set(fn func(*fake)) { f.mu.Lock(); fn(f); f.mu.Unlock() }

// warm runs ticks until a fresh healthy probe exists, so later ticks have positive evidence.
func warm(t *testing.T, w *watcher, from time.Time) time.Time {
	step(t, w, from)
	step(t, w, from.Add(15*time.Second))
	return from.Add(15 * time.Second)
}

// A healthy host raises no alert, posts nothing and writes a 0600 heartbeat on every tick.
func TestHealthyIsQuiet(t *testing.T) {
	f := newFake()
	f.reports = []report{{Name: "syspolicyd-old.ips", Class: "syspolicyd", Source: "/sys-reports"}}
	w := newTestWatcher(t, f)
	for i := 0; i < 3; i++ {
		at := t0.Add(time.Duration(i) * 15 * time.Second)
		step(t, w, at)
		hb, err := os.ReadFile(w.heartbeatPath())
		if err != nil || strings.TrimSpace(string(hb)) != at.Format(time.RFC3339) {
			t.Fatalf("tick %d heartbeat %q %v", i, hb, err)
		}
		fi, _ := os.Stat(w.heartbeatPath())
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("heartbeat mode %v", fi.Mode().Perm())
		}
	}
	if len(f.notes) != 0 || len(f.posts) != 0 || f.flag != nil {
		t.Fatalf("healthy host alerted: notes=%v posts=%v flag=%v", f.notes, f.posts, f.flag)
	}
}

// A syspolicyd crash publishes the flag, notifies at once and queues a2a while degraded; the notice
// goes out once health evidence returns, and the flag clears only after clear-after of health.
func TestCrashDegradesQueuesThenRecovers(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) {
		f.reports = []report{{Name: "syspolicyd-2026-11-10-212821.ips", Class: "syspolicyd", Source: "/sys-reports"}}
		f.svc = serviceState{State: "spawn scheduled", Runs: 2}
	})
	step(t, w, at.Add(15*time.Second))
	if f.flag == nil || !strings.Contains(f.flag.Reason, "syspolicyd.state=alert") || f.flag.HostWatchPID != w.pid {
		t.Fatalf("flag not set: %+v", f.flag)
	}
	if len(f.notes) == 0 || f.attempts != 0 {
		t.Fatalf("degraded: notes=%v attempts=%d (a2a must wait)", f.notes, f.attempts)
	}
	f.set(func(f *fake) { f.svc = serviceState{State: "running", Runs: 3, PID: 9} })
	step(t, w, at.Add(30*time.Second)) // health window starts
	step(t, w, at.Add(45*time.Second)) // queued notice goes out
	if len(f.posts) != 1 || !strings.Contains(f.posts[0], "syspolicyd-2026-11-10-212821.ips") || !strings.Contains(f.posts[0], "kickstart") {
		t.Fatalf("posts after recovery: %v", f.posts)
	}
	if f.flag == nil {
		t.Fatal("flag cleared before clear-after")
	}
	for i := 4; i <= 44; i++ { // keep probes fresh for 10 min
		step(t, w, at.Add(time.Duration(i)*15*time.Second))
	}
	if f.flag != nil {
		t.Fatalf("flag still set after clear-after: %+v", f.flag)
	}
	step(t, w, at.Add(46*15*time.Second))
	all := strings.Join(f.posts, "\n")
	if strings.Count(all, "syspolicyd-2026-11-10-212821.ips") != 1 || !strings.Contains(all, "CLEARED") {
		t.Fatalf("posts: %v", f.posts)
	}
}

// A failed first flag write is retried on every degraded tick until the flag is published.
func TestFlagWriteRetriedDuringIncident(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) {
		f.svc = serviceState{State: "spawn scheduled", Runs: 2}
		f.writeErr = errors.New("disk full")
	})
	step(t, w, at.Add(15*time.Second))
	if f.flag != nil {
		t.Fatal("flag present after failed write")
	}
	f.set(func(f *fake) { f.writeErr = nil })
	step(t, w, at.Add(30*time.Second))
	if f.flag == nil {
		t.Fatalf("flag not republished after the write recovered (writes=%d)", f.writes)
	}
	// A flag removed by someone else during the incident is published again.
	f.set(func(f *fake) { f.flag = nil })
	step(t, w, at.Add(45*time.Second))
	if f.flag == nil {
		t.Fatal("flag not republished after external removal")
	}
}

// State left by a dry run (degraded, no flag written) does not suppress publication by a live run.
func TestDryRunStateDoesNotSuppressLiveFlag(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	od := o
	od.dryRun = true
	dry := f.system()
	dry.flagPresent = func(string) bool { return false }
	dry.writeFlag = func(string, degradedFlag) error { return nil }
	wd := newWatcher(od, dry)
	f.set(func(f *fake) { f.svc = serviceState{State: "spawn scheduled", Runs: 2} })
	step(t, wd, t0)
	live := newWatcher(o, f.system())
	step(t, live, t0.Add(15*time.Second))
	if f.flag == nil {
		t.Fatal("live run did not publish the flag after a dry run")
	}
}

// Missing or unknown exec evidence never counts as health: an unknown probe, a failed ps scan and
// a restart without a fresh probe all reset the health window and keep the flag and the queue.
func TestUnknownEvidenceNeverClears(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	w := newWatcher(o, f.system())
	at := warm(t, w, t0)
	f.set(func(f *fake) {
		f.svc = serviceState{State: "spawn scheduled", Runs: 2}
		f.probeErr, f.control = context.DeadlineExceeded, time.Second // unknown: Apple control slow too
	})
	step(t, w, at.Add(15*time.Second))
	f.set(func(f *fake) { f.svc = serviceState{State: "running", Runs: 3} })
	for i := 2; i <= 50; i++ {
		step(t, w, at.Add(time.Duration(i)*15*time.Second))
	}
	if f.flag == nil || f.attempts != 0 {
		t.Fatalf("unknown probe cleared or posted: flag=%v attempts=%d", f.flag, f.attempts)
	}
	f.set(func(f *fake) { f.probeErr, f.control = nil, time.Millisecond; f.psErr = errors.New("ps failed") })
	for i := 51; i <= 100; i++ {
		step(t, w, at.Add(time.Duration(i)*15*time.Second))
	}
	if f.flag == nil || f.attempts != 0 {
		t.Fatalf("failed ps cleared or posted: flag=%v attempts=%d", f.flag, f.attempts)
	}
	// Restart across a monitoring gap with a persisted health window: no fresh probe yet, so the
	// first tick must not clear.
	f.set(func(f *fake) { f.psErr = nil })
	step(t, w, at.Add(101*15*time.Second))
	step(t, w, at.Add(102*15*time.Second)) // health window starts (fresh probe)
	s, _ := w.load()
	s.HealthySince = at.Add(-time.Hour).Format(time.RFC3339)
	if err := w.save(s); err != nil {
		t.Fatal(err)
	}
	restarted := newWatcher(o, f.system())
	if err := restarted.tick(at.Add(103 * 15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	restarted.wg.Wait()
	if f.flag == nil {
		t.Fatal("restart without a fresh probe cleared the flag")
	}
}

// A hung exec probe is never stacked, alerts as stuck after the timeout and blocks a2a.
func TestHungProbeNotStacked(t *testing.T) {
	f := newFake()
	release := make(chan struct{})
	var calls int
	sys := f.system()
	sys.execProbe = func(ctx context.Context) (time.Duration, time.Duration, error) {
		f.mu.Lock()
		calls++
		f.mu.Unlock()
		<-release
		return 0, 0, nil
	}
	o := testOptions(t)
	w := newWatcher(o, sys)
	for i := 0; i < 4; i++ {
		if err := w.tick(t0.Add(time.Duration(i*10) * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	f.mu.Lock()
	c := calls
	f.mu.Unlock()
	if c != 1 {
		t.Fatalf("probes started while one was outstanding: %d", c)
	}
	s, _ := w.load()
	if s.Levels["exec.probe"] != lvAlert || f.flag == nil {
		t.Fatalf("hung probe not alerted: levels=%v flag=%v", s.Levels, f.flag)
	}
	if f.attempts != 0 {
		t.Fatalf("posted while exec degraded: %d", f.attempts)
	}
	close(release)
	w.wg.Wait()
}

// A slow non-Apple exec alerts only when the Apple control is fast; a generally slow host only warns,
// and a failure with a slow control is unknown.
func TestJudgeProbe(t *testing.T) {
	cases := []struct {
		r    probeResult
		want string
	}{
		{probeResult{probe: 100 * time.Millisecond, control: time.Millisecond}, lvOK},
		{probeResult{probe: 3 * time.Second, control: time.Millisecond}, lvWarn},
		{probeResult{probe: 6 * time.Second, control: time.Millisecond}, lvAlert},
		{probeResult{probe: 6 * time.Second, control: time.Second}, lvWarn},
		{probeResult{err: context.DeadlineExceeded, control: time.Millisecond}, lvAlert},
		{probeResult{err: context.DeadlineExceeded, control: time.Second}, lvUnknown},
	}
	for i, c := range cases {
		if got, _ := judgeProbe(c.r); got != c.want {
			t.Errorf("case %d: got %s want %s", i, got, c.want)
		}
	}
}

// A failed post keeps its entries pending and they are retried; every attempt is counted, and each
// alert is delivered once after the post recovers.
func TestFailedPostRetried(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) { f.disk = 4; f.postErr = errors.New("a2a failed") })
	step(t, w, at.Add(15*time.Second))
	f.set(func(f *fake) { f.fsev = "fseventsd watchdog LaunchAgent is disabled" })
	step(t, w, at.Add(30*time.Second))
	if f.attempts != 2 || len(f.posts) != 0 {
		t.Fatalf("attempts=%d posts=%v", f.attempts, f.posts)
	}
	f.set(func(f *fake) { f.postErr = nil })
	step(t, w, at.Add(45*time.Second))
	step(t, w, at.Add(60*time.Second))
	got := deliveries(f.posts)
	if got["1"] != 1 || got["2"] != 1 || f.attempts != 3 {
		t.Fatalf("attempts=%d deliveries=%v", f.attempts, got)
	}
}

// A backlog larger than one post's budget drains in bounded posts after recovery, oldest first.
func TestBacklogDrainsInBoundedPosts(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	s, _ := w.load()
	for i := 0; i < 50; i++ {
		s.NextSeq++
		s.Pending = append(s.Pending, alert{Seq: s.NextSeq, At: "22:00:00Z", Key: "k", Text: strings.Repeat("x", 200)})
	}
	if err := w.save(s); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 30; i++ {
		step(t, w, at.Add(time.Duration(i)*15*time.Second))
	}
	total := 0
	for _, p := range f.posts {
		if len(p) > postMaxBytes {
			t.Fatalf("post of %d bytes exceeds the budget", len(p))
		}
		total += strings.Count(p, "[host-watch")
	}
	if total != 50 || len(f.posts) < 4 {
		t.Fatalf("delivered %d entries in %d posts", total, len(f.posts))
	}
}

// One unreadable report directory does not hide the others; a source seeds on its first successful
// scan, so its history never alerts when it appears later.
func TestReportSourcesIndependent(t *testing.T) {
	f := newFake()
	f.repErrs = map[string]error{"/user-reports": os.ErrPermission}
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) {
		f.reports = []report{{Name: "syspolicyd-new.ips", Class: "syspolicyd", Source: "/sys-reports"}}
	})
	step(t, w, at.Add(15*time.Second))
	if !strings.Contains(strings.Join(f.notes, "\n"), "syspolicyd-new.ips") {
		t.Fatalf("system report hidden by a failing user dir: %v", f.notes)
	}
	f.set(func(f *fake) {
		f.repErrs = nil
		f.reports = append(f.reports, report{Name: "mac-firewall-old.ips", Class: "tool", Source: "/user-reports"})
	})
	step(t, w, at.Add(30*time.Second))
	if strings.Contains(strings.Join(f.notes, "\n"), "mac-firewall-old.ips") {
		t.Fatal("history of a newly readable source alerted")
	}
}

// Reports of one class alert at most once per throttle window; reports held meanwhile go out with
// the next alert, none lost or duplicated.
func TestReportThrottle(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	for i, name := range []string{"WindowServer-a.ips", "WindowServer-b.spin", "WindowServer-c.hang"} {
		n := name
		f.set(func(f *fake) { f.reports = append(f.reports, report{Name: n, Class: "gui", Source: "/sys-reports"}) })
		step(t, w, at.Add(time.Duration(i+1)*15*time.Second))
	}
	gui := 0
	for _, n := range f.notes {
		if strings.Contains(n, "WindowServer") {
			gui++
		}
	}
	if gui != 1 {
		t.Fatalf("gui alerts within the window: %d (%v)", gui, f.notes)
	}
	step(t, w, at.Add(reportThrottle+time.Minute))
	all := strings.Join(f.notes, "\n")
	if strings.Count(all, "WindowServer-b.spin") != 1 || strings.Count(all, "WindowServer-c.hang") != 1 {
		t.Fatalf("held reports: %v", f.notes)
	}
}

// Report files are classified by name in the active and Retired directories, including .spin and
// .hang for every class; an unreadable source is reported while the others are kept.
func TestListReports(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Retired"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"syspolicyd-a.ips", "syspolicyd-b.spin", "WindowServer-2026.ips", "WindowServer_x.spin", "mac-firewall-b.ips", "mac-firewall-c.hang", "Claude_x.diag", "cat-1.ips", "Retired/syspolicyd-r.hang", "Retired/WindowServer-r.hang"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	missing := filepath.Join(dir, "absent")
	got, errs, _ := listReports([]string{dir, missing}, []string{"mac-firewall", "host-watch"})
	classes := map[string]int{}
	for _, r := range got {
		classes[r.Class]++
	}
	if len(got) != 8 || classes["syspolicyd"] != 3 || classes["gui"] != 3 || classes["tool"] != 2 {
		t.Fatalf("got %+v", got)
	}
	if errs[missing] == nil || len(errs) != 1 {
		t.Fatalf("errs %v", errs)
	}
}

// Publication is exclusive and atomic: a symlink planted at a predictable temporary path is not
// followed, a pre-existing permissive file gets the contract mode, and the flag JSON has exactly the
// contract fields; removal is idempotent.
func TestFlagFileSafety(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	p := filepath.Join(dir, "host-health", "exec-degraded")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, p+".tmp"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := writeDegradedFlag(p, degradedFlag{Reason: "syspolicyd.state=alert", Since: "2026-11-10T21:08:17Z", HostWatchPID: 42}); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(victim); string(raw) != "keep" {
		t.Fatal("symlink at a temporary path was followed")
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("flag mode %v", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m["reason"] != "syspolicyd.state=alert" || m["since"] != "2026-11-10T21:08:17Z" || m["host_watch_pid"] != float64(42) || len(m) != 3 {
		t.Fatalf("flag %s %v", raw, err)
	}
	if err := removeDegradedFlag(p); err != nil || removeDegradedFlag(p) != nil {
		t.Fatal("removal not idempotent")
	}
}

// A pre-existing permissive state directory is tightened to 0700; a symlinked one is refused.
func TestStateDirModes(t *testing.T) {
	dir := t.TempDir()
	st := filepath.Join(dir, "state")
	if err := os.MkdirAll(st, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(st, 0o777)
	if err := ensurePrivateDir(st); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(st)
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v", fi.Mode().Perm())
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(st, link); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateDir(link); err == nil {
		t.Fatal("symlinked state dir accepted")
	}
}

// The runner returns at the deadline even while a child is held before execve, never starts a
// second child of the same kind meanwhile, and frees the slot once the held launch ends.
func TestRunnerBoundsLaunchStage(t *testing.T) {
	r := newRunner()
	release := make(chan struct{})
	r.start = func(cmd *exec.Cmd) error { <-release; return errors.New("launch aborted") }
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t1 := time.Now()
	_, err := r.run(ctx, "probe-exec", "/usr/bin/true")
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(t1) > 2*time.Second {
		t.Fatalf("held launch: err=%v after %s", err, time.Since(t1))
	}
	if _, err := r.run(context.Background(), "probe-exec", "/usr/bin/true"); !errors.Is(err, errChildHeld) {
		t.Fatalf("second child started while one is held: %v", err)
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for r.busy("probe-exec") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	r.start = func(cmd *exec.Cmd) error { return cmd.Start() }
	if out, err := r.run(context.Background(), "probe-exec", "/bin/echo", "ok"); err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("slot not freed: %q %v", out, err)
	}
}

// Every required flag is enforced, the timing flags stay inside the agreed bounds, and the degraded
// flag must be the one contract path: a marker at any other configured path is refused.
func TestValidate(t *testing.T) {
	err := (options{}).validate()
	if err == nil || !strings.Contains(err.Error(), "--probe-every") || !strings.Contains(err.Error(), "--degraded-flag") {
		t.Fatalf("empty options: %v", err)
	}
	canonical, err := canonicalFlagPath()
	if err != nil {
		t.Fatal(err)
	}
	ok := options{reportsDirs: []string{"/r"}, toolPrefixes: []string{"mac-firewall"}, stateDir: "/s", flagPath: canonical, a2a: "/a", as: "x", room: "!r", to: "y", dataVolume: "/d", fseventsLabel: "l", interval: 15 * time.Second, probeEvery: time.Minute, postTimeout: 20 * time.Second, clearAfter: 10 * time.Minute}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*options){
		"relative a2a":           func(o *options) { o.a2a = "a2a" },
		"other flag path":        func(o *options) { o.flagPath = "/tmp/elsewhere/exec-degraded" },
		"post timeout above 60s": func(o *options) { o.postTimeout = 61 * time.Second },
		"clear-after below 10m":  func(o *options) { o.clearAfter = time.Second },
		"probe faster than tick": func(o *options) { o.probeEvery = time.Second },
		"bad tool prefix":        func(o *options) { o.toolPrefixes = []string{"a|b"} },
	} {
		o := ok
		mut(&o)
		if err := o.validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The flag path must be exactly the contract path: a dot-dot spelling that cleans to it, and a
// symlinked host-health directory, are both refused, so the writer and the consumers use one file.
func TestFlagPathExactAndNoSymlinks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	canonical, err := canonicalFlagPath()
	if err != nil {
		t.Fatal(err)
	}
	ok := options{reportsDirs: []string{"/r"}, toolPrefixes: []string{"mac-firewall"}, stateDir: "/s", flagPath: canonical, a2a: "/a", as: "x", room: "!r", to: "y", dataVolume: "/d", fseventsLabel: "l", interval: 15 * time.Second, probeEvery: time.Minute, postTimeout: 20 * time.Second, clearAfter: 10 * time.Minute}
	if err := ok.validate(); err != nil {
		t.Fatalf("canonical path refused: %v", err)
	}
	dotted := ok
	dotted.flagPath = filepath.Join(home, "x") + "/../Library/Application Support/host-health/exec-degraded"
	if err := dotted.validate(); err == nil {
		t.Fatal("dot-dot spelling accepted")
	}
	elsewhere := filepath.Join(home, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, "Library", "Application Support", "host-health")); err != nil {
		t.Fatal(err)
	}
	if err := ok.validate(); err == nil {
		t.Fatal("symlinked host-health directory accepted")
	}
	if err := writeDegradedFlag(canonical, degradedFlag{Reason: "r", Since: "s", HostWatchPID: 1}); err == nil {
		t.Fatal("flag written through a symlinked directory")
	}
	if _, err := os.Stat(filepath.Join(elsewhere, "exec-degraded")); err == nil {
		t.Fatal("flag landed outside the contract path")
	}
}

// An over-long notice is cut on a UTF-8 boundary, marked as truncated and kept within the budget.
func TestTruncateLine(t *testing.T) {
	for _, long := range []string{strings.Repeat("ж", 2000), "a" + strings.Repeat("ж", 2000)} { // 2-byte runes, both alignments
		got := truncateLine(long, postMaxBytes)
		if len(got) > postMaxBytes || !utf8.ValidString(got) || !strings.HasSuffix(got, truncMark) {
			t.Fatalf("len=%d valid=%v", len(got), utf8.ValidString(got))
		}
	}
	if short := "[host-watch 22:00:00Z] ok"; truncateLine(short, postMaxBytes) != short {
		t.Fatal("short line changed")
	}
}

// A dry run never writes the state directory, so it can neither suppress nor clear a live incident:
// after a live run publishes the flag, a long healthy dry run leaves the live state bytes and the flag.
func TestDryRunLeavesLiveIncident(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	live := newWatcher(o, f.system())
	at := warm(t, live, t0)
	f.set(func(f *fake) { f.svc = serviceState{State: "spawn scheduled", Runs: 2} })
	step(t, live, at.Add(15*time.Second))
	before, err := os.ReadFile(live.statePath())
	if err != nil || f.flag == nil {
		t.Fatalf("live incident not recorded: %v flag=%v", err, f.flag)
	}
	od := o
	od.dryRun = true
	dsys := f.system()
	dsys.removeFlag = func(string) error { return nil }
	dry := newWatcher(od, dsys)
	f.set(func(f *fake) { f.svc = serviceState{State: "running", Runs: 3} })
	for i := 2; i <= 50; i++ {
		step(t, dry, at.Add(time.Duration(i)*15*time.Second))
	}
	after, _ := os.ReadFile(live.statePath())
	if string(before) != string(after) || f.flag == nil {
		t.Fatalf("dry run changed the live incident: state changed=%v flag=%v", string(before) != string(after), f.flag)
	}
}

// Only a probe launched after the incident began is recovery evidence: with no newer probe the flag
// stays for longer than clear-after.
func TestProbeBeforeIncidentIsNotEvidence(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	o.probeEvery = 10 * time.Minute // no new probe during the test window
	w := newWatcher(o, f.system())
	step(t, w, t0) // the only probe, launched before the incident
	f.set(func(f *fake) { f.svc = serviceState{State: "spawn scheduled", Runs: 2} })
	step(t, w, t0.Add(15*time.Second))
	f.set(func(f *fake) { f.svc = serviceState{State: "running", Runs: 3} })
	for i := 2; i <= 50; i++ {
		step(t, w, t0.Add(time.Duration(i)*15*time.Second))
	}
	if f.flag == nil {
		t.Fatal("a probe from before the incident cleared the flag")
	}
}

// An unobserved gap between ticks restarts the health window: health on both sides of a gap is not
// continuous health.
func TestObservationGapResetsWindow(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	o.probeEvery = 6 * time.Minute // the probe stays fresh across the gap, so only gap detection can reset
	w := newWatcher(o, f.system())
	step(t, w, t0)
	f.set(func(f *fake) { f.svc = serviceState{State: "spawn scheduled", Runs: 2} })
	step(t, w, t0.Add(15*time.Second))
	f.set(func(f *fake) { f.svc = serviceState{State: "running", Runs: 3} })
	for at := 30 * time.Second; at <= 6*time.Minute+45*time.Second; at += 15 * time.Second {
		step(t, w, t0.Add(at)) // a probe after the incident launches near 6m; the health window opens
	}
	if s, _ := w.load(); s.HealthySince == "" {
		t.Fatal("precondition: the health window did not open before the gap")
	}
	step(t, w, t0.Add(16*time.Minute+30*time.Second)) // next tick only after a 10 min gap
	if f.flag == nil {
		t.Fatal("a gap was counted as continuous health")
	}
}

// A component redirected after startup is never written or removed through, and nothing is created
// at the redirect target.
func TestFlagSymlinkAfterStartup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	canonical, err := canonicalFlagPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkNoSymlinks(canonical); err != nil {
		t.Fatalf("clean home refused: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, "Library"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "redirect")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "Library", "Application Support")); err != nil {
		t.Fatal(err)
	}
	if err := writeDegradedFlag(canonical, degradedFlag{Reason: "r", Since: "s", HostWatchPID: 1}); err == nil {
		t.Fatal("flag written through a component redirected after startup")
	}
	if _, err := os.Stat(filepath.Join(target, "host-health")); err == nil {
		t.Fatal("directory created at the redirect target")
	}
	if err := os.MkdirAll(filepath.Join(target, "host-health"), 0o755); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(target, "host-health", "exec-degraded")
	if err := os.WriteFile(planted, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeDegradedFlag(canonical); err == nil {
		t.Fatal("removal through a redirected component accepted")
	}
	if _, err := os.Stat(planted); err != nil {
		t.Fatal("file at the redirect target was removed")
	}
}

// An unreadable Retired keeps the active directory's results, and a regular file at Retired is an
// error of that source only.
func TestRetiredIsItsOwnSource(t *testing.T) {
	for _, mode := range []string{"unreadable", "regular-file"} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "syspolicyd-a.ips"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		ret := filepath.Join(dir, "Retired")
		if mode == "unreadable" {
			if err := os.Mkdir(ret, 0o000); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(ret, 0o700)
		} else if err := os.WriteFile(ret, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		got, errs, _ := listReports([]string{dir}, []string{"mac-firewall"})
		if len(got) != 1 || got[0].Name != "syspolicyd-a.ips" || errs[ret] == nil || errs[dir] != nil {
			t.Fatalf("%s: got=%+v errs=%v", mode, got, errs)
		}
	}
}

// A symlink planted at events.jsonl is refused and its target is untouched.
func TestEventsFileNoFollow(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	if err := ensurePrivateDir(w.o.stateDir); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, w.eventsPath()); err != nil {
		t.Fatal(err)
	}
	if err := w.record(alert{Seq: 1, Text: "x"}); err == nil {
		t.Fatal("events symlink followed")
	}
	raw, _ := os.ReadFile(victim)
	fi, _ := os.Stat(victim)
	if string(raw) != "keep" || fi.Mode().Perm() != 0o644 {
		t.Fatal("events symlink target changed")
	}
}

// --once observes only: it starts no exec probe and no a2a post.
func TestOnceObservesOnly(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	o.once = true
	var probes int
	sys := f.system()
	sys.execProbe = func(context.Context) (time.Duration, time.Duration, error) { probes++; return 0, 0, nil }
	w := newWatcher(o, sys)
	f.set(func(f *fake) { f.disk = 4 })
	step(t, w, t0)
	if probes != 0 || f.attempts != 0 {
		t.Fatalf("once mode probed=%d posted=%d", probes, f.attempts)
	}
}

// A component replaced by a symlink between its check and its open is detected: neither publication
// nor removal goes through it, and the marker at the redirect target is untouched.
func TestFlagSwapBetweenCheckAndUse(t *testing.T) {
	for _, op := range []string{"write", "remove"} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		canonical, err := canonicalFlagPath()
		if err != nil {
			t.Fatal(err)
		}
		as := filepath.Join(home, "Library", "Application Support")
		if err := os.MkdirAll(filepath.Join(as, "host-health"), 0o755); err != nil {
			t.Fatal(err)
		}
		// The redirect stays inside the anchored parent and the symlink is relative, so os.Root itself
		// would follow it; only the identity check can catch the swap.
		redirect := filepath.Join(home, "Library", "redirect")
		if err := os.MkdirAll(filepath.Join(redirect, "host-health"), 0o755); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(redirect, "host-health", "exec-degraded")
		if err := os.WriteFile(marker, []byte("redirected"), 0o644); err != nil {
			t.Fatal(err)
		}
		flagDirHook = func(comp string) {
			if comp == "Application Support" {
				_ = os.Rename(as, as+".real")
				_ = os.Symlink("redirect", as)
			}
		}
		if op == "write" {
			err = writeDegradedFlag(canonical, degradedFlag{Reason: "r", Since: "s", HostWatchPID: 1})
		} else {
			err = removeDegradedFlag(canonical)
		}
		flagDirHook = nil
		if err == nil {
			t.Fatalf("%s went through a component swapped between check and open", op)
		}
		if raw, _ := os.ReadFile(marker); string(raw) != "redirected" {
			t.Fatalf("%s changed the marker at the redirect target", op)
		}
	}
}

// A Retired directory that is absent at first and appears later with history does not alert: an
// absent source is not a scan, so its first real enumeration seeds it.
func TestAbsentRetiredSeedsOnFirstEnumeration(t *testing.T) {
	f := newFake()
	f.absent = map[string]bool{"/sys-reports/Retired": true}
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) {
		f.absent = nil
		f.reports = []report{{Name: "syspolicyd-historical.ips", Class: "syspolicyd", Source: "/sys-reports/Retired"}}
	})
	step(t, w, at.Add(15*time.Second))
	if strings.Contains(strings.Join(f.notes, "\n"), "syspolicyd-historical.ips") || f.flag != nil {
		t.Fatalf("history of a newly appeared Retired alerted: notes=%v flag=%v", f.notes, f.flag)
	}
	dir := t.TempDir()
	_, _, scanned := listReports([]string{dir}, []string{"mac-firewall"})
	if !scanned[dir] || scanned[filepath.Join(dir, "Retired")] {
		t.Fatalf("scanned=%v: a missing Retired must not count as enumerated", scanned)
	}
}

// A configured report directory given as a symlink (an alias) is still read.
func TestReportDirAlias(t *testing.T) {
	real := t.TempDir()
	if err := os.WriteFile(filepath.Join(real, "syspolicyd-a.ips"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	got, errs, scanned := listReports([]string{alias}, []string{"mac-firewall"})
	if len(got) != 1 || errs[alias] != nil || !scanned[alias] {
		t.Fatalf("alias: got=%v errs=%v scanned=%v", got, errs, scanned)
	}
}

// A component swapped for a relative symlink back to the same directory is refused at open time:
// O_NOFOLLOW sees the link itself, so neither publication nor removal goes through it.
func TestFlagSameInodeSwap(t *testing.T) {
	for _, op := range []string{"write", "remove"} {
		home := t.TempDir()
		t.Setenv("HOME", home)
		canonical, _ := canonicalFlagPath()
		as := filepath.Join(home, "Library", "Application Support")
		if err := os.MkdirAll(filepath.Join(as, "host-health"), 0o755); err != nil {
			t.Fatal(err)
		}
		marker := filepath.Join(as, "host-health", "exec-degraded")
		if err := os.WriteFile(marker, []byte("marker"), 0o644); err != nil {
			t.Fatal(err)
		}
		flagDirHook = func(comp string) {
			if comp == "Application Support" {
				_ = os.Rename(as, as+".moved")
				_ = os.Symlink("Application Support.moved", as)
			}
		}
		var err error
		if op == "write" {
			err = writeDegradedFlag(canonical, degradedFlag{Reason: "r", Since: "s", HostWatchPID: 1})
		} else {
			err = removeDegradedFlag(canonical)
		}
		flagDirHook = nil
		if err == nil {
			t.Fatalf("%s went through a same-inode symlink swap", op)
		}
		if raw, _ := os.ReadFile(filepath.Join(as+".moved", "host-health", "exec-degraded")); string(raw) != "marker" {
			t.Fatalf("%s changed the marker behind the swap", op)
		}
	}
}

// A symlink at the flag name (dangling or not) is not the flag: presence matches a consumer's
// `test -e` for a dangling link. Removal unlinks the entry without following it, so the link goes
// and its target is never touched.
func TestFlagLeafSymlink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	canonical, _ := canonicalFlagPath()
	if err := os.MkdirAll(filepath.Dir(canonical), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nowhere", canonical); err != nil {
		t.Fatal(err)
	}
	if flagPresentAnchored(canonical) {
		t.Fatal("dangling leaf symlink counted as the flag")
	}
	target := filepath.Join(home, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(canonical); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, canonical); err != nil {
		t.Fatal(err)
	}
	if flagPresentAnchored(canonical) {
		t.Fatal("leaf symlink to a regular file counted as the flag")
	}
	if err := removeDegradedFlag(canonical); err != nil {
		t.Fatalf("removal of a leaf symlink: %v", err)
	}
	if _, err := os.Lstat(canonical); err == nil {
		t.Fatal("leaf symlink not removed")
	}
	if raw, _ := os.ReadFile(target); string(raw) != "keep" {
		t.Fatal("symlink target touched")
	}
	// Positive control: a regular flag file is present and removable.
	if err := writeDegradedFlag(canonical, degradedFlag{Reason: "r", Since: "s", HostWatchPID: 1}); err != nil || !flagPresentAnchored(canonical) {
		t.Fatalf("regular flag not present: %v", err)
	}
	if err := removeDegradedFlag(canonical); err != nil || flagPresentAnchored(canonical) {
		t.Fatalf("regular flag not removed: %v", err)
	}
}

// Saving filters into new storage: the caller's pending slice is unchanged, so one unsent alert is
// never seen twice.
func TestSaveDoesNotRewriteCallerSlice(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	if err := ensurePrivateDir(w.o.stateDir); err != nil {
		t.Fatal(err)
	}
	s := state{Version: stateVersion, Acked: 1, Pending: []alert{{Seq: 1, Key: "acked"}, {Seq: 2, Key: "unsent"}}}
	if err := w.save(s); err != nil {
		t.Fatal(err)
	}
	if s.Pending[0].Key != "acked" || s.Pending[1].Key != "unsent" {
		t.Fatalf("caller slice rewritten: %+v", s.Pending)
	}
	saved, _ := w.load()
	if len(saved.Pending) != 1 || saved.Pending[0].Key != "unsent" {
		t.Fatalf("saved pending: %+v", saved.Pending)
	}
}

// deliveries counts, per delivery id, how many successful posts carried it.
func deliveries(posts []string) map[string]int {
	out := map[string]int{}
	for _, p := range posts {
		for _, line := range strings.Split(p, "\n") {
			i := strings.Index(line, " #")
			j := strings.Index(line, "] ")
			if i > 0 && j > i {
				out[line[i+2:j]]++
			}
		}
	}
	return out
}

// eventSeqs lists the delivery ids of every alert recorded in events.jsonl.
func eventSeqs(t *testing.T, w *watcher) []string {
	raw, err := os.ReadFile(w.eventsPath())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var a alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatal(err)
		}
		out = append(out, fmt.Sprint(a.Seq))
	}
	return out
}

// The delivery invariant (at least once, never lost; a repeat carries the same delivery id) holds
// for a restart at every step from sending to recording: before the send completes, after a
// successful send that was never recorded, and after the delivery was recorded.
func TestDeliveryInvariantRestartAtEachStep(t *testing.T) {
	for _, stepName := range []string{"before-send", "sent-not-recorded", "recorded"} {
		t.Run(stepName, func(t *testing.T) {
			f := newFake()
			if stepName == "before-send" {
				f.postHang = make(chan struct{})
				f.postErr = errors.New("process died during the send")
			}
			w := newTestWatcher(t, f)
			at := warm(t, w, t0)
			f.set(func(f *fake) { f.disk = 4 })
			if stepName == "before-send" {
				// The old process hangs inside its post after recording the batch in flight.
				hung := make(chan struct{})
				go func() { _ = w.tick(at.Add(15 * time.Second)); close(hung) }()
				for {
					f.mu.Lock()
					a := f.attempts
					f.mu.Unlock()
					if a > 0 {
						break
					}
					time.Sleep(5 * time.Millisecond)
				}
				defer func() { close(f.postHang); <-hung }()
			} else {
				if stepName == "sent-not-recorded" {
					// The post succeeds, then the save that records it fails (as if the process died).
					w.beforeSave = func() error {
						f.mu.Lock()
						defer f.mu.Unlock()
						if f.attempts > 0 {
							return errors.New("died before recording")
						}
						return nil
					}
				}
				err := w.tick(at.Add(15 * time.Second))
				if (err != nil) != (stepName == "sent-not-recorded") {
					t.Fatalf("tick: %v", err)
				}
				w.beforeSave = nil
			}
			if stepName == "recorded" {
				step(t, w, at.Add(30*time.Second)) // the result is applied and saved
			}
			// Restart: a new process from the saved state, without the old sender.
			re := newWatcher(w.o, f.system())
			if stepName == "before-send" {
				sys := f.system()
				sys.post = func(ctx context.Context, text string) error { // the new process posts normally
					f.mu.Lock()
					defer f.mu.Unlock()
					f.posts = append(f.posts, text)
					return nil
				}
				re = newWatcher(w.o, sys)
			}
			for i := 3; i <= 6; i++ {
				step(t, re, at.Add(time.Duration(i)*15*time.Second))
			}
			got := deliveries(f.posts)
			for _, seq := range eventSeqs(t, w) {
				if got[seq] < 1 {
					t.Fatalf("alert #%s lost (posts %v)", seq, f.posts)
				}
			}
			if stepName == "recorded" && got["1"] != 1 {
				t.Fatalf("recorded delivery sent again: %v", got)
			}
			if stepName == "sent-not-recorded" && got["1"] != 2 {
				t.Fatalf("unrecorded delivery: want exactly one repeat with the same id, got %v", got)
			}
		})
	}
}

// A live watcher whose save fails right after a successful post (a durable record that could not
// be written) sends the batch again; the repeat is allowed and carries the same delivery id.
func TestStorageFailureAtRecord(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) { f.disk = 4 })
	failed := false
	w.beforeSave = func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.attempts > 0 && !failed {
			failed = true
			return errors.New("disk error at the record")
		}
		return nil
	}
	if err := w.tick(at.Add(15 * time.Second)); err == nil {
		t.Fatal("injected save failure not reported")
	}
	for i := 2; i <= 5; i++ {
		step(t, w, at.Add(time.Duration(i)*15*time.Second))
	}
	got := deliveries(f.posts)
	if got["1"] != 2 || len(got) != 1 {
		t.Fatalf("deliveries after a failed record: %v (want the same #1 twice)", got)
	}
}

// Concurrent ticks are serialized by the queue owner: every recorded alert is delivered at least
// once, and no delivery id is ever attached to two different alerts.
func TestConcurrentTicksKeepInvariant(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	var wg sync.WaitGroup
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				f.set(func(f *fake) { f.disk = float64(4 + 50*((i+g)%2)) }) // flaps: new alerts
				_ = w.tick(at.Add(time.Duration(1+i) * 15 * time.Second))
			}
		}(g)
	}
	wg.Wait()
	w.wg.Wait()
	f.set(func(f *fake) { f.disk = 50 })
	for i := 20; i <= 40; i++ {
		step(t, w, at.Add(time.Duration(i)*15*time.Second))
	}
	got := deliveries(f.posts)
	seqs := eventSeqs(t, w)
	for _, seq := range seqs {
		if got[seq] < 1 {
			t.Fatalf("alert #%s lost under concurrent ticks", seq)
		}
	}
	text := map[string]string{}
	for _, p := range f.posts {
		for _, line := range strings.Split(p, "\n") {
			i, j := strings.Index(line, " #"), strings.Index(line, "] ")
			if i < 0 || j < i {
				continue
			}
			id, body := line[i+2:j], line[j+2:]
			if prev, ok := text[id]; ok && prev != body {
				t.Fatalf("delivery id #%s carries two alerts: %q / %q", id, prev, body)
			}
			text[id] = body
		}
	}
}

// A child that exits while a descendant keeps its output open is observed at its exit: the runner
// returns within the short post deadline, frees the slot, reports the exit status (success or
// failure) and marks the output incomplete instead of treating it as a full sample.
func TestRunnerDescendantHoldsOutput(t *testing.T) {
	r := newRunner()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	t1 := time.Now()
	out, err := r.run(ctx, "a2a-post", "/bin/sh", "-c", "/bin/sleep 6 & echo posted")
	if !errors.Is(err, errOutputIncomplete) || !strings.Contains(out, "posted") || time.Since(t1) > 900*time.Millisecond {
		t.Fatalf("out=%q err=%v after %s", out, err, time.Since(t1))
	}
	if r.busy("a2a-post") {
		t.Fatal("slot held by a lingering descendant")
	}
	if _, err := r.run(context.Background(), "x", "/bin/sh", "-c", "/bin/sleep 6 & exit 3"); err == nil || errors.Is(err, errOutputIncomplete) {
		t.Fatalf("failing exit not reported as a failure: %v", err)
	}
	// A plain child gives complete output.
	if out, err := r.run(context.Background(), "echo", "/bin/echo", "ok"); err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("plain child: %q %v", out, err)
	}
}

// The a2a post treats incomplete output after a successful exit as delivered, so a delivery is not
// repeated because of its output; a failing exit stays a failure.
func TestPostIgnoresIncompleteOutput(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok-post", "/bin/sleep 6 &\necho posted\nexit 0\n")
	bad := write("bad-post", "/bin/sleep 6 &\nexit 3\n")
	for _, c := range []struct {
		bin     string
		wantErr bool
	}{{ok, false}, {bad, true}} {
		sys := liveSystem(options{a2a: c.bin, as: "x", room: "r", to: "y"}, "/usr/bin/true")
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := sys.post(ctx, "notice")
		cancel()
		if (err != nil) != c.wantErr {
			t.Fatalf("%s: err=%v", filepath.Base(c.bin), err)
		}
	}
}

// Output beyond the bound is kept bounded in memory, discarded beyond it, never stored on disk, and
// reported as an incomplete observation rather than a truncated sample.
func TestRunnerOutputBound(t *testing.T) {
	r := newRunner()
	out, err := r.run(context.Background(), "big", "/bin/dd", "if=/dev/zero", "bs=1048576", "count=4")
	if !errors.Is(err, errOutputIncomplete) || len(out) > maxChildOutput {
		t.Fatalf("oversized output: len=%d err=%v", len(out), err)
	}
}

// An event-log failure never loses a notice: with events.jsonl obstructed, the alert is still
// queued and delivered.
func TestEventLogFailureKeepsNotice(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	if err := os.Mkdir(w.eventsPath(), 0o700); err != nil { // obstruct the log
		t.Fatal(err)
	}
	f.set(func(f *fake) { f.disk = 4 })
	step(t, w, at.Add(15*time.Second))
	step(t, w, at.Add(30*time.Second))
	if !strings.Contains(strings.Join(f.posts, "\n"), "disk.free") {
		t.Fatalf("notice lost on an event-log failure: %v", f.posts)
	}
}

// Every physical line of a post carries a delivery id, even when an alert text contains line breaks.
func TestNoticeLinesCarryID(t *testing.T) {
	f := newFake()
	f.repErrs = map[string]error{"/user-reports": errors.New("open /x\ny\r\nz: no such file")}
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	step(t, w, at.Add(15*time.Second))
	if len(f.posts) == 0 {
		t.Fatal("no post")
	}
	for _, p := range f.posts {
		for _, line := range strings.Split(p, "\n") {
			if !strings.Contains(line, " #") {
				t.Fatalf("line without delivery id: %q", line)
			}
		}
	}
}

// Only the current state format is read: a file without the current version, with another
// version, or with unknown fields is refused; there is no migration.
func TestStateFormatStrict(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	step(t, w, t0) // writes a current-format state
	if _, err := w.load(); err != nil {
		t.Fatalf("current format refused: %v", err)
	}
	for name, body := range map[string]string{
		"no version":    `{"seen":{},"pending":[{"at":"x","key":"k","text":"t"}]}`,
		"other version": `{"version":2,"seen":{}}`,
		"unknown field": `{"version":1,"acked_file":"500"}`,
	} {
		if err := atomicWrite(w.statePath(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := w.tick(t0.Add(time.Minute)); err == nil {
			t.Fatalf("%s: state accepted", name)
		}
	}
}

// An event is logged only after the queue holding it is committed: a failed save logs nothing.
func TestEventLoggedOnlyAfterCommit(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	f.set(func(f *fake) { f.disk = 4 })
	w.beforeSave = func() error { return errors.New("disk error") }
	if err := w.tick(at.Add(15 * time.Second)); err == nil {
		t.Fatal("injected save failure not reported")
	}
	w.beforeSave = nil
	if raw, err := os.ReadFile(w.eventsPath()); err == nil && strings.Contains(string(raw), "disk.free") {
		t.Fatal("event logged for a queue entry that was never committed")
	}
	step(t, w, at.Add(30*time.Second))
	raw, _ := os.ReadFile(w.eventsPath())
	if strings.Count(string(raw), `"key":"disk.free"`) != 1 {
		t.Fatalf("event after commit: %s", raw)
	}
}

// A FIFO planted at events.jsonl cannot block the tick: the log open is non-blocking and the
// notice is still delivered.
func TestEventLogFIFODoesNotBlock(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	at := warm(t, w, t0)
	if err := syscall.Mkfifo(w.eventsPath(), 0o600); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *fake) { f.disk = 4 })
	done := make(chan error, 1)
	go func() { done <- w.tick(at.Add(15 * time.Second)) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tick blocked on a FIFO event log")
	}
	if !strings.Contains(strings.Join(f.posts, "\n"), "disk.free") {
		t.Fatalf("notice lost: %v", f.posts)
	}
}

// A read error other than EOF ends collection as incomplete output, never as a complete sample.
func TestCollectorReadErrorIncomplete(t *testing.T) {
	c := newCollector(errReader{})
	out, complete := c.finish(time.Second)
	if complete || len(out) != 2 {
		t.Fatalf("complete=%v out=%q", complete, out)
	}
	c2 := newCollector(strings.NewReader("ok"))
	if out, complete := c2.finish(time.Second); !complete || string(out) != "ok" {
		t.Fatalf("positive control: complete=%v out=%q", complete, out)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return copy(p, "ab"), errors.New("device error") }

// Once a child's exit is observed, a deadline that fires during the output drain does not turn the
// exit into a failure: exit 0 stays success with incomplete output.
func TestExitObservedBeatsDeadline(t *testing.T) {
	r := newRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := r.run(ctx, "a2a-post", "/bin/sh", "-c", "/bin/sleep 6 & exit 0")
	if errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errOutputIncomplete) {
		t.Fatalf("observed exit 0 reported as %v", err)
	}
}

// --once is read-only: run against a live watcher's state directory, it leaves the queue, the event
// log, the heartbeat and the flag exactly as they were, even when it observes new alerts.
func TestOnceIsReadOnly(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	live := newWatcher(o, f.system())
	at := warm(t, live, t0)
	f.set(func(f *fake) {
		f.disk = 4
		f.svc = serviceState{State: "spawn scheduled", Runs: 2}
		f.postErr = errors.New("held")
	})
	step(t, live, at.Add(15*time.Second)) // pending notice, flag published
	files := []string{live.statePath(), live.eventsPath(), live.heartbeatPath()}
	before := map[string]string{}
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		before[p] = string(raw)
	}
	flagBefore := f.flag
	oo := o
	oo.once = true
	osys := f.system()
	osys.writeFlag = func(string, degradedFlag) error { t.Fatal("--once wrote the flag"); return nil }
	osys.removeFlag = func(string) error { t.Fatal("--once removed the flag"); return nil }
	osys.post = func(context.Context, string) error { t.Fatal("--once posted"); return nil }
	once := newWatcher(oo, osys)
	f.set(func(f *fake) { f.fsev = "fseventsd watchdog LaunchAgent is disabled" }) // a new alert
	if err := once.tick(at.Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		raw, _ := os.ReadFile(p)
		if string(raw) != before[p] {
			t.Fatalf("--once changed %s", filepath.Base(p))
		}
	}
	if f.flag != flagBefore {
		t.Fatal("--once changed the flag")
	}
}

// Strict loading refuses trailing content after the state object instead of overwriting it.
func TestStateTrailingContentRefused(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	step(t, w, t0)
	raw, err := os.ReadFile(w.statePath())
	if err != nil {
		t.Fatal(err)
	}
	bad := append(append([]byte(nil), raw...), []byte("\n{\"version\":1}\n")...)
	if err := atomicWrite(w.statePath(), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.tick(t0.Add(time.Minute)); err == nil {
		t.Fatal("state with trailing content accepted")
	}
	after, _ := os.ReadFile(w.statePath())
	if string(after) != string(bad) {
		t.Fatal("refused state file was overwritten")
	}
}

// recoveringWatcher returns a watcher that is degraded and has an open health window as of the
// returned time.
func recoveringWatcher(t *testing.T, f *fake, o options, start time.Time) (*watcher, time.Time) {
	t.Helper()
	w := newWatcher(o, f.system())
	step(t, w, start)
	step(t, w, start.Add(o.interval))
	f.set(func(f *fake) { f.svc = serviceState{State: "spawn scheduled", Runs: 2} })
	at := start.Add(2 * o.interval)
	step(t, w, at)
	f.set(func(f *fake) { f.svc = serviceState{State: "running", Runs: 3} })
	at = at.Add(o.probeEvery) // a probe launched after the incident
	step(t, w, at)
	at = at.Add(o.interval)
	step(t, w, at)
	s, _ := w.load()
	if s.DegradedSince == "" || s.HealthySince == "" {
		t.Fatalf("precondition: degraded=%q healthy=%q", s.DegradedSince, s.HealthySince)
	}
	return w, at
}

// A long tick (observation plus a post that runs to its timeout) is observed time, not an outage:
// with a 1 s interval and a 10.4 s post timeout, a 12.408 s start-to-start gap keeps the window.
func TestLongTickIsNotAGap(t *testing.T) {
	f := newFake()
	o := testOptions(t)
	o.interval, o.probeEvery, o.postTimeout = time.Second, time.Second, 10400*time.Millisecond
	w, at := recoveringWatcher(t, f, o, t0)
	before, _ := w.load()
	w.since = func(time.Time) time.Duration { return 11408 * time.Millisecond } // 1 s observing + 10.4 s post
	step(t, w, at.Add(o.interval))
	w.since = time.Since
	step(t, w, at.Add(o.interval+12408*time.Millisecond))
	after, _ := w.load()
	if after.HealthySince != before.HealthySince {
		t.Fatalf("a long tick reset the health window: %q -> %q", before.HealthySince, after.HealthySince)
	}
}

// The gap is measured with full precision: a 39.4 s gap after a tick ending 900 ms into a second
// stays under the 40 s limit; a 40.5 s gap is an outage and resets the window.
func TestGapPrecision(t *testing.T) {
	for _, c := range []struct {
		gap   time.Duration
		reset bool
	}{{39400 * time.Millisecond, false}, {40500 * time.Millisecond, true}} {
		f := newFake()
		o := testOptions(t)
		w, at := recoveringWatcher(t, f, o, t0)
		end := at.Add(15*time.Second + 900*time.Millisecond)
		step(t, w, end)
		before, _ := w.load()
		step(t, w, end.Add(c.gap))
		after, _ := w.load()
		if (after.HealthySince != before.HealthySince) != c.reset {
			t.Fatalf("gap %s: window %q -> %q (want reset=%v)", c.gap, before.HealthySince, after.HealthySince, c.reset)
		}
	}
}

// An observation phase that stalls longer than the gap limit (here a report scan blocked 12.25 s
// against a 12 s limit) is an unobserved stretch: it resets the recovery window even though the
// tick saves its end afterwards. A normal observation phase keeps the window.
func TestStalledObservationResetsWindow(t *testing.T) {
	for _, c := range []struct {
		obs   time.Duration
		reset bool
	}{{500 * time.Millisecond, false}, {12250 * time.Millisecond, true}} {
		f := newFake()
		o := testOptions(t)
		o.interval, o.probeEvery = time.Second, time.Second
		w, at := recoveringWatcher(t, f, o, t0)
		before, _ := w.load()
		w.since = func(time.Time) time.Duration { return c.obs }
		step(t, w, at.Add(o.interval))
		w.since = time.Since
		after, _ := w.load()
		if (after.HealthySince != before.HealthySince) != c.reset {
			t.Fatalf("observation %s: window %q -> %q (want reset=%v)", c.obs, before.HealthySince, after.HealthySince, c.reset)
		}
	}
}

// A report scan that misses its deadline is an unhealthy observation: it resets the recovery
// window, is reported as unknown, and a still-running scan is not stacked by the next tick. A scan
// that finishes in time keeps the window.
func TestReportScanDeadline(t *testing.T) {
	old := scanTimeout
	scanTimeout = 50 * time.Millisecond
	defer func() { scanTimeout = old }()
	for _, blocked := range []bool{false, true} {
		f := newFake()
		o := testOptions(t)
		w, at := recoveringWatcher(t, f, o, t0)
		before, _ := w.load()
		release := make(chan struct{})
		calls := 0
		sys := f.system()
		inner := sys.reports
		sys.reports = func() ([]report, map[string]error, map[string]bool) {
			f.mu.Lock()
			calls++
			f.mu.Unlock()
			if blocked {
				<-release
			}
			return inner()
		}
		w.sys = sys
		step(t, w, at.Add(o.interval))
		step(t, w, at.Add(2*o.interval)) // the first scan is still blocked: no second scan
		after, _ := w.load()
		reset := after.HealthySince != before.HealthySince
		if reset != blocked {
			t.Fatalf("blocked=%v: window %q -> %q", blocked, before.HealthySince, after.HealthySince)
		}
		if blocked && (after.Levels["reports.scan"] != lvUnknown || calls != 1) {
			t.Fatalf("blocked scan: level=%q calls=%d", after.Levels["reports.scan"], calls)
		}
		close(release)
	}
}

// A FIFO named like a report is neither enumerated nor able to hang a body read; a regular report
// with a code-signing termination is still recognized.
func TestReportFIFOCannotHang(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "mac-firewall-2026-11-11-000000.ips")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	regular := filepath.Join(dir, "mac-firewall-2026-11-11-000001.ips")
	if err := os.WriteFile(regular, []byte(`{"termination":{"namespace":"CODESIGNING"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _, _ := listReports([]string{dir}, []string{"mac-firewall"})
	if len(got) != 1 || got[0].Path != regular {
		t.Fatalf("enumerated: %+v", got)
	}
	done := make(chan bool, 1)
	go func() { done <- reportIsCodesign(fifo) }()
	select {
	case cs := <-done:
		if cs {
			t.Fatal("FIFO classified as a code-signing report")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("body read blocked on a FIFO")
	}
	if !reportIsCodesign(regular) {
		t.Fatal("regular code-signing report not recognized")
	}
}
