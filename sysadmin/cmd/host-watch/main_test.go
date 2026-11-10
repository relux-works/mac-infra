package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// The stuck-exec count takes old, tiny, non-OS processes only; OS binaries, young, large and zombie rows do not count.
func TestCountStuckExecs(t *testing.T) {
	ps := strings.Join([]string{
		"24543 12:36 112 S ugrep",                                // counts
		"20380 1-20:40:09 112 SN /Users/example/.local/bin/tool", // counts (days format)
		"40791 00:10 112 S ugrep",                                // too young
		"432 25-06:28:11 900000 Ss /System/Library/WindowServer", // large and OS
		"99 05:00 100 S /usr/libexec/tiny",                       // OS binary
		"77 05:00 0 Z /opt/example/zombie",                       // zombie
		"78 05:00 4000 S /opt/homebrew/bin/codex",                // large
	}, "\n")
	n, err := countStuckExecs(ps, 30*time.Second, 256)
	if err != nil || n != 2 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	if _, err := countStuckExecs("1 xx 112 S a", 30*time.Second, 256); err == nil {
		t.Fatal("bad etime accepted")
	}
}

func TestParseSwapAndEtime(t *testing.T) {
	u, tot, err := parseSwap("total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted)")
	if err != nil || u != 1024.5 || tot != 2048 {
		t.Fatalf("swap %v %v %v", u, tot, err)
	}
	if _, _, err := parseSwap("garbage"); err == nil {
		t.Fatal("garbage swap accepted")
	}
	d, err := parseEtime("01-02:03:04")
	if err != nil || d != 26*time.Hour+3*time.Minute+4*time.Second {
		t.Fatalf("etime %v %v", d, err)
	}
}

// fake is a controllable system for watcher tests.
type fake struct {
	mu       sync.Mutex
	svc      serviceState
	svcErr   error
	reports  []report
	ps       string
	probe    time.Duration
	control  time.Duration
	probeErr error
	block    chan struct{} // when non-nil, the exec probe blocks until closed
	postErr  error
	postHang chan struct{}
	posts    []string
	notes    []string
	flag     *degradedFlag
	disk     float64
	pressure int
	fsev     string
}

func (f *fake) system() system {
	return system{
		syspolicy: func(context.Context) (serviceState, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.svc, f.svcErr },
		reports: func() ([]report, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]report(nil), f.reports...), nil
		},
		ps:          func(context.Context) (string, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.ps, nil },
		pressure:    func(context.Context) (int, error) { return f.pressure, nil },
		swap:        func(context.Context) (float64, float64, error) { return 0, 0, nil },
		diskFreePct: func() (float64, error) { return f.disk, nil },
		fsevents:    func(context.Context) (string, error) { return f.fsev, nil },
		execProbe: func(ctx context.Context) (time.Duration, time.Duration, error) {
			f.mu.Lock()
			b := f.block
			p, c, e := f.probe, f.control, f.probeErr
			f.mu.Unlock()
			if b != nil {
				<-b
			}
			return p, c, e
		},
		notify: func(_ context.Context, text string) error {
			f.mu.Lock()
			f.notes = append(f.notes, text)
			f.mu.Unlock()
			return nil
		},
		post: func(ctx context.Context, text string) error {
			f.mu.Lock()
			h := f.postHang
			f.mu.Unlock()
			if h != nil {
				<-h
			}
			f.mu.Lock()
			e := f.postErr
			f.mu.Unlock()
			if e != nil {
				return e
			}
			f.mu.Lock()
			f.posts = append(f.posts, text)
			f.mu.Unlock()
			return nil
		},
		writeFlag:  func(_ string, d degradedFlag) error { f.mu.Lock(); f.flag = &d; f.mu.Unlock(); return nil },
		removeFlag: func(string) error { f.mu.Lock(); f.flag = nil; f.mu.Unlock(); return nil },
	}
}

func newFake() *fake {
	return &fake{svc: serviceState{State: "running", Runs: 1, PID: 549}, probe: 10 * time.Millisecond, control: time.Millisecond, disk: 50, pressure: 1}
}

func newTestWatcher(t *testing.T, f *fake) *watcher {
	t.Helper()
	dir := t.TempDir()
	o := options{stateDir: filepath.Join(dir, "state"), flagPath: filepath.Join(dir, "flag"), postTimeout: time.Second, probeEvery: time.Minute, clearAfter: 10 * time.Minute}
	return newWatcher(o, f.system())
}

var t0 = time.Date(2026, 11, 10, 22, 0, 0, 0, time.UTC)

func step(t *testing.T, w *watcher, at time.Time) {
	t.Helper()
	if err := w.tick(at); err != nil {
		t.Fatal(err)
	}
	w.wg.Wait()
}

// A healthy host raises no alert, posts nothing and writes a heartbeat every tick.
func TestHealthyIsQuiet(t *testing.T) {
	f := newFake()
	f.reports = []report{{Name: "syspolicyd-old.ips", Class: "syspolicyd"}}
	w := newTestWatcher(t, f)
	for i := 0; i < 3; i++ {
		step(t, w, t0.Add(time.Duration(i)*time.Minute))
	}
	if len(f.notes) != 0 || len(f.posts) != 0 || f.flag != nil {
		t.Fatalf("healthy host alerted: notes=%v posts=%v flag=%v", f.notes, f.posts, f.flag)
	}
	hb, err := os.ReadFile(w.heartbeatPath())
	if err != nil || !strings.HasPrefix(string(hb), t0.Add(2*time.Minute).Format(time.RFC3339)) {
		t.Fatalf("heartbeat %q %v", hb, err)
	}
}

// A syspolicyd crash sets the degraded flag, notifies at once, queues the a2a notice while degraded,
// and sends it once the host has been healthy again; the flag clears after clear-after.
func TestCrashDegradesQueuesThenRecovers(t *testing.T) {
	f := newFake()
	w := newTestWatcher(t, f)
	step(t, w, t0) // seed
	f.mu.Lock()
	f.reports = []report{{Name: "syspolicyd-2026-11-10-212821.ips", Class: "syspolicyd"}}
	f.svc = serviceState{State: "spawn scheduled", Runs: 2}
	f.mu.Unlock()
	step(t, w, t0.Add(15*time.Second))
	if f.flag == nil || !strings.Contains(f.flag.Reason, "syspolicyd.state=alert") || f.flag.HostWatchPID != w.pid {
		t.Fatalf("flag not set: %+v", f.flag)
	}
	if len(f.notes) == 0 || len(f.posts) != 0 {
		t.Fatalf("degraded: notes=%v posts=%v (a2a must wait)", f.notes, f.posts)
	}
	f.mu.Lock()
	f.svc = serviceState{State: "running", Runs: 3, PID: 9}
	f.mu.Unlock()
	step(t, w, t0.Add(30*time.Second)) // healthy since now
	step(t, w, t0.Add(45*time.Second)) // healthy: queued notice goes out now
	if len(f.posts) != 1 || !strings.Contains(f.posts[0], "syspolicyd-2026-11-10-212821.ips") || !strings.Contains(f.posts[0], "kickstart") {
		t.Fatalf("posts after recovery: %v", f.posts)
	}
	if f.flag == nil {
		t.Fatal("flag cleared before clear-after")
	}
	step(t, w, t0.Add(11*time.Minute))
	if f.flag != nil {
		t.Fatalf("flag still set after clear-after: %+v", f.flag)
	}
	step(t, w, t0.Add(12*time.Minute))
	all := strings.Join(f.posts, "\n")
	if strings.Count(all, "syspolicyd-2026-11-10-212821.ips") != 1 || !strings.Contains(all, "CLEARED") {
		t.Fatalf("posts: %v", f.posts)
	}
}

// A hung exec probe is never stacked: one probe at most, and it alerts as stuck after the timeout.
func TestHungProbeNotStacked(t *testing.T) {
	f := newFake()
	f.block = make(chan struct{})
	var calls int
	sys := f.system()
	inner := sys.execProbe
	sys.execProbe = func(ctx context.Context) (time.Duration, time.Duration, error) {
		f.mu.Lock()
		calls++
		f.mu.Unlock()
		return inner(ctx)
	}
	dir := t.TempDir()
	w := newWatcher(options{stateDir: filepath.Join(dir, "s"), flagPath: filepath.Join(dir, "f"), postTimeout: time.Second, probeEvery: time.Second, clearAfter: time.Minute}, sys)
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
	if len(f.posts) != 0 {
		t.Fatalf("posted while exec degraded: %v", f.posts)
	}
	close(f.block)
	w.wg.Wait()
}

// A slow non-Apple exec alerts only when the Apple control is fast; a generally slow host only warns.
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

// At most one a2a post is outstanding; a failed post keeps the batch pending without duplicates.
func TestSinglePostOutstandingAndRetry(t *testing.T) {
	f := newFake()
	f.postHang = make(chan struct{})
	w := newTestWatcher(t, f)
	step2 := func(at time.Time) {
		if err := w.tick(at); err != nil {
			t.Fatal(err)
		}
	}
	step2(t0)
	f.mu.Lock()
	f.disk = 4 // alert-only resource check: does not degrade, so a2a is allowed
	f.mu.Unlock()
	step2(t0.Add(15 * time.Second))
	f.mu.Lock()
	f.fsev = "fseventsd watchdog LaunchAgent is disabled"
	f.mu.Unlock()
	step2(t0.Add(30 * time.Second)) // second alert while the first post hangs: no second post starts
	f.mu.Lock()
	f.postErr = errors.New("a2a failed")
	f.mu.Unlock()
	close(f.postHang)
	w.wg.Wait()
	f.mu.Lock()
	f.postHang, f.postErr = nil, nil
	f.mu.Unlock()
	step(t, w, t0.Add(45*time.Second))
	step(t, w, t0.Add(60*time.Second))
	if len(f.posts) != 1 {
		t.Fatalf("posts: %v", f.posts)
	}
	p := f.posts[0]
	if strings.Count(p, "disk.free") != 1 || strings.Count(p, "fseventsd.watchdog") != 1 {
		t.Fatalf("batch: %q", p)
	}
	s, _ := w.load()
	if len(s.Pending) != 0 || f.flag != nil {
		t.Fatalf("pending=%v flag=%v", s.Pending, f.flag)
	}
}

// A new host-tool crash report with a code-signing termination is named as such; old reports never re-alert.
func TestToolCodesignReport(t *testing.T) {
	f := newFake()
	dir := t.TempDir()
	p := filepath.Join(dir, "mac-firewall-2026-11-11-005046.ips")
	if err := os.WriteFile(p, []byte(`{"termination":{"namespace":"CODESIGNING","indicator":"Launch Constraint Violation"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w := newTestWatcher(t, f)
	step(t, w, t0)
	f.mu.Lock()
	f.reports = []report{{Name: filepath.Base(p), Path: p, Class: "tool"}}
	f.mu.Unlock()
	step(t, w, t0.Add(15*time.Second))
	step(t, w, t0.Add(30*time.Second))
	all := strings.Join(f.notes, "\n")
	if strings.Count(all, "mac-firewall-2026-11-11-005046.ips (CODESIGNING)") != 1 || f.flag != nil {
		t.Fatalf("notes=%v flag=%v", f.notes, f.flag)
	}
}

// Report files are classified by name; unrelated reports are ignored and Retired is scanned.
func TestListReports(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "Retired"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"syspolicyd-a.ips", "WindowServer-2026.ips", "WindowServer_x.spin", "mac-firewall-b.ips", "Claude_x.diag", "cat-1.ips", "Retired/syspolicyd-r.ips"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := listReports([]string{dir}, []string{"mac-firewall", "host-watch"})
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]int{}
	for _, r := range got {
		classes[r.Class]++
	}
	if len(got) != 5 || classes["syspolicyd"] != 2 || classes["gui"] != 2 || classes["tool"] != 1 {
		t.Fatalf("got %+v", got)
	}
}

// The flag file follows the written contract: JSON with reason, since and host_watch_pid; removal is idempotent.
func TestDegradedFlagContract(t *testing.T) {
	p := filepath.Join(t.TempDir(), "host-health", "exec-degraded")
	if err := writeDegradedFlag(p, degradedFlag{Reason: "syspolicyd.state=alert", Since: "2026-11-10T21:08:17Z", HostWatchPID: 42}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m["reason"] != "syspolicyd.state=alert" || m["since"] != "2026-11-10T21:08:17Z" || m["host_watch_pid"] != float64(42) || len(m) != 3 {
		t.Fatalf("flag %s %v", raw, err)
	}
	if err := removeDegradedFlag(p); err != nil {
		t.Fatal(err)
	}
	if err := removeDegradedFlag(p); err != nil {
		t.Fatal("second removal failed")
	}
}

// Every required flag is enforced; there are no implicit defaults.
func TestValidate(t *testing.T) {
	err := (options{}).validate()
	if err == nil || !strings.Contains(err.Error(), "--probe-every") || !strings.Contains(err.Error(), "--degraded-flag") {
		t.Fatalf("empty options: %v", err)
	}
	ok := options{reportsDirs: []string{"/r"}, toolPrefixes: []string{"mac-firewall"}, stateDir: "/s", flagPath: "/f", a2a: "/a", as: "x", room: "!r", to: "y", dataVolume: "/d", fseventsLabel: "l", interval: time.Second, probeEvery: time.Second, postTimeout: time.Second, clearAfter: time.Second}
	if err := ok.validate(); err != nil {
		t.Fatal(err)
	}
	ok.a2a = "a2a"
	if err := ok.validate(); err == nil {
		t.Fatal("relative a2a accepted")
	}
}
