package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Apple binaries only: these keep working while execs of non-Apple code are held.
const (
	launchctlPath = "/bin/launchctl"
	osascriptPath = "/usr/bin/osascript"
	psPath        = "/bin/ps"
	sysctlPath    = "/usr/sbin/sysctl"
	truePath      = "/usr/bin/true"
	syspolicyJob  = "system/com.apple.security.syspolicy"
)

// system is every observation and side channel host-watch uses; tests replace it.
type system struct {
	syspolicy   func(ctx context.Context) (serviceState, error)
	reports     func() ([]report, map[string]error)
	ps          func(ctx context.Context) (string, error)
	pressure    func(ctx context.Context) (int, error)
	swap        func(ctx context.Context) (used, total float64, err error)
	diskFreePct func() (float64, error)
	fsevents    func(ctx context.Context) (string, error) // "" when enabled and loaded, else the problem
	execProbe   func(ctx context.Context) (probe, control time.Duration, err error)
	notify      func(ctx context.Context, text string) error
	post        func(ctx context.Context, text string) error
	flagPresent func(path string) bool
	writeFlag   func(path string, f degradedFlag) error
	removeFlag  func(path string) error
}

func liveSystem(o options, self string) system {
	r := newRunner()
	s := system{
		syspolicy: func(ctx context.Context) (serviceState, error) {
			out, err := r.run(ctx, "launchctl-syspolicy", launchctlPath, "print", syspolicyJob)
			if err != nil {
				return serviceState{}, err
			}
			return parseLaunchctl(out)
		},
		reports: func() ([]report, map[string]error) { return listReports(o.reportsDirs, o.toolPrefixes) },
		ps: func(ctx context.Context) (string, error) {
			return r.run(ctx, "ps", psPath, "-axo", "pid=,etime=,rss=,state=,comm=")
		},
		pressure: func(ctx context.Context) (int, error) {
			out, err := r.run(ctx, "sysctl-pressure", sysctlPath, "-n", "kern.memorystatus_vm_pressure_level")
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(strings.TrimSpace(out))
		},
		swap: func(ctx context.Context) (float64, float64, error) {
			out, err := r.run(ctx, "sysctl-swap", sysctlPath, "-n", "vm.swapusage")
			if err != nil {
				return 0, 0, err
			}
			return parseSwap(out)
		},
		diskFreePct: func() (float64, error) {
			var st syscall.Statfs_t
			if err := syscall.Statfs(o.dataVolume, &st); err != nil {
				return 0, err
			}
			if st.Blocks == 0 {
				return 0, errors.New("statfs: zero blocks")
			}
			return 100 * float64(st.Bavail) / float64(st.Blocks), nil
		},
		fsevents: func(ctx context.Context) (string, error) {
			out, err := r.run(ctx, "launchctl-disabled", launchctlPath, "print-disabled", fmt.Sprintf("gui/%d", os.Getuid()))
			if err != nil {
				return "", err
			}
			if strings.Contains(out, fmt.Sprintf("%q => disabled", o.fseventsLabel)) || strings.Contains(out, fmt.Sprintf("%q => true", o.fseventsLabel)) {
				return "fseventsd watchdog LaunchAgent is disabled", nil
			}
			if _, err := r.run(ctx, "launchctl-fsevents", launchctlPath, "print", fmt.Sprintf("gui/%d/%s", os.Getuid(), o.fseventsLabel)); err != nil {
				if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errChildHeld) {
					return "", err
				}
				return "fseventsd watchdog LaunchAgent is not loaded", nil
			}
			return "", nil
		},
		execProbe: func(ctx context.Context) (time.Duration, time.Duration, error) {
			t0 := time.Now()
			if _, err := r.run(ctx, "probe-control", truePath); err != nil {
				return 0, time.Since(t0), fmt.Errorf("control: %w", err)
			}
			control := time.Since(t0)
			t1 := time.Now()
			_, err := r.run(ctx, "probe-exec", self, "--probe-exec")
			return time.Since(t1), control, err
		},
		notify: func(ctx context.Context, text string) error {
			script := fmt.Sprintf("display notification %q with title %q", text, "host-watch")
			_, err := r.run(ctx, "osascript", osascriptPath, "-e", script)
			return err
		},
		post: func(ctx context.Context, text string) error {
			_, err := r.run(ctx, "a2a-post", o.a2a, "--as", o.as, "post", o.room, "--kind", "notice", "--to", o.to, text)
			return err
		},
		flagPresent: func(path string) bool { _, err := os.Lstat(path); return err == nil },
		writeFlag:   writeDegradedFlag,
		removeFlag:  removeDegradedFlag,
	}
	if !o.notify {
		s.notify = nil
	}
	if o.dryRun {
		s.notify, s.post = nil, nil
		s.flagPresent = func(string) bool { return false }
		s.writeFlag = func(string, degradedFlag) error { return nil }
		s.removeFlag = func(string) error { return nil }
	}
	return s
}

// serviceState is what launchctl reports for syspolicyd.
type serviceState struct {
	State string `json:"state"`
	Runs  int    `json:"runs"`
	PID   int    `json:"pid"`
}

// parseLaunchctl reads the top-level state, runs and pid of a `launchctl print` service dump.
// Only top-level keys (one leading tab) count; nested endpoint states are ignored.
func parseLaunchctl(out string) (serviceState, error) {
	var s serviceState
	seenState := false
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimPrefix(line, "\t"), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			s.State, seenState = v, true
		case "runs", "pid":
			n, err := strconv.Atoi(v)
			if err != nil {
				return s, fmt.Errorf("%s %q: %w", k, v, err)
			}
			if k == "runs" {
				s.Runs = n
			} else {
				s.PID = n
			}
		}
	}
	if !seenState {
		return s, errors.New("no top-level state in launchctl output")
	}
	return s, nil
}

var swapRe = regexp.MustCompile(`total = ([0-9]+(?:\.[0-9]+)?)M\s+used = ([0-9]+(?:\.[0-9]+)?)M`)

// parseSwap reads `sysctl -n vm.swapusage` and returns used and total MiB.
func parseSwap(out string) (float64, float64, error) {
	m := swapRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, fmt.Errorf("vm.swapusage: unexpected %q", strings.TrimSpace(out))
	}
	total, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("vm.swapusage total: %w", err)
	}
	used, err := strconv.ParseFloat(m[2], 64)
	if err != nil {
		return 0, 0, fmt.Errorf("vm.swapusage used: %w", err)
	}
	if used > total {
		return 0, 0, fmt.Errorf("vm.swapusage: used %.0fM above total %.0fM", used, total)
	}
	return used, total, nil
}

// report is one diagnostic report file, its class and the configured directory it came from.
type report struct {
	Name, Path, Class, Source string
}

type reportClass struct {
	class string
	re    *regexp.Regexp
}

var toolPrefixRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

const reportExt = `\.(ips|spin|hang)$`

// reportClassesFor builds the report classes; toolPrefixes name the host tools whose reports alert.
func reportClassesFor(toolPrefixes []string) []reportClass {
	quoted := make([]string, len(toolPrefixes))
	for i, p := range toolPrefixes {
		quoted[i] = regexp.QuoteMeta(p)
	}
	return []reportClass{
		{"syspolicyd", regexp.MustCompile(`^syspolicyd[-_].*` + reportExt)},
		{"gui", regexp.MustCompile(`^WindowServer[-_].*` + reportExt)},
		{"tool", regexp.MustCompile(`^(` + strings.Join(quoted, "|") + `)[-_].*` + reportExt)},
	}
}

// reportSources lists the scanned directories: each configured directory and its Retired
// subdirectory, each a source with its own error and its own first-scan seeding.
func reportSources(dirs []string) []string {
	var out []string
	for _, base := range dirs {
		out = append(out, base, filepath.Join(base, "Retired"))
	}
	return out
}

// listReports scans every source. A source that cannot be read, or a Retired path that is not a
// directory, is reported in the error map; the results of every other source are kept. A missing
// Retired directory is not an error.
func listReports(dirs, toolPrefixes []string) ([]report, map[string]error) {
	classes := reportClassesFor(toolPrefixes)
	var out []report
	errs := map[string]error{}
	for i, d := range reportSources(dirs) {
		retired := i%2 == 1
		fi, err := os.Lstat(d)
		if err != nil {
			if !(retired && errors.Is(err, os.ErrNotExist)) {
				errs[d] = err
			}
			continue
		}
		if !fi.IsDir() {
			errs[d] = fmt.Errorf("%s is not a directory", d)
			continue
		}
		entries, err := os.ReadDir(d)
		if err != nil {
			errs[d] = err
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			for _, c := range classes {
				if c.re.MatchString(e.Name()) {
					out = append(out, report{Name: e.Name(), Path: filepath.Join(d, e.Name()), Class: c.class, Source: d})
					break
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, errs
}

// reportIsCodesign tells whether a crash report records a code-signing termination.
func reportIsCodesign(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(raw), `"namespace":"CODESIGNING"`)
}

// applePrefixes are binary locations of the OS itself; a stuck exec there is not this class.
var applePrefixes = []string{"/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"}

// countStuckExecs counts processes that look held at exec: older than minAge, resident at most
// maxRSSKB, and with a known absolute binary path outside the OS directories. A held exec sits at
// _dyld_start with a footprint of about 112 KB; the RSS threshold is not yet calibrated against a
// real stall. Rows without an absolute path (a bare argv[0], or a name ps prints in parentheses
// because the arguments are unavailable) are not counted: their location is unknown.
func countStuckExecs(psOut string, minAge time.Duration, maxRSSKB int) (int, error) {
	n := 0
	for _, line := range strings.Split(psOut, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		age, err := parseEtime(f[1])
		if err != nil {
			return 0, fmt.Errorf("ps etime %q: %w", f[1], err)
		}
		rss, err := strconv.Atoi(f[2])
		if err != nil {
			return 0, fmt.Errorf("ps rss %q: %w", f[2], err)
		}
		comm := strings.Join(f[4:], " ")
		if age < minAge || rss > maxRSSKB || strings.HasPrefix(f[3], "Z") || !strings.HasPrefix(comm, "/") {
			continue
		}
		apple := false
		for _, p := range applePrefixes {
			if strings.HasPrefix(comm, p) {
				apple = true
				break
			}
		}
		if !apple {
			n++
		}
	}
	return n, nil
}

// parseEtime parses ps elapsed time: [[dd-]hh:]mm:ss.
func parseEtime(s string) (time.Duration, error) {
	days := 0
	if d, rest, ok := strings.Cut(s, "-"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, err
		}
		days, s = n, rest
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, errors.New("bad etime")
	}
	var nums []int
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, err
		}
		nums = append(nums, n)
	}
	h, m, sec := 0, nums[0], nums[1]
	if len(nums) == 3 {
		h, m, sec = nums[0], nums[1], nums[2]
	}
	return time.Duration(((days*24+h)*60+m)*60+sec) * time.Second, nil
}
