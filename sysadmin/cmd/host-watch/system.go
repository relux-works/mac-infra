package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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
	reports     func() ([]report, error)
	ps          func(ctx context.Context) (string, error)
	pressure    func(ctx context.Context) (int, error)
	swap        func(ctx context.Context) (used, total float64, err error)
	diskFreePct func() (float64, error)
	fsevents    func(ctx context.Context) (string, error) // "" when enabled and loaded, else the problem
	execProbe   func(ctx context.Context) (probe, control time.Duration, err error)
	notify      func(ctx context.Context, text string) error
	post        func(ctx context.Context, text string) error
	writeFlag   func(path string, f degradedFlag) error
	removeFlag  func(path string) error
}

func liveSystem(o options, self string) system {
	run := func(ctx context.Context, bin string, args ...string) (string, error) {
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.WaitDelay = 2 * time.Second
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			return "", fmt.Errorf("%s: %w", filepath.Base(bin), ctx.Err())
		}
		if err != nil {
			return string(out), fmt.Errorf("%s: %w", filepath.Base(bin), err)
		}
		return string(out), nil
	}
	s := system{
		syspolicy: func(ctx context.Context) (serviceState, error) {
			out, err := run(ctx, launchctlPath, "print", syspolicyJob)
			if err != nil {
				return serviceState{}, err
			}
			return parseLaunchctl(out)
		},
		reports: func() ([]report, error) { return listReports(o.reportsDirs, o.toolPrefixes) },
		ps: func(ctx context.Context) (string, error) {
			return run(ctx, psPath, "-axo", "pid=,etime=,rss=,state=,comm=")
		},
		pressure: func(ctx context.Context) (int, error) {
			out, err := run(ctx, sysctlPath, "-n", "kern.memorystatus_vm_pressure_level")
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(strings.TrimSpace(out))
		},
		swap: func(ctx context.Context) (float64, float64, error) {
			out, err := run(ctx, sysctlPath, "-n", "vm.swapusage")
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
			out, err := run(ctx, launchctlPath, "print-disabled", fmt.Sprintf("gui/%d", os.Getuid()))
			if err != nil {
				return "", err
			}
			if strings.Contains(out, fmt.Sprintf("%q => disabled", o.fseventsLabel)) || strings.Contains(out, fmt.Sprintf("%q => true", o.fseventsLabel)) {
				return "fseventsd watchdog LaunchAgent is disabled", nil
			}
			if _, err := run(ctx, launchctlPath, "print", fmt.Sprintf("gui/%d/%s", os.Getuid(), o.fseventsLabel)); err != nil {
				return "fseventsd watchdog LaunchAgent is not loaded", nil
			}
			return "", nil
		},
		execProbe: func(ctx context.Context) (time.Duration, time.Duration, error) {
			t0 := time.Now()
			if _, err := run(ctx, truePath); err != nil {
				return 0, 0, fmt.Errorf("control: %w", err)
			}
			control := time.Since(t0)
			t1 := time.Now()
			_, err := run(ctx, self, "--probe-exec")
			return time.Since(t1), control, err
		},
		notify: func(ctx context.Context, text string) error {
			script := fmt.Sprintf("display notification %q with title %q", text, "host-watch")
			_, err := run(ctx, osascriptPath, "-e", script)
			return err
		},
		post: func(ctx context.Context, text string) error {
			_, err := run(ctx, o.a2a, "--as", o.as, "post", o.room, "--kind", "notice", "--to", o.to, text)
			return err
		},
		writeFlag:  writeDegradedFlag,
		removeFlag: removeDegradedFlag,
	}
	if !o.notify {
		s.notify = nil
	}
	if o.dryRun {
		s.notify, s.post = nil, nil
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

var swapRe = regexp.MustCompile(`total = ([0-9.]+)M\s+used = ([0-9.]+)M`)

// parseSwap reads `sysctl -n vm.swapusage` and returns used and total MiB.
func parseSwap(out string) (float64, float64, error) {
	m := swapRe.FindStringSubmatch(out)
	if m == nil {
		return 0, 0, fmt.Errorf("vm.swapusage: unexpected %q", strings.TrimSpace(out))
	}
	total, _ := strconv.ParseFloat(m[1], 64)
	used, _ := strconv.ParseFloat(m[2], 64)
	return used, total, nil
}

// report is one diagnostic report file and its class.
type report struct {
	Name, Path, Class string
}

type reportClass struct {
	class string
	re    *regexp.Regexp
}

var toolPrefixRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// reportClassesFor builds the report classes; toolPrefixes name the host tools whose crash reports alert.
func reportClassesFor(toolPrefixes []string) []reportClass {
	quoted := make([]string, len(toolPrefixes))
	for i, p := range toolPrefixes {
		quoted[i] = regexp.QuoteMeta(p)
	}
	return []reportClass{
		{"syspolicyd", regexp.MustCompile(`^syspolicyd-.*\.ips$`)},
		{"gui", regexp.MustCompile(`^WindowServer[-_].*\.(ips|spin|hang)$`)},
		{"tool", regexp.MustCompile(`^(` + strings.Join(quoted, "|") + `)-.*\.ips$`)},
	}
}

// listReports returns the classified reports in each dir and its Retired subdirectory, sorted by name.
func listReports(dirs, toolPrefixes []string) ([]report, error) {
	reportClasses := reportClassesFor(toolPrefixes)
	var out []report
	for _, base := range dirs {
		for _, d := range []string{base, filepath.Join(base, "Retired")} {
			entries, err := os.ReadDir(d)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) && d != base {
					continue
				}
				return nil, err
			}
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				for _, c := range reportClasses {
					if c.re.MatchString(e.Name()) {
						out = append(out, report{Name: e.Name(), Path: filepath.Join(d, e.Name()), Class: c.class})
						break
					}
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
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
// maxRSSKB, and not an OS binary. A held exec sits at _dyld_start with about 112 KB resident.
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
		if age < minAge || rss > maxRSSKB || strings.HasPrefix(f[3], "Z") {
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
