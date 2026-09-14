// Package fsevents diagnoses fseventsd bloat: the FSEvents daemon grows its
// resident memory when a slow consumer (for example the Colima inotify
// forwarder) cannot drain the event stream, and burns CPU when the file-event
// volume is high (git-heavy test loops, mass temp churn). It is read-only.
package fsevents

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/relux-works/mac-infra/internal/loadprofile"
)

const (
	DaemonPath = "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/FSEvents.framework/Versions/A/Support/fseventsd"

	DefaultRSSWarnBytes     int64 = 2 * 1024 * 1024 * 1024
	DefaultRSSCriticalBytes int64 = 4 * 1024 * 1024 * 1024
	DefaultCPUWarnPercent         = 50.0
	// DefaultTempBuildWarnBytes flags leftover go-build temp directories that
	// keep growing when test loops are killed mid-run.
	DefaultTempBuildWarnBytes int64 = 2 * 1024 * 1024 * 1024
)

type Verdict string

const (
	VerdictOK       Verdict = "ok"
	VerdictWarning  Verdict = "warning"
	VerdictCritical Verdict = "critical"
)

type Thresholds struct {
	RSSWarnBytes       int64
	RSSCriticalBytes   int64
	CPUWarnPercent     float64
	TempBuildWarnBytes int64
}

func DefaultThresholds() Thresholds {
	return Thresholds{
		RSSWarnBytes:       DefaultRSSWarnBytes,
		RSSCriticalBytes:   DefaultRSSCriticalBytes,
		CPUWarnPercent:     DefaultCPUWarnPercent,
		TempBuildWarnBytes: DefaultTempBuildWarnBytes,
	}
}

// Consumer is a process known to hold an FSEvents stream or to generate
// high file-event volume; both make fseventsd work harder.
type Consumer struct {
	Kind    string              `json:"kind"`
	Note    string              `json:"note,omitempty"`
	Process loadprofile.Process `json:"process"`
}

type ColimaProfile struct {
	Path         string   `json:"path"`
	MountInotify bool     `json:"mount_inotify"`
	Mounts       []string `json:"mounts"`
	Error        string   `json:"error,omitempty"`
}

type TempBuild struct {
	Dir   string `json:"dir"`
	Count int    `json:"count"`
	Bytes int64  `json:"bytes"`
	Error string `json:"error,omitempty"`
}

type Diagnostic struct {
	DaemonFound     bool                 `json:"daemon_found"`
	Daemon          *loadprofile.Process `json:"daemon,omitempty"`
	RSSBytes        int64                `json:"rss_bytes"`
	Consumers       []Consumer           `json:"consumers"`
	ColimaProfiles  []ColimaProfile      `json:"colima_profiles"`
	TempBuild       TempBuild            `json:"temp_build"`
	Thresholds      Thresholds           `json:"thresholds"`
	Verdict         Verdict              `json:"verdict"`
	Findings        []string             `json:"findings"`
	Recommendations []string             `json:"recommendations"`
}

// FindDaemon returns the fseventsd process. ps prints the full path as the
// command, so match on the basename to survive path or argument changes.
func FindDaemon(processes []loadprofile.Process) (loadprofile.Process, bool) {
	for _, process := range processes {
		command := strings.Fields(process.Command)
		if len(command) == 0 {
			continue
		}
		if filepath.Base(command[0]) == "fseventsd" {
			return process, true
		}
	}
	return loadprofile.Process{}, false
}

// Consumers picks out processes that are known FSEvents stream holders or
// known file-event generators. It is a heuristic allowlist, not a client list:
// fseventsd clients are not enumerable without root.
func Consumers(processes []loadprofile.Process) []Consumer {
	var consumers []Consumer
	for _, process := range processes {
		if kind, note, ok := classifyConsumer(process.Command); ok {
			consumers = append(consumers, Consumer{Kind: kind, Note: note, Process: process})
		}
	}
	sort.SliceStable(consumers, func(i, j int) bool {
		if consumers[i].Kind != consumers[j].Kind {
			return consumers[i].Kind < consumers[j].Kind
		}
		return consumers[i].Process.PID < consumers[j].Process.PID
	})
	return consumers
}

func classifyConsumer(command string) (kind, note string, ok bool) {
	lower := strings.ToLower(command)
	fields := strings.Fields(lower)
	if len(fields) == 0 {
		return "", "", false
	}
	base := filepath.Base(fields[0])
	switch {
	case base == "colima" && strings.Contains(lower, " daemon ") && strings.Contains(lower, "--inotify"):
		return "colima-inotify", "forwards every FSEvent under --inotify-dir into the VM; slow consumer", true
	case base == "mds_stores" || base == "mds":
		return "spotlight", "", true
	case base == "backupd":
		return "time-machine", "", true
	case base == "bird":
		return "icloud-drive", "", true
	case base == "git" && strings.Contains(lower, "fsmonitor--daemon"):
		return "git-fsmonitor", "", true
	case base == "watchman":
		return "watchman", "", true
	// App-bundle executables often live under paths with spaces
	// ("/Applications/Saby Center.app/.../sabycenter"), so match them on the
	// executable segment rather than on the whitespace-split first field.
	case hasExecutable(lower, "sabycenter"):
		return "saby-center", "third-party sync agent", true
	case hasExecutable(lower, "dropbox"):
		return "dropbox", "", true
	case hasExecutable(lower, "onedrive"):
		return "onedrive", "", true
	case hasExecutable(lower, "google drive") || hasExecutable(lower, "googledrive"):
		return "google-drive", "", true
	case hasExecutable(lower, "yandex.disk") || hasExecutable(lower, "yandexdisk"):
		return "yandex-disk", "", true
	case base == "go" && len(fields) > 1 && fields[1] == "test":
		return "go-test", "git/tmp-heavy test loops generate high event volume", true
	}
	return "", "", false
}

func hasExecutable(lowerCommand, name string) bool {
	return lowerCommand == name ||
		strings.HasSuffix(lowerCommand, "/"+name) ||
		strings.Contains(lowerCommand, "/"+name+" ")
}

// ScanColimaProfiles reads ~/.colima/*/colima.yaml with a line-oriented
// parser: the two keys of interest are top-level scalars/lists and a YAML
// dependency is not worth the surface.
func ScanColimaProfiles(homeDir string) []ColimaProfile {
	pattern := filepath.Join(homeDir, ".colima", "*", "colima.yaml")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}
	sort.Strings(matches)
	profiles := make([]ColimaProfile, 0, len(matches))
	for _, path := range matches {
		profiles = append(profiles, parseColimaProfile(path))
	}
	return profiles
}

func parseColimaProfile(path string) ColimaProfile {
	profile := ColimaProfile{Path: path, Mounts: []string{}}
	file, err := os.Open(path)
	if err != nil {
		profile.Error = err.Error()
		return profile
	}
	defer file.Close()
	profile.MountInotify, profile.Mounts, profile.Error = ParseColimaConfig(file)
	return profile
}

// ParseColimaConfig extracts mountInotify and mounts[].location from a Colima
// config stream. Unknown keys are ignored; a parse problem is reported, not
// guessed around.
func ParseColimaConfig(r io.Reader) (mountInotify bool, mounts []string, errText string) {
	mounts = []string{}
	scanner := bufio.NewScanner(r)
	inMounts := false
	sawMounts := false
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimRight(raw, " \t")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		if !indented {
			inMounts = false
			key, value, found := strings.Cut(trimmed, ":")
			if !found {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			switch key {
			case "mountInotify":
				mountInotify = value == "true"
			case "mounts":
				sawMounts = true
				inMounts = value == ""
			}
			continue
		}
		if !inMounts {
			continue
		}
		item := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
		key, value, found := strings.Cut(item, ":")
		if found && strings.TrimSpace(key) == "location" {
			mounts = append(mounts, strings.TrimSpace(value))
		}
	}
	if err := scanner.Err(); err != nil {
		return mountInotify, mounts, err.Error()
	}
	if !sawMounts {
		errText = "mounts key not found; Colima defaults to mounting $HOME"
	}
	return mountInotify, mounts, errText
}

// ScanTempBuild sizes go-build* leftovers under dir. It walks bounded to those
// directories only and never modifies anything.
func ScanTempBuild(dir string) TempBuild {
	result := TempBuild{Dir: dir}
	if strings.TrimSpace(dir) == "" {
		result.Error = "empty temp dir"
		return result
	}
	matches, err := filepath.Glob(filepath.Join(dir, "go-build*"))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	for _, match := range matches {
		info, err := os.Lstat(match)
		if err != nil || !info.IsDir() {
			continue
		}
		result.Count++
		_ = filepath.WalkDir(match, func(_ string, entry fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if entry.Type().IsRegular() {
				if info, err := entry.Info(); err == nil {
					result.Bytes += info.Size()
				}
			}
			return nil
		})
	}
	return result
}

func Analyze(processes []loadprofile.Process, colima []ColimaProfile, tempBuild TempBuild, thresholds Thresholds) Diagnostic {
	d := Diagnostic{
		Consumers:       Consumers(processes),
		ColimaProfiles:  colima,
		TempBuild:       tempBuild,
		Thresholds:      thresholds,
		Verdict:         VerdictOK,
		Findings:        []string{},
		Recommendations: []string{},
	}
	if colima == nil {
		d.ColimaProfiles = []ColimaProfile{}
	}
	if d.Consumers == nil {
		d.Consumers = []Consumer{}
	}

	daemon, found := FindDaemon(processes)
	d.DaemonFound = found
	if found {
		copyDaemon := daemon
		d.Daemon = &copyDaemon
		d.RSSBytes = daemon.RSSKB * 1024
	} else {
		d.addFinding(VerdictWarning, "fseventsd process not found in ps output")
	}

	switch {
	case found && d.RSSBytes >= thresholds.RSSCriticalBytes:
		d.addFinding(VerdictCritical, fmt.Sprintf("fseventsd rss %s is at or above the critical threshold %s",
			loadprofile.FormatBytes(d.RSSBytes), loadprofile.FormatBytes(thresholds.RSSCriticalBytes)))
		d.Recommendations = append(d.Recommendations,
			"restart fseventsd through the root daemon: mac-infra-core fseventsd-restart",
			"fseventsd does not release buffered memory on its own; only a restart or reboot reclaims it")
	case found && d.RSSBytes >= thresholds.RSSWarnBytes:
		d.addFinding(VerdictWarning, fmt.Sprintf("fseventsd rss %s is above the warning threshold %s",
			loadprofile.FormatBytes(d.RSSBytes), loadprofile.FormatBytes(thresholds.RSSWarnBytes)))
	}
	if found && daemon.CPU >= thresholds.CPUWarnPercent {
		d.addFinding(VerdictWarning, fmt.Sprintf("fseventsd cpu %.1f%% is above %.0f%%; a process is generating high file-event volume",
			daemon.CPU, thresholds.CPUWarnPercent))
		d.Recommendations = append(d.Recommendations,
			"do not renice or throttle fseventsd: a starved daemon drops events and every client rescans the volume")
	}

	for _, consumer := range d.Consumers {
		switch consumer.Kind {
		case "colima-inotify":
			d.addFinding(VerdictWarning, fmt.Sprintf("colima inotify forwarder pid %d is running (%s)", consumer.Process.PID, consumer.Note))
			d.Recommendations = append(d.Recommendations,
				"set mountInotify: false in ~/.colima/<profile>/colima.yaml, or narrow mounts: to the project directories, then colima restart")
		case "go-test":
			d.addFinding(VerdictOK, fmt.Sprintf("go test pid %d is running; expect fseventsd cpu while it spawns git and temp repos", consumer.Process.PID))
		}
	}

	for _, profile := range d.ColimaProfiles {
		if profile.MountInotify {
			d.addFinding(VerdictWarning, fmt.Sprintf("%s has mountInotify: true", profile.Path))
			if len(profile.Mounts) == 0 {
				d.addFinding(VerdictWarning, fmt.Sprintf("%s mounts the whole $HOME (mounts: [] or missing); inotify watches everything under it", profile.Path))
			}
			d.Recommendations = append(d.Recommendations,
				"colima: disable mountInotify unless a container needs host file events; if it does, list only those directories under mounts:")
		}
	}

	if d.TempBuild.Error == "" && d.TempBuild.Bytes >= thresholds.TempBuildWarnBytes {
		d.addFinding(VerdictWarning, fmt.Sprintf("%d go-build leftover dirs use %s under %s",
			d.TempBuild.Count, loadprofile.FormatBytes(d.TempBuild.Bytes), d.TempBuild.Dir))
		d.Recommendations = append(d.Recommendations,
			"remove go-build* leftovers that belong to finished or killed test runs (mac-infra never deletes them for you)")
	}

	d.Recommendations = dedupe(d.Recommendations)
	return d
}

func (d *Diagnostic) addFinding(level Verdict, text string) {
	d.Findings = append(d.Findings, fmt.Sprintf("%s: %s", level, text))
	if rank(level) > rank(d.Verdict) {
		d.Verdict = level
	}
}

func rank(v Verdict) int {
	switch v {
	case VerdictCritical:
		return 2
	case VerdictWarning:
		return 1
	default:
		return 0
	}
}

func dedupe(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func PrintDiagnostic(w io.Writer, d Diagnostic) {
	fmt.Fprintf(w, "verdict: %s\n", d.Verdict)
	if d.DaemonFound && d.Daemon != nil {
		fmt.Fprintf(w, "fseventsd_pid: %d\n", d.Daemon.PID)
		fmt.Fprintf(w, "fseventsd_rss: %s\n", loadprofile.FormatBytes(d.RSSBytes))
		fmt.Fprintf(w, "fseventsd_cpu: %.1f%%\n", d.Daemon.CPU)
		fmt.Fprintf(w, "fseventsd_elapsed: %s\n", d.Daemon.Elapsed)
	} else {
		fmt.Fprintln(w, "fseventsd_pid: not-found")
	}
	fmt.Fprintf(w, "thresholds: rss_warn=%s rss_critical=%s cpu_warn=%.0f%%\n",
		loadprofile.FormatBytes(d.Thresholds.RSSWarnBytes),
		loadprofile.FormatBytes(d.Thresholds.RSSCriticalBytes),
		d.Thresholds.CPUWarnPercent)

	fmt.Fprintf(w, "\nconsumers: %d\n", len(d.Consumers))
	for _, consumer := range d.Consumers {
		fmt.Fprintf(w, "- %s pid=%d cpu=%.1f%% rss=%s elapsed=%s\n",
			consumer.Kind, consumer.Process.PID, consumer.Process.CPU,
			loadprofile.FormatBytes(consumer.Process.RSSKB*1024), consumer.Process.Elapsed)
	}

	fmt.Fprintf(w, "\ncolima_profiles: %d\n", len(d.ColimaProfiles))
	for _, profile := range d.ColimaProfiles {
		mounts := "$HOME (default)"
		if len(profile.Mounts) > 0 {
			mounts = strings.Join(profile.Mounts, ", ")
		}
		fmt.Fprintf(w, "- %s mountInotify=%t mounts=%s\n", profile.Path, profile.MountInotify, mounts)
		if profile.Error != "" {
			fmt.Fprintf(w, "  note: %s\n", profile.Error)
		}
	}

	if d.TempBuild.Error != "" {
		fmt.Fprintf(w, "\ntemp_build: %s (%s)\n", d.TempBuild.Dir, d.TempBuild.Error)
	} else {
		fmt.Fprintf(w, "\ntemp_build: %d go-build dirs, %s under %s\n",
			d.TempBuild.Count, loadprofile.FormatBytes(d.TempBuild.Bytes), d.TempBuild.Dir)
	}

	fmt.Fprintf(w, "\nfindings: %d\n", len(d.Findings))
	for _, finding := range d.Findings {
		fmt.Fprintf(w, "- %s\n", finding)
	}
	fmt.Fprintf(w, "\nrecommendations: %d\n", len(d.Recommendations))
	for _, recommendation := range d.Recommendations {
		fmt.Fprintf(w, "- %s\n", recommendation)
	}
	fmt.Fprintln(w, "\nnote: fseventsd clients are not enumerable without root; consumers above are a known-pattern allowlist")
}
