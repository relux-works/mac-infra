package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/anyconnect"
	"github.com/relux-works/mac-infra/internal/fsevents"
	"github.com/relux-works/mac-infra/internal/loadprofile"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 2
	}

	switch args[0] {
	case "capture":
		return runCapture(args[1:], stdout, stderr)
	case "snapshot":
		return runSnapshot(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "tunnel":
		return runTunnel(args[1:], stdout, stderr)
	case "anyconnect":
		return runAnyConnect(args[1:], stdout, stderr)
	case "fsevents":
		return runFSEvents(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-load-profile %s %s %s\n", Version, Commit, BuildDate)
		return 0
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runCapture(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	topN := fs.Int("top", 20, "number of top processes to include in summary")
	query := fs.String("query", "", "optional process query to include in summary")
	includeLogs := fs.Bool("logs", false, "include recent load, memory pressure, thermal, and jetsam logs")
	artifactRoot := fs.String("artifact-dir", ".temp/mac-load-profile", "root directory for capture artifacts")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "capture failed: %v\n", err)
		return 1
	}
	processes = withoutProfilerProcess(processes)

	captureDir := filepath.Join(*artifactRoot, "capture-"+time.Now().UTC().Format("20060102T150405Z"))
	if err := os.MkdirAll(captureDir, 0o755); err != nil {
		fmt.Fprintf(stderr, "capture failed: create artifact dir: %v\n", err)
		return 1
	}

	summaryPath := filepath.Join(captureDir, "summary.txt")
	summaryFile, err := os.Create(summaryPath)
	if err != nil {
		fmt.Fprintf(stderr, "capture failed: create summary: %v\n", err)
		return 1
	}
	writeSummary(summaryFile, processes, *topN, *query)
	if err := summaryFile.Close(); err != nil {
		fmt.Fprintf(stderr, "capture failed: close summary: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "capture: %s\n", captureDir)
	fmt.Fprintf(stdout, "summary: %s\n", summaryPath)
	writeSummary(stdout, processes, *topN, *query)

	for _, command := range loadprofile.DefaultCaptureCommands(*includeLogs) {
		path := filepath.Join(captureDir, command.Filename)
		if err := runCaptureCommand(path, command); err != nil {
			if command.Optional {
				fmt.Fprintf(stdout, "warning: %s: %v\n", command.Name, err)
				continue
			}
			fmt.Fprintf(stderr, "capture failed: %s: %v\n", command.Name, err)
			return 1
		}
		fmt.Fprintf(stdout, "artifact: %s -> %s\n", command.Name, path)
	}
	return 0
}

func runSnapshot(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	topN := fs.Int("top", 15, "number of top processes to print")
	query := fs.String("query", "", "optional process query to include")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "snapshot failed: %v\n", err)
		return 1
	}
	processes = withoutProfilerProcess(processes)

	fmt.Fprintf(stdout, "processes: %d\n", len(processes))
	fmt.Fprintf(stdout, "total listed rss: %s\n", loadprofile.FormatBytes(loadprofile.TotalRSSKB(processes)*1024))

	fmt.Fprintln(stdout, "\n== top cpu ==")
	loadprofile.PrintTable(stdout, loadprofile.TopByCPU(processes, *topN))

	fmt.Fprintln(stdout, "\n== top memory ==")
	loadprofile.PrintTable(stdout, loadprofile.TopByRSS(processes, *topN))

	if strings.TrimSpace(*query) != "" {
		matches := loadprofile.Filter(processes, *query)
		fmt.Fprintf(stdout, "\n== matches: %s ==\n", *query)
		printProcessSet(stdout, matches)
	}
	return 0
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	withChildren := fs.Bool("children", true, "include descendant processes")
	sampleSeconds := fs.Int("sample", 0, "run sample(1) for each matched root process for N seconds")
	artifactDir := fs.String("artifact-dir", ".temp/mac-load-profile", "directory for sample artifacts")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	query := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if query == "" {
		fmt.Fprintln(stderr, "inspect requires a pid or process query")
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "inspect failed: %v\n", err)
		return 1
	}
	processes = withoutProfilerProcess(processes)

	roots := loadprofile.Filter(processes, query)
	if len(roots) == 0 {
		fmt.Fprintf(stdout, "no processes matched %q\n", query)
		return 0
	}

	visible := roots
	if *withChildren {
		visible = loadprofile.WithDescendants(processes, roots)
	}

	fmt.Fprintf(stdout, "matches: %d root process(es)\n", len(roots))
	fmt.Fprintf(stdout, "included rss: %s\n", loadprofile.FormatBytes(loadprofile.TotalRSSKB(visible)*1024))
	fmt.Fprintf(stdout, "included cpu: %.1f%%\n", loadprofile.TotalCPU(visible))
	printProcessSet(stdout, visible)

	if *sampleSeconds > 0 {
		if err := runSamples(stdout, roots, *sampleSeconds, *artifactDir); err != nil {
			fmt.Fprintf(stderr, "sample failed: %v\n", err)
			return 1
		}
	}
	return 0
}

func runTunnel(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tunnel", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sampleSeconds := fs.Int("sample", 0, "run sample(1) for hot tunnel root processes for N seconds")
	artifactDir := fs.String("artifact-dir", ".temp/mac-load-profile", "directory for sample artifacts")
	hotCPU := fs.Float64("hot-cpu", 50, "CPU percentage threshold for hot tunnel processes")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "tunnel profile failed: %v\n", err)
		return 1
	}
	processes = withoutProfilerProcess(processes)

	roots := loadprofile.FilterAny(processes, loadprofile.TunnelQueries())
	if len(roots) == 0 {
		fmt.Fprintln(stdout, "no tunnel-related processes matched")
		return 0
	}

	visible := loadprofile.WithDescendants(processes, roots)
	fmt.Fprintf(stdout, "tunnel processes: %d root process(es), %d including descendants\n", len(roots), len(visible))
	fmt.Fprintf(stdout, "tunnel rss: %s\n", loadprofile.FormatBytes(loadprofile.TotalRSSKB(visible)*1024))
	fmt.Fprintf(stdout, "tunnel cpu: %.1f%%\n", loadprofile.TotalCPU(visible))
	printProcessSet(stdout, visible)

	hot := hotProcesses(roots, *hotCPU)
	if len(hot) > 0 {
		fmt.Fprintf(stdout, "\n== hot tunnel roots >= %.1f%% cpu ==\n", *hotCPU)
		loadprofile.PrintTable(stdout, hot)
	}

	if *sampleSeconds > 0 {
		targets := hot
		if len(targets) == 0 {
			targets = roots
		}
		if err := runSamples(stdout, targets, *sampleSeconds, *artifactDir); err != nil {
			fmt.Fprintf(stderr, "sample failed: %v\n", err)
			return 1
		}
	}
	return 0
}

func runAnyConnect(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("anyconnect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	includeLogs := fs.Bool("logs", false, "include recent acsockext NetworkExtension log hints")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "anyconnect profile failed: %v\n", err)
		return 1
	}
	processes = withoutProfilerProcess(processes)

	vpnStatus, vpnStatusErr := runOptionalCommand(5*time.Second, "/opt/cisco/anyconnect/bin/vpn", "status")
	systemExtensions, systemExtensionsErr := runOptionalCommand(5*time.Second, "/usr/bin/systemextensionsctl", "list")
	logHints := ""
	logErr := ""
	if *includeLogs {
		logHints, logErr = runOptionalCommand(
			10*time.Second,
			"/usr/bin/log",
			"show",
			"--style",
			"compact",
			"--last",
			"5m",
			"--predicate",
			`process == "com.cisco.anyconnect.macos.acsockext" || eventMessage CONTAINS[c] "acsockext" || eventMessage CONTAINS[c] "NEFlow"`,
		)
	}

	statusErrText := vpnStatusErr
	if systemExtensionsErr != "" {
		statusErrText = strings.TrimSpace(statusErrText + "; systemextensionsctl: " + systemExtensionsErr)
	}
	if logErr != "" {
		statusErrText = strings.TrimSpace(statusErrText + "; log: " + logErr)
	}
	diagnostic := anyconnect.Analyze(processes, vpnStatus, statusErrText, systemExtensions, logHints)
	anyconnect.PrintDiagnostic(stdout, diagnostic)
	if !*includeLogs {
		fmt.Fprintln(stdout, "log_hints_note: pass --logs to include recent bounded acsockext/NEFlow log hints")
	}
	return 0
}

func runFSEvents(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fsevents", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaults := fsevents.DefaultThresholds()
	rssWarnGB := fs.Float64("rss-warn-gb", float64(defaults.RSSWarnBytes)/(1024*1024*1024), "fseventsd RSS warning threshold in GB")
	rssCriticalGB := fs.Float64("rss-critical-gb", float64(defaults.RSSCriticalBytes)/(1024*1024*1024), "fseventsd RSS critical threshold in GB")
	cpuWarn := fs.Float64("cpu-warn", defaults.CPUWarnPercent, "fseventsd CPU warning threshold in percent")
	tempDir := fs.String("temp-dir", os.TempDir(), "directory scanned for go-build* leftovers")
	asJSON := fs.Bool("json", false, "print the diagnostic as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *rssWarnGB <= 0 || *rssCriticalGB <= 0 || *rssCriticalGB < *rssWarnGB {
		fmt.Fprintln(stderr, "fsevents: thresholds must be positive and rss-critical-gb must be >= rss-warn-gb")
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "fsevents profile failed: %v\n", err)
		return 1
	}
	processes = withoutProfilerProcess(processes)

	thresholds := fsevents.Thresholds{
		RSSWarnBytes:       int64(*rssWarnGB * 1024 * 1024 * 1024),
		RSSCriticalBytes:   int64(*rssCriticalGB * 1024 * 1024 * 1024),
		CPUWarnPercent:     *cpuWarn,
		TempBuildWarnBytes: defaults.TempBuildWarnBytes,
	}
	home, _ := os.UserHomeDir()
	diagnostic := fsevents.Analyze(processes, fsevents.ScanColimaProfiles(home), fsevents.ScanTempBuild(*tempDir), thresholds)
	if *asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(diagnostic); err != nil {
			fmt.Fprintf(stderr, "fsevents profile failed: encode: %v\n", err)
			return 1
		}
		return 0
	}
	fsevents.PrintDiagnostic(stdout, diagnostic)
	return 0
}

func collectProcesses() ([]loadprofile.Process, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ps", loadprofile.PSArgs()...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("ps timed out")
	}
	if err != nil {
		return nil, fmt.Errorf("ps: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return loadprofile.ParsePS(out)
}

func runOptionalCommand(timeout time.Duration, name string, args ...string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))
	if ctx.Err() == context.DeadlineExceeded {
		return output, fmt.Sprintf("%s timed out after %s", name, timeout)
	}
	if err != nil {
		if output != "" {
			return output, fmt.Sprintf("%s: %v (%s)", name, err, output)
		}
		return output, fmt.Sprintf("%s: %v", name, err)
	}
	return output, ""
}

func runCaptureCommand(path string, command loadprofile.CaptureCommand) error {
	timeout := command.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, command.Executable, command.Args...)
	out, err := cmd.CombinedOutput()
	if writeErr := os.WriteFile(path, out, 0o644); writeErr != nil {
		return fmt.Errorf("write artifact: %w", writeErr)
	}
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("timed out after %s", timeout)
	}
	if err != nil {
		return fmt.Errorf("%w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func writeSummary(w io.Writer, processes []loadprofile.Process, topN int, query string) {
	fmt.Fprintf(w, "processes: %d\n", len(processes))
	fmt.Fprintf(w, "total listed rss: %s\n", loadprofile.FormatBytes(loadprofile.TotalRSSKB(processes)*1024))

	fmt.Fprintln(w, "\n== top cpu ==")
	loadprofile.PrintTable(w, loadprofile.TopByCPU(processes, topN))

	fmt.Fprintln(w, "\n== top memory ==")
	loadprofile.PrintTable(w, loadprofile.TopByRSS(processes, topN))

	if strings.TrimSpace(query) != "" {
		matches := loadprofile.Filter(processes, query)
		fmt.Fprintf(w, "\n== matches: %s ==\n", query)
		printProcessSet(w, matches)
	}
}

func runSamples(stdout io.Writer, processes []loadprofile.Process, seconds int, artifactDir string) error {
	if seconds <= 0 {
		return nil
	}
	if seconds > 30 {
		return fmt.Errorf("--sample is capped at 30 seconds")
	}
	if len(processes) > 5 {
		return fmt.Errorf("refusing to sample %d processes; narrow the query", len(processes))
	}
	if err := os.MkdirAll(artifactDir, 0o755); err != nil {
		return fmt.Errorf("create artifact dir: %w", err)
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	for _, process := range processes {
		path := filepath.Join(artifactDir, fmt.Sprintf("sample-%d-%s.txt", process.PID, timestamp))
		fmt.Fprintf(stdout, "sampling pid %d for %ds -> %s\n", process.PID, seconds, path)
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds+10)*time.Second)
		cmd := exec.CommandContext(ctx, "/usr/bin/sample", strconv.Itoa(process.PID), strconv.Itoa(seconds), "-file", path)
		out, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			return fmt.Errorf("sample pid %d: %w (%s)", process.PID, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func hotProcesses(processes []loadprofile.Process, threshold float64) []loadprofile.Process {
	var hot []loadprofile.Process
	for _, process := range processes {
		if process.CPU >= threshold {
			hot = append(hot, process)
		}
	}
	return loadprofile.TopByCPU(hot, len(hot))
}

func printProcessSet(stdout io.Writer, processes []loadprofile.Process) {
	if len(processes) == 0 {
		fmt.Fprintln(stdout, "none")
		return
	}
	var buf bytes.Buffer
	loadprofile.PrintTable(&buf, processes)
	_, _ = stdout.Write(buf.Bytes())
}

func withoutProfilerProcess(processes []loadprofile.Process) []loadprofile.Process {
	var filtered []loadprofile.Process
	selfPID := os.Getpid()
	parentPID := os.Getppid()
	for _, process := range processes {
		if process.PID == selfPID || process.PID == parentPID || process.PPID == parentPID {
			continue
		}
		if strings.Contains(process.Command, "mac-load-profile") {
			continue
		}
		filtered = append(filtered, process)
	}
	return filtered
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mac-load-profile captures read-only CPU and memory process profiles.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-load-profile capture [--top N] [--query TEXT] [--logs] [--artifact-dir DIR]")
	fmt.Fprintln(w, "  mac-load-profile snapshot [--top N] [--query TEXT]")
	fmt.Fprintln(w, "  mac-load-profile inspect [--children=true] [--sample SECONDS] PID_OR_QUERY")
	fmt.Fprintln(w, "  mac-load-profile tunnel [--hot-cpu PERCENT] [--sample SECONDS]")
	fmt.Fprintln(w, "  mac-load-profile anyconnect [--logs]")
	fmt.Fprintln(w, "  mac-load-profile fsevents [--json] [--rss-warn-gb N] [--rss-critical-gb N] [--cpu-warn PERCENT] [--temp-dir DIR]")
	fmt.Fprintln(w, "  mac-load-profile version")
}
