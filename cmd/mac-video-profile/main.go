package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/loadprofile"
	"github.com/relux-works/mac-infra/internal/videoprofile"
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
	case "version":
		fmt.Fprintf(stdout, "mac-video-profile %s %s %s\n", Version, Commit, BuildDate)
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
	hotCPU := fs.Float64("hot-cpu", 0, "global CPU percentage threshold for hot video groups; 0 uses group defaults")
	query := fs.String("query", "", "optional process query to include in summary")
	includeLogs := fs.Bool("logs", false, "include recent WindowServer, display, GPU, Metal, and frame logs")
	artifactRoot := fs.String("artifact-dir", videoprofile.DefaultArtifactRoot, "root directory for capture artifacts")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "capture failed: %v\n", err)
		return 1
	}
	processes = withoutVideoProfilerProcess(processes)

	captureDir := videoprofile.CaptureDir(*artifactRoot, time.Now())
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
	writeSummary(summaryFile, processes, *topN, *hotCPU, *query)
	if err := summaryFile.Close(); err != nil {
		fmt.Fprintf(stderr, "capture failed: close summary: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "capture: %s\n", captureDir)
	fmt.Fprintf(stdout, "summary: %s\n", summaryPath)
	writeSummary(stdout, processes, *topN, *hotCPU, *query)

	for _, command := range videoprofile.DefaultCaptureCommands(*includeLogs) {
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

	if !*includeLogs {
		fmt.Fprintln(stdout, "log_hints_note: pass --logs to include recent bounded WindowServer/display/GPU/Metal/frame log hints")
	}
	return 0
}

func runSnapshot(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	topN := fs.Int("top", 15, "number of top processes to print")
	hotCPU := fs.Float64("hot-cpu", 0, "global CPU percentage threshold for hot video groups; 0 uses group defaults")
	query := fs.String("query", "", "optional process query to include")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	processes, err := collectProcesses()
	if err != nil {
		fmt.Fprintf(stderr, "snapshot failed: %v\n", err)
		return 1
	}
	processes = withoutVideoProfilerProcess(processes)
	writeSummary(stdout, processes, *topN, *hotCPU, *query)
	fmt.Fprintln(stdout, "capture_hint: mac-video-profile capture --logs")
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

func runCaptureCommand(path string, command videoprofile.CaptureCommand) error {
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

func writeSummary(w io.Writer, processes []loadprofile.Process, topN int, hotCPU float64, query string) {
	fmt.Fprintf(w, "processes: %d\n", len(processes))
	fmt.Fprintf(w, "total listed rss: %s\n", loadprofile.FormatBytes(loadprofile.TotalRSSKB(processes)*1024))

	fmt.Fprintln(w, "\n== video smoothness groups ==")
	summaries := videoprofile.SortSummariesByCPU(videoprofile.SummarizeGroups(processes, hotCPU))
	if len(summaries) == 0 {
		fmt.Fprintln(w, "none")
	} else {
		for _, summary := range summaries {
			threshold := hotCPU
			if threshold <= 0 {
				threshold = summary.Group.HotCPU
			}
			fmt.Fprintf(
				w,
				"%s: processes=%d cpu=%.1f%% rss=%s hot>=%0.1f%%=%d\n",
				summary.Group.Name,
				len(summary.Matches),
				summary.TotalCPU,
				loadprofile.FormatBytes(summary.TotalRSSB),
				threshold,
				len(summary.Hot),
			)
			fmt.Fprintf(w, "  %s\n", summary.Group.Description)
			if len(summary.Hot) > 0 {
				printProcessSet(w, summary.Hot)
			}
		}
	}

	fmt.Fprintln(w, "\n== top video/display suspects ==")
	printProcessSet(w, videoprofile.TopInteresting(processes, topN))

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

func printProcessSet(w io.Writer, processes []loadprofile.Process) {
	if len(processes) == 0 {
		fmt.Fprintln(w, "none")
		return
	}
	var buf bytes.Buffer
	loadprofile.PrintTable(&buf, processes)
	_, _ = w.Write(buf.Bytes())
}

func withoutVideoProfilerProcess(processes []loadprofile.Process) []loadprofile.Process {
	var filtered []loadprofile.Process
	selfPID := os.Getpid()
	parentPID := os.Getppid()
	for _, process := range processes {
		if process.PID == selfPID || process.PID == parentPID || process.PPID == parentPID {
			continue
		}
		if strings.Contains(process.Command, "mac-video-profile") {
			continue
		}
		filtered = append(filtered, process)
	}
	return filtered
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mac-video-profile captures read-only macOS video/display smoothness diagnostics.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-video-profile snapshot [--top N] [--hot-cpu PERCENT] [--query TEXT]")
	fmt.Fprintln(w, "  mac-video-profile capture [--top N] [--hot-cpu PERCENT] [--query TEXT] [--logs] [--artifact-dir DIR]")
	fmt.Fprintln(w, "  mac-video-profile version")
}
