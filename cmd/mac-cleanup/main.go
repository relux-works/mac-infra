package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/cleanup"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var errFullDiskAccessRunnerNotImplemented = errors.New("not implemented: dedicated Full Disk Access runner is not implemented; granting Full Disk Access to Terminal, iTerm2, Cursor, VS Code, or another broad launcher is too risky because every process launched from it may inherit that access")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 2
	}

	switch args[0] {
	case "scan":
		return runPlanCommand(cleanup.PlanSourceScan, args[1:], stdout, stderr)
	case "target":
		return runPlanCommand(cleanup.PlanSourceTarget, args[1:], stdout, stderr)
	case "xcode":
		return runPlanCommand(cleanup.PlanSourceXcode, args[1:], stdout, stderr)
	case "permissions":
		return runPermissionsCommand(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-cleanup %s %s %s\n", Version, Commit, BuildDate)
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

func runPlanCommand(source cleanup.PlanSource, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(string(source), flag.ContinueOnError)
	fs.SetOutput(stderr)
	category := fs.String("category", "", "limit planning to one cleanup category ID")
	jsonPath := fs.String("json", "", "write versioned Plan JSON to PATH; use --json without PATH for .temp/mac-cleanup/<command>-plan.json")
	homeDir := fs.String("home", "", "home directory override for deterministic planning")
	largeFileBytes := fs.Int64("large-file-bytes", cleanup.DefaultLargeFileBytes, "minimum file size for target large-files review candidates")
	oldFileDays := fs.Int("old-file-days", int(cleanup.DefaultOldFileAge/(24*time.Hour)), "minimum age in days for target old-files review candidates")
	if err := fs.Parse(normalizeJSONFlag(args, defaultJSONPath(source))); err != nil {
		return 2
	}

	positionals := fs.Args()
	root := ""
	switch source {
	case cleanup.PlanSourceTarget:
		if len(positionals) != 1 {
			fmt.Fprintln(stderr, "target requires exactly one PATH")
			return 2
		}
		root = positionals[0]
	case cleanup.PlanSourceScan, cleanup.PlanSourceXcode:
		if len(positionals) != 0 {
			fmt.Fprintf(stderr, "%s does not accept positional paths\n", source)
			return 2
		}
	default:
		fmt.Fprintf(stderr, "unsupported command source %q\n", source)
		return 2
	}

	var categories []cleanup.CategoryID
	if strings.TrimSpace(*category) != "" {
		categories = []cleanup.CategoryID{cleanup.CategoryID(strings.TrimSpace(*category))}
	}
	result, err := buildPlanWithTimeout(cleanup.PlannerOptions{
		Source:         source,
		Root:           root,
		HomeDir:        *homeDir,
		CategoryIDs:    categories,
		LargeFileBytes: *largeFileBytes,
		OldFileAge:     time.Duration(*oldFileDays) * 24 * time.Hour,
	})
	if err != nil {
		fmt.Fprintf(stderr, "%s failed: %v\n", source, err)
		return 1
	}

	if strings.TrimSpace(*jsonPath) != "" {
		if err := cleanup.WritePlanArtifact(*jsonPath, result.Plan); err != nil {
			fmt.Fprintf(stderr, "%s failed: write json: %v\n", source, err)
			return 1
		}
		fmt.Fprintf(stdout, "json: %s\n", *jsonPath)
	}
	printPlanTable(stdout, result)
	return 0
}

func runPermissionsCommand(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("permissions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	openSettings := fs.Bool("open", false, "open macOS Full Disk Access settings")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "permissions does not accept positional paths")
		return 2
	}

	printPermissionsGuide(stdout)
	if *openSettings {
		if err := openFullDiskAccessSettings(); err != nil {
			fmt.Fprintf(stderr, "permissions --open failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "opened Full Disk Access settings")
	}
	return 0
}

func openFullDiskAccessSettings() error {
	// Intentionally disabled for now. Opening the Full Disk Access pane from a
	// terminal-launched CLI nudges the user toward granting access to a broad
	// launcher, which would also cover arbitrary child processes. The safer
	// future path is a dedicated narrow mac-infra runner/app.
	return errFullDiskAccessRunnerNotImplemented
}

func buildPlanWithTimeout(options cleanup.PlannerOptions) (cleanup.PlannerResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return cleanup.BuildPlan(ctx, options)
}

func normalizeJSONFlag(args []string, defaultPath string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--json" {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				out = append(out, arg)
			} else {
				out = append(out, "--json="+defaultPath)
			}
			continue
		}
		if arg == "--json=" {
			out = append(out, "--json="+defaultPath)
			continue
		}
		out = append(out, arg)
	}
	return out
}

func defaultJSONPath(source cleanup.PlanSource) string {
	return ".temp/mac-cleanup/" + string(source) + "-plan.json"
}

func printPlanTable(w io.Writer, result cleanup.PlannerResult) {
	fmt.Fprintf(w, "%-28s %-15s %-7s %12s %10s %10s  %s\n", "category", "risk", "default", "bytes", "candidates", "selected", "reason")
	for _, row := range result.Rows {
		fmt.Fprintf(
			w,
			"%-28s %-15s %-7s %12s %10d %10d  %s\n",
			row.ID,
			row.Risk,
			yesNo(row.DefaultSelected),
			formatBytes(row.LogicalBytes),
			row.CandidateCount,
			row.SelectedCount,
			row.Reason,
		)
	}
	fmt.Fprintf(
		w,
		"\ntotals: candidates=%d selected=%d logical=%s selectedLogical=%s\n",
		result.Plan.Totals.CandidateCount,
		result.Plan.Totals.SelectedCount,
		formatBytes(result.Plan.Totals.LogicalBytes),
		formatBytes(result.Plan.Totals.SelectedLogicalBytes),
	)
	printPlannerWarnings(w, result.Warnings)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: mac-cleanup <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  scan      plan allowlisted home cleanup categories")
	fmt.Fprintln(w, "  target    plan cleanup candidates under an explicit target path")
	fmt.Fprintln(w, "  xcode     plan Xcode cleanup candidates")
	fmt.Fprintln(w, "  permissions show Full Disk Access guidance")
	fmt.Fprintln(w, "  version   print version")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "scan/target/xcode are read-only planners; this binary has no deletion command.")
}

func printPermissionsGuide(w io.Writer) {
	fmt.Fprintln(w, "mac-cleanup can produce partial plans without Full Disk Access, but macOS may hide protected paths.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Security note:")
	fmt.Fprintln(w, "  Do not grant Full Disk Access to Terminal, iTerm2, Cursor, VS Code, or another broad launcher unless you accept that every process launched from it inherits that access.")
	fmt.Fprintln(w, "  Prefer partial scans until mac-infra has a dedicated narrow Full Disk Access runner.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "mac-cleanup permissions --open is intentionally not implemented until a dedicated narrow runner exists.")
}

func printPlannerWarnings(w io.Writer, warnings []cleanup.PlannerWarning) {
	if len(warnings) == 0 {
		return
	}
	fmt.Fprintf(w, "\nwarnings: %d path(s) skipped or partially measured because macOS denied access.\n", len(warnings))
	limit := len(warnings)
	if limit > 8 {
		limit = 8
	}
	for i := 0; i < limit; i++ {
		warning := warnings[i]
		fmt.Fprintf(w, "  %s: %s (%s)\n", warning.Operation, warning.Path, warning.Code)
	}
	if len(warnings) > limit {
		fmt.Fprintf(w, "  ... %d more\n", len(warnings)-limit)
	}
	fmt.Fprintln(w, "for security guidance:")
	fmt.Fprintln(w, "  mac-cleanup permissions")
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value := float64(bytes)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fPB", value/unit)
}
