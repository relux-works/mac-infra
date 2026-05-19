package main

import (
	"context"
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
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: mac-cleanup <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  scan      plan allowlisted home cleanup categories")
	fmt.Fprintln(w, "  target    plan cleanup candidates under an explicit target path")
	fmt.Fprintln(w, "  xcode     plan Xcode cleanup candidates")
	fmt.Fprintln(w, "  version   print version")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "scan/target/xcode are read-only planners; this binary has no deletion command.")
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
