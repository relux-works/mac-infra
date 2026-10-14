// mac-security collects read-only host evidence; only explicit baseline capture
// writes a new private artifact. It never installs jobs or changes host policy.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/relux-works/mac-infra/internal/security"
	"io"
	"os"
	"runtime"
	"time"
)

var Version = "dev"
var Commit = "unknown"
var BuildDate = "unknown"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: mac-security scan|baseline|diff|version|help [--json] [--file PATH] [--ioc-file PATH]")
		return 2
	}
	command := args[0]
	if command == "help" || command == "--help" {
		fmt.Fprintln(out, "mac-security scan [--json] [--ioc-file PATH]\nmac-security baseline --file NEW_PATH [--json]\nmac-security diff --file BASELINE [--json]\nBaseline and diff compare persistence metadata/hashes only. Exit 0 completed (findings may exist), 1 operational, 2 usage.")
		return 0
	}
	if command == "version" {
		fmt.Fprintf(out, "mac-security %s %s %s\n", Version, Commit, BuildDate)
		return 0
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(errOut)
	asJSON := flags.Bool("json", false, "JSON to stdout; short summary to stderr")
	file := flags.String("file", "", "baseline path")
	iocFile := flags.String("ioc-file", "", "additional fixed-target IOC rules")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return 2
	}
	if command != "scan" && command != "baseline" && command != "diff" {
		fmt.Fprintln(errOut, "unknown command")
		return 2
	}
	if (command == "baseline" || command == "diff") && *file == "" || command == "scan" && *file != "" {
		fmt.Fprintln(errOut, "baseline/diff require --file; scan does not accept --file")
		return 2
	}
	rules := security.DefaultRules()
	if *iocFile != "" {
		extra, err := security.LoadRules(*iocFile)
		if err != nil {
			fmt.Fprintln(errOut, "invalid IOC file")
			return 2
		}
		rules, err = security.MergeRules(extra)
		if err != nil {
			fmt.Fprintln(errOut, "IOC rule IDs must be unique and total rules bounded")
			return 2
		}
	}
	var old security.Snapshot
	var err error
	if command == "diff" {
		old, err = security.LoadBaseline(*file)
		if err != nil {
			fmt.Fprintln(errOut, "cannot load valid baseline")
			return 1
		}
	}
	if runtime.GOOS != "darwin" {
		fmt.Fprintln(errOut, "mac-security requires macOS")
		return 1
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(errOut, "home unavailable")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runner := security.CommandRunner{}
	var snap security.Snapshot
	check := security.Observe(ctx, runner, func(ctx context.Context, r security.Runner) security.Check {
		var c security.Check
		snap, c = security.Persistence(ctx, r, home)
		return c
	})
	if command == "baseline" {
		snap.Evidence = &check
		if err := security.SaveBaseline(*file, snap); err != nil {
			fmt.Fprintln(errOut, err)
			return 1
		}
		return output(out, errOut, *asJSON, snap, "Private persistence baseline captured; inspect coverage before trusting comparisons.")
	}
	if command == "diff" {
		drift, err := security.Compare(old, snap)
		if err != nil {
			fmt.Fprintln(errOut, "cannot compare baseline")
			return 1
		}
		return output(out, errOut, *asJSON, drift, fmt.Sprintf("Persistence drift: %d added, %d changed, %d removed, %d sources unknown.", len(drift.Added), len(drift.Changed), len(drift.Removed), len(drift.Unknown)))
	}
	report := security.Report{Schema: 1, GeneratedAt: time.Now().UTC(), Checks: []security.Check{check}, Persistence: snap}
	report.Checks = append(report.Checks, security.Exposure(ctx, runner)...)
	report.Checks = append(report.Checks, security.Posture(ctx, runner)...)
	report.Checks = append(report.Checks, security.Observe(ctx, runner, func(ctx context.Context, r security.Runner) security.Check { return security.SSH(ctx, r, home) }), security.Observe(ctx, runner, func(ctx context.Context, r security.Runner) security.Check { return security.IOC(ctx, r, rules) }))
	return output(out, errOut, *asJSON, report, security.Summary(report))
}
func output(out, errOut io.Writer, asJSON bool, value any, summary string) int {
	if asJSON {
		e := json.NewEncoder(out)
		e.SetIndent("", "  ")
		if e.Encode(value) != nil {
			return 1
		}
		fmt.Fprintln(errOut, summary)
	} else {
		fmt.Fprintln(out, summary)
	}
	return 0
}
