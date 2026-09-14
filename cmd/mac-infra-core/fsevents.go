package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/relux-works/mac-infra/internal/fsevents"
	"github.com/relux-works/mac-infra/internal/loadprofile"
	"github.com/relux-works/mac-infra/internal/maccore"
)

const bytesPerGB = 1024 * 1024 * 1024

func runFSEventsRestart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fseventsd-restart", flag.ContinueOnError)
	fs.SetOutput(stderr)
	force := fs.Bool("force", false, "restart even when fseventsd rss is below the threshold or the process is missing")
	thresholdGB := fs.Float64("threshold-gb", float64(fsevents.DefaultRSSCriticalBytes)/bytesPerGB, "rss threshold in GB below which the restart is refused")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *thresholdGB <= 0 {
		fmt.Fprintln(stderr, "fseventsd-restart: --threshold-gb must be positive")
		return 2
	}

	// Inspect locally first so a refusal never needs the root daemon.
	state, _, err := inspectFSEventsDaemon()
	if err != nil {
		fmt.Fprintf(stderr, "fseventsd-restart failed: %v\n", err)
		return 1
	}
	thresholdBytes := int64(*thresholdGB * bytesPerGB)
	if !*force {
		if !state.Found {
			fmt.Fprintln(stderr, "fseventsd-restart refused: fseventsd process not found; pass --force to kickstart anyway")
			return 1
		}
		if state.RSSBytes < thresholdBytes {
			fmt.Fprintf(stderr, "fseventsd-restart refused: rss %s is below threshold %s; pass --force to override\n",
				loadprofile.FormatBytes(state.RSSBytes), loadprofile.FormatBytes(thresholdBytes))
			return 1
		}
	}

	resp, err := restartFSEvents(maccore.DefaultServiceConfig(), *force, thresholdBytes)
	if err != nil {
		fmt.Fprintf(stderr, "fseventsd-restart failed: %v\n", err)
		if len(resp.Commands) > 0 {
			printCommandResults(stderr, resp.Commands)
		}
		return 1
	}
	fmt.Fprintln(stdout, "fseventsd-restart: applied")
	printCommandResults(stdout, resp.Commands)
	fmt.Fprintln(stdout, "note: FSEvents clients (Spotlight, Time Machine, Finder) resync after a restart; brief mds activity is expected")
	return 0
}

func runFSEventsWatchdog(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printFSEventsWatchdogUsage(stderr)
		return 2
	}
	switch args[0] {
	case "enable":
		return runFSEventsWatchdogEnable(args[1:], stdout, stderr)
	case "disable":
		cfg, err := watchdogConfig()
		if err != nil {
			fmt.Fprintf(stderr, "fseventsd-watchdog disable failed: %v\n", err)
			return 1
		}
		results, err := disableFSEventsWatchdog(cfg)
		if err != nil {
			fmt.Fprintf(stderr, "fseventsd-watchdog disable failed: %v\n", err)
			printCommandResults(stderr, results)
			return 1
		}
		return printFSEventsWatchdogStatusAfter("disable", cfg, results, stdout, stderr)
	case "status":
		cfg, err := watchdogConfig()
		if err != nil {
			fmt.Fprintf(stderr, "fseventsd-watchdog status failed: %v\n", err)
			return 1
		}
		status, err := inspectFSEventsWatchdog(cfg)
		printFSEventsWatchdogStatus(stdout, status)
		if err != nil {
			fmt.Fprintf(stderr, "fseventsd-watchdog status failed: %v\n", err)
			return 1
		}
		return 0
	case "help", "--help", "-h":
		printFSEventsWatchdogUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown fseventsd-watchdog command %q\n", args[0])
		printFSEventsWatchdogUsage(stderr)
		return 2
	}
}

func runFSEventsWatchdogEnable(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fseventsd-watchdog enable", flag.ContinueOnError)
	fs.SetOutput(stderr)
	defaults := maccore.DefaultFSEventsWatchdogSettings()
	thresholdGB := fs.Float64("threshold-gb", float64(defaults.RSSThresholdBytes)/bytesPerGB, "fseventsd rss threshold in GB")
	interval := fs.Duration("interval", defaults.Interval, "check interval (minimum 1m)")
	autoRestart := fs.Bool("auto-restart", false, "restart fseventsd through mac-infra-core when over threshold (default: notify only)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *thresholdGB <= 0 {
		fmt.Fprintln(stderr, "fseventsd-watchdog enable: --threshold-gb must be positive")
		return 2
	}
	cfg, err := watchdogConfig()
	if err != nil {
		fmt.Fprintf(stderr, "fseventsd-watchdog enable failed: %v\n", err)
		return 1
	}
	settings := maccore.FSEventsWatchdogSettings{
		RSSThresholdBytes: int64(*thresholdGB * bytesPerGB),
		Interval:          *interval,
		AutoRestart:       *autoRestart,
	}
	if settings.AutoRestart && !coreAvailable(maccore.DefaultServiceConfig()) {
		fmt.Fprintln(stderr, "fseventsd-watchdog enable failed: --auto-restart needs the mac-infra-core daemon; run `mac-infra-core install` first")
		return 1
	}
	results, err := enableFSEventsWatchdog(cfg, settings)
	if err != nil {
		fmt.Fprintf(stderr, "fseventsd-watchdog enable failed: %v\n", err)
		printCommandResults(stderr, results)
		return 1
	}
	return printFSEventsWatchdogStatusAfter("enable", cfg, results, stdout, stderr)
}

// runFSEventsCheck is the LaunchAgent entry point. It is not user-facing:
// thresholds and the restart choice come from the state file.
func runFSEventsCheck(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("_fseventsd-check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	statePath := fs.String("state", "", "watchdog state file path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := watchdogConfig()
	if err != nil {
		fmt.Fprintf(stderr, "fseventsd check failed: %v\n", err)
		return 1
	}
	if *statePath != "" {
		cfg.StatePath = *statePath
	}
	check, err := runFSEventsWatchdogCheck(cfg, maccore.DefaultServiceConfig(), time.Now())
	if err != nil {
		fmt.Fprintf(stderr, "fseventsd check failed: %v\n", err)
		return 1
	}
	printFSEventsWatchdogCheck(stdout, &check)
	if check.Error != "" {
		return 1
	}
	return 0
}

func watchdogConfig() (maccore.FSEventsWatchdogConfig, error) {
	binary, err := resolveExecutablePath()
	if err != nil {
		return maccore.FSEventsWatchdogConfig{}, err
	}
	return defaultFSEventsWatchdogConfig(binary)
}

func printFSEventsWatchdogStatusAfter(operation string, cfg maccore.FSEventsWatchdogConfig, results []maccore.CommandResult, stdout, stderr io.Writer) int {
	status, statusErr := inspectFSEventsWatchdog(cfg)
	printFSEventsWatchdogStatus(stdout, status)
	printCommandResults(stdout, results)
	if statusErr != nil {
		fmt.Fprintf(stderr, "fseventsd-watchdog %s applied but status failed: %v\n", operation, statusErr)
		return 1
	}
	return 0
}

func printFSEventsWatchdogStatus(w io.Writer, status maccore.FSEventsWatchdogStatus) {
	fmt.Fprintf(w, "fseventsd_watchdog: %s\n", status.State)
	fmt.Fprintf(w, "label: %s\n", status.Label)
	fmt.Fprintf(w, "plist: %s\n", status.PlistPath)
	fmt.Fprintf(w, "state: %s\n", status.StatePath)
	if status.Settings != nil {
		fmt.Fprintf(w, "threshold: %s\n", loadprofile.FormatBytes(status.Settings.RSSThresholdBytes))
		fmt.Fprintf(w, "interval: %s\n", status.Settings.Interval)
		fmt.Fprintf(w, "auto_restart: %t\n", status.Settings.AutoRestart)
	}
	printFSEventsWatchdogCheck(w, status.LastCheck)
	fmt.Fprintln(w, "session_scope: current-user")
}

func printFSEventsWatchdogCheck(w io.Writer, check *maccore.FSEventsWatchdogCheck) {
	if check == nil {
		fmt.Fprintln(w, "last_check: none")
		return
	}
	fmt.Fprintf(w, "last_check: %s\n", check.CheckedAt.Format(time.RFC3339))
	if check.Found {
		fmt.Fprintf(w, "fseventsd: pid=%d rss=%s cpu=%.1f%%\n", check.PID, loadprofile.FormatBytes(check.RSSBytes), check.CPU)
	} else {
		fmt.Fprintln(w, "fseventsd: not-found")
	}
	fmt.Fprintf(w, "over_limit: %t\n", check.OverLimit)
	fmt.Fprintf(w, "notified: %t\n", check.Notified)
	fmt.Fprintf(w, "restarted: %t\n", check.Restarted)
	if !check.LastNotify.IsZero() {
		fmt.Fprintf(w, "last_notify: %s\n", check.LastNotify.Format(time.RFC3339))
	}
	if !check.LastRestart.IsZero() {
		fmt.Fprintf(w, "last_restart: %s\n", check.LastRestart.Format(time.RFC3339))
	}
	if check.Error != "" {
		fmt.Fprintf(w, "check_error: %s\n", check.Error)
	}
}

func printFSEventsWatchdogUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core fseventsd-watchdog enable [--threshold-gb N] [--interval DURATION] [--auto-restart]")
	fmt.Fprintln(w, "  mac-infra-core fseventsd-watchdog disable")
	fmt.Fprintln(w, "  mac-infra-core fseventsd-watchdog status")
}
