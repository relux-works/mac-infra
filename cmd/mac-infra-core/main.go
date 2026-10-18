package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/mac-infra/internal/maccore"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var (
	inspectService                = maccore.InspectService
	installService                = maccore.InstallService
	inspectSleepPrevention        = maccore.InspectSleepPrevention
	inspectDisplaySleepPrevention = maccore.InspectDisplaySleepPrevention
	inspectIdleLockPrevention     = maccore.InspectIdleLockPrevention
	requestSudoCredentials        = maccore.RequestSudoCredentials
	cleanupAnyConnect             = maccore.CleanupAnyConnect
	enableSleepPrevention         = maccore.EnableSleepPrevention
	disableSleepPrevention        = maccore.DisableSleepPrevention
	enableDisplaySleepPrevention  = maccore.EnableDisplaySleepPrevention
	disableDisplaySleepPrevention = maccore.DisableDisplaySleepPrevention
	enableIdleLockPrevention      = maccore.EnableIdleLockPrevention
	disableIdleLockPrevention     = maccore.DisableIdleLockPrevention
	inspectFSEventsDaemon         = maccore.InspectFSEventsDaemon
	restartFSEvents               = maccore.RestartFSEvents
	inspectFSEventsWatchdog       = maccore.InspectFSEventsWatchdog
	enableFSEventsWatchdog        = maccore.EnableFSEventsWatchdog
	disableFSEventsWatchdog       = maccore.DisableFSEventsWatchdog
	runFSEventsWatchdogCheck      = maccore.RunFSEventsWatchdogCheck
	defaultFSEventsWatchdogConfig = maccore.DefaultFSEventsWatchdogConfig
	coreAvailable                 = maccore.Available
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
	case "_vpn-core-source":
		return maccore.RunVPNCoreSource(args[1:], stdout, stderr)
	case "vpn-core":
		return runVPNCore(args[1:], stdout, stderr)
	case "install":
		return runInstall(args[1:], stdout, stderr)
	case "install-digest":
		return runInstallDigest(args[1:], stdout, stderr)
	case "uninstall":
		return runUninstall(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "request-permissions":
		return runRequestPermissions(args[1:], stdout, stderr)
	case "anyconnect-cleanup":
		return runAnyConnectCleanup(args[1:], stdout, stderr)
	case "sleep-prevention":
		return runSleepPrevention(args[1:], stdout, stderr)
	case "display-sleep-prevention":
		return runDisplaySleepPrevention(args[1:], stdout, stderr)
	case "idle-lock-prevention":
		return runIdleLockPrevention(args[1:], stdout, stderr)
	case "fseventsd-restart":
		return runFSEventsRestart(args[1:], stdout, stderr)
	case "fseventsd-watchdog":
		return runFSEventsWatchdog(args[1:], stdout, stderr)
	case "_fseventsd-check":
		return runFSEventsCheck(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-infra-core %s %s %s\n", Version, Commit, BuildDate)
		return 0
	case "_daemon":
		return runDaemon(args[1:], stderr)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runInstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(stderr)
	expected := fs.String("expect-sha256", "", "refuse to install unless the executable has this sha256 (from install-digest)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// A stray argument stops flag parsing and would silently drop a later
	// --expect-sha256; an empty value (an unset variable) would unpin.
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "install takes no arguments, got %q\n", fs.Args())
		return 2
	}
	pinned := false
	fs.Visit(func(f *flag.Flag) { pinned = pinned || f.Name == "expect-sha256" })
	if pinned && !isSHA256Hex(*expected) {
		fmt.Fprintf(stderr, "--expect-sha256 must be 64 hex characters, got %q\n", *expected)
		return 2
	}

	path, err := resolveExecutablePath()
	if err != nil {
		fmt.Fprintf(stderr, "install failed: %v\n", err)
		return 1
	}
	cfg := maccore.DefaultServiceConfig()
	options := maccore.InstallOptions{
		ExpectedSHA256: *expected,
		Announce: func(path, sha string, size int) {
			fmt.Fprintf(stdout, "installing: %s\nsha256: %s\nsize: %d bytes\n", path, sha, size)
		},
	}
	if err := installService(cfg, path, os.Getuid(), os.Getgid(), options); err != nil {
		fmt.Fprintf(stderr, "install failed: %v\n", err)
		return 1
	}

	status, err := maccore.InspectService(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "install failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "installed mac-infra-core")
	fmt.Fprintf(stdout, "socket: %s\n", status.SocketPath)
	fmt.Fprintf(stdout, "label: %s\n", status.Label)
	fmt.Fprintf(stdout, "plist: %s\n", status.PlistPath)
	return 0
}

// runInstallDigest shows, without privileges, exactly which bytes install
// would place in the root-owned helper directory.
func runInstallDigest(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("install-digest", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path, err := resolveExecutablePath()
	if err != nil {
		fmt.Fprintf(stderr, "install-digest failed: %v\n", err)
		return 1
	}
	digest, size, err := maccore.ReviewedExecutableDigest(path)
	if err != nil {
		fmt.Fprintf(stderr, "install-digest failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "executable: %s\nversion: %s %s %s\nsha256: %s\nsize: %d bytes\n", path, Version, Commit, BuildDate, digest, size)
	fmt.Fprintf(stdout, "install with: mac-infra-core install --expect-sha256 %s\n", digest)
	return 0
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

func runUninstall(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg := maccore.DefaultServiceConfig()
	if err := maccore.UninstallService(cfg); err != nil {
		fmt.Fprintf(stderr, "uninstall failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "uninstalled mac-infra-core")
	fmt.Fprintf(stdout, "socket: %s\n", cfg.SocketPath)
	fmt.Fprintf(stdout, "label: %s\n", cfg.Label)
	return 0
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	status, err := inspectService(maccore.DefaultServiceConfig())
	if err != nil {
		fmt.Fprintf(stderr, "status failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "label: %s\n", status.Label)
	fmt.Fprintf(stdout, "plist: %s\n", status.PlistPath)
	fmt.Fprintf(stdout, "socket: %s\n", status.SocketPath)
	if status.Reachable {
		fmt.Fprintln(stdout, "state: reachable")
		fmt.Fprintf(stdout, "daemon_pid: %d\n", status.DaemonPID)
	} else {
		fmt.Fprintln(stdout, "state: missing")
	}
	return 0
}

func runRequestPermissions(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("request-permissions", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		printRequestPermissionsUsage(stderr)
		return 2
	}

	permission := fs.Arg(0)
	switch permission {
	case "sudo":
		return runRequestSudoPermission(stdout, stderr)
	default:
		fmt.Fprintf(stderr, "unknown permission %q\n", permission)
		printRequestPermissionsUsage(stderr)
		return 2
	}
}

func runRequestSudoPermission(stdout, stderr io.Writer) int {
	if err := requestSudoCredentials(); err != nil {
		fmt.Fprintf(stderr, "request-permissions sudo failed: %v\n", err)
		return 1
	}

	cfg := maccore.DefaultServiceConfig()
	status, err := inspectService(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "request-permissions sudo failed: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "sudo: ready")
	fmt.Fprintln(stdout, "permission: sudo")
	fmt.Fprintln(stdout, "scope: mac-infra-core privileged setup/actions")
	fmt.Fprintln(stdout, "note: this does not grant Full Disk Access and does not grant anything to Terminal, iTerm2, Cursor, or VS Code.")
	fmt.Fprintf(stdout, "label: %s\n", cfg.Label)
	fmt.Fprintf(stdout, "plist: %s\n", cfg.PlistPath)
	fmt.Fprintf(stdout, "socket: %s\n", cfg.SocketPath)
	if status.Reachable {
		fmt.Fprintln(stdout, "state: reachable")
		fmt.Fprintf(stdout, "daemon_pid: %d\n", status.DaemonPID)
	} else {
		fmt.Fprintln(stdout, "state: missing")
		fmt.Fprintln(stdout, "next: mac-infra-core install")
	}
	return 0
}

func runAnyConnectCleanup(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("anyconnect-cleanup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "execute the cleanup through mac-infra-core")
	force := fs.Bool("force", false, "allow cleanup even when AnyConnect state is not confirmed disconnected")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if !*apply {
		fmt.Fprintln(stdout, "mode: dry-run")
		fmt.Fprintln(stdout, "refuse_if_connected: true")
		if *force {
			fmt.Fprintln(stdout, "force: true")
		}
		fmt.Fprintln(stdout, "actions:")
		fmt.Fprintln(stdout, "- verify AnyConnect state with /opt/cisco/anyconnect/bin/vpn status")
		fmt.Fprintln(stdout, "- terminate Cisco socket filter: /usr/bin/pkill -TERM -f com[.]cisco[.]anyconnect[.]macos[.]acsockext")
		fmt.Fprintln(stdout, "- restart AnyConnect agent: /bin/launchctl kickstart -k system/com.cisco.anyconnect.vpnagentd")
		fmt.Fprintln(stdout, "apply: mac-infra-core anyconnect-cleanup --apply")
		return 0
	}

	resp, err := cleanupAnyConnect(maccore.DefaultServiceConfig(), *force)
	if err != nil {
		fmt.Fprintf(stderr, "anyconnect-cleanup failed: %v\n", err)
		if len(resp.Commands) > 0 {
			printCommandResults(stderr, resp.Commands)
		}
		return 1
	}

	fmt.Fprintln(stdout, "anyconnect-cleanup: applied")
	printCommandResults(stdout, resp.Commands)
	return 0
}

func runSleepPrevention(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		printSleepPreventionUsage(stderr)
		return 2
	}

	switch args[0] {
	case "enable":
		return runSleepPreventionMutation(
			"enable",
			maccore.SleepPreventionStateEnabled,
			enableSleepPrevention,
			stdout,
			stderr,
		)
	case "disable":
		return runSleepPreventionMutation(
			"disable",
			maccore.SleepPreventionStateDisabled,
			disableSleepPrevention,
			stdout,
			stderr,
		)
	case "status":
		status, err := inspectSleepPrevention()
		printSleepPreventionStatus(stdout, status)
		if err != nil {
			fmt.Fprintf(stderr, "sleep-prevention status failed: %v\n", err)
			return 1
		}
		return 0
	case "help", "--help", "-h":
		printSleepPreventionUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown sleep-prevention command %q\n", args[0])
		printSleepPreventionUsage(stderr)
		return 2
	}
}

func runSleepPreventionMutation(
	operation string,
	state maccore.SleepPreventionState,
	call func(maccore.ServiceConfig) (maccore.Response, error),
	stdout, stderr io.Writer,
) int {
	resp, err := call(maccore.DefaultServiceConfig())
	if err != nil {
		fmt.Fprintf(stderr, "sleep-prevention %s failed: %v\n", operation, err)
		if len(resp.Commands) > 0 {
			printCommandResults(stderr, resp.Commands)
		}
		return 1
	}

	printSleepPreventionStatus(stdout, maccore.SleepPreventionStatus{
		State:     state,
		AppliesTo: maccore.SleepPreventionAppliesTo,
	})
	printCommandResults(stdout, resp.Commands)
	return 0
}

func runDisplaySleepPrevention(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		printDisplaySleepPreventionUsage(stderr)
		return 2
	}

	switch args[0] {
	case "enable":
		return runDisplaySleepPreventionMutation("enable", enableDisplaySleepPrevention, stdout, stderr)
	case "disable":
		return runDisplaySleepPreventionMutation("disable", disableDisplaySleepPrevention, stdout, stderr)
	case "status":
		status, err := inspectDisplaySleepPrevention()
		printDisplaySleepPreventionStatus(stdout, status)
		if err != nil {
			fmt.Fprintf(stderr, "display-sleep-prevention status failed: %v\n", err)
			return 1
		}
		return 0
	case "help", "--help", "-h":
		printDisplaySleepPreventionUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown display-sleep-prevention command %q\n", args[0])
		printDisplaySleepPreventionUsage(stderr)
		return 2
	}
}

func runDisplaySleepPreventionMutation(
	operation string,
	call func() ([]maccore.CommandResult, error),
	stdout, stderr io.Writer,
) int {
	results, err := call()
	if err != nil {
		fmt.Fprintf(stderr, "display-sleep-prevention %s failed: %v\n", operation, err)
		printCommandResults(stderr, results)
		return 1
	}

	status, statusErr := inspectDisplaySleepPrevention()
	printDisplaySleepPreventionStatus(stdout, status)
	printCommandResults(stdout, results)
	if statusErr != nil {
		fmt.Fprintf(stderr, "display-sleep-prevention %s applied but status failed: %v\n", operation, statusErr)
		return 1
	}
	return 0
}

func runIdleLockPrevention(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		printIdleLockPreventionUsage(stderr)
		return 2
	}

	switch args[0] {
	case "enable":
		return runIdleLockPreventionMutation("enable", enableIdleLockPrevention, stdout, stderr)
	case "disable":
		return runIdleLockPreventionMutation("disable", disableIdleLockPrevention, stdout, stderr)
	case "status":
		status, err := inspectIdleLockPrevention()
		printIdleLockPreventionStatus(stdout, status)
		if err != nil {
			fmt.Fprintf(stderr, "idle-lock-prevention status failed: %v\n", err)
			return 1
		}
		return 0
	case "help", "--help", "-h":
		printIdleLockPreventionUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown idle-lock-prevention command %q\n", args[0])
		printIdleLockPreventionUsage(stderr)
		return 2
	}
}

func runIdleLockPreventionMutation(
	operation string,
	call func() ([]maccore.CommandResult, error),
	stdout, stderr io.Writer,
) int {
	results, err := call()
	if err != nil {
		fmt.Fprintf(stderr, "idle-lock-prevention %s failed: %v\n", operation, err)
		printCommandResults(stderr, results)
		return 1
	}

	status, statusErr := inspectIdleLockPrevention()
	printIdleLockPreventionStatus(stdout, status)
	printCommandResults(stdout, results)
	if statusErr != nil {
		fmt.Fprintf(stderr, "idle-lock-prevention %s applied but status failed: %v\n", operation, statusErr)
		return 1
	}
	return 0
}

func runDaemon(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := maccore.DefaultServiceConfig()
	socketPath := fs.String("socket", cfg.SocketPath, "Unix socket path")
	clientUID := fs.Int("client-uid", os.Getuid(), "client uid for socket ownership")
	clientGID := fs.Int("client-gid", os.Getgid(), "client gid for socket ownership")
	binarySHA256 := fs.String("binary-sha256", "", "installed executable SHA-256")
	binaryID := fs.String("binary-id", "", "installed executable inode/creation time")
	plistID := fs.String("plist-id", "", "installed plist inode/creation time")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg.SocketPath = *socketPath
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "daemon does not accept positional arguments")
		return 2
	}
	trust := maccore.DaemonTrust{BinarySHA256: *binarySHA256, BinaryIdentity: *binaryID, PlistIdentity: *plistID}
	if err := maccore.RunDaemon(cfg, *clientUID, *clientGID, trust); err != nil {
		fmt.Fprintf(stderr, "daemon failed: %v\n", err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mac-infra-core manages the privileged macOS maintenance daemon.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core install-digest")
	fmt.Fprintln(w, "  mac-infra-core install [--expect-sha256 HEX]")
	fmt.Fprintln(w, "  mac-infra-core uninstall")
	fmt.Fprintln(w, "  mac-infra-core status")
	fmt.Fprintln(w, "  mac-infra-core request-permissions sudo")
	fmt.Fprintln(w, "  mac-infra-core anyconnect-cleanup [--apply] [--force]")
	fmt.Fprintln(w, "  mac-infra-core sleep-prevention enable|disable|status")
	fmt.Fprintln(w, "  mac-infra-core display-sleep-prevention enable|disable|status")
	fmt.Fprintln(w, "  mac-infra-core idle-lock-prevention enable|disable|status")
	fmt.Fprintln(w, "  mac-infra-core fseventsd-restart [--force] [--threshold-gb N]")
	fmt.Fprintln(w, "  mac-infra-core fseventsd-watchdog enable [--threshold-gb N] [--interval DURATION] [--auto-restart]")
	fmt.Fprintln(w, "  mac-infra-core fseventsd-watchdog disable|status")
	fmt.Fprintln(w, "  mac-infra-core vpn-core install --package DIR --expect-digest HEX")
	fmt.Fprintln(w, "  mac-infra-core vpn-core rollback --expect-digest HEX")
	fmt.Fprintln(w, "  mac-infra-core vpn-core status")
	fmt.Fprintln(w, "  mac-infra-core version")
}

func printRequestPermissionsUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core request-permissions sudo")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Available permissions:")
	fmt.Fprintln(w, "  sudo    cache sudo credentials for mac-infra-core privileged setup/actions")
}

func printSleepPreventionUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core sleep-prevention enable")
	fmt.Fprintln(w, "  mac-infra-core sleep-prevention disable")
	fmt.Fprintln(w, "  mac-infra-core sleep-prevention status")
}

func printDisplaySleepPreventionUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core display-sleep-prevention enable")
	fmt.Fprintln(w, "  mac-infra-core display-sleep-prevention disable")
	fmt.Fprintln(w, "  mac-infra-core display-sleep-prevention status")
}

func printIdleLockPreventionUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core idle-lock-prevention enable")
	fmt.Fprintln(w, "  mac-infra-core idle-lock-prevention disable")
	fmt.Fprintln(w, "  mac-infra-core idle-lock-prevention status")
}

func printSleepPreventionStatus(w io.Writer, status maccore.SleepPreventionStatus) {
	fmt.Fprintf(w, "sleep_prevention: %s\n", status.State)
	fmt.Fprintf(w, "applies_to: %s\n", status.AppliesTo)
}

func printDisplaySleepPreventionStatus(w io.Writer, status maccore.DisplaySleepPreventionStatus) {
	fmt.Fprintf(w, "display_sleep_prevention: %s\n", status.State)
	fmt.Fprintf(w, "applies_to: %s\n", status.AppliesTo)
	fmt.Fprintln(w, "assertion: PreventUserIdleDisplaySleep")
	fmt.Fprintln(w, "session_scope: current-user")
}

func printIdleLockPreventionStatus(w io.Writer, status maccore.IdleLockPreventionStatus) {
	fmt.Fprintf(w, "idle_lock_prevention: %s\n", status.State)
	if status.IdleTimePresent {
		fmt.Fprintf(w, "idle_time_seconds: %d\n", status.IdleTimeSeconds)
	} else if status.State != maccore.IdleLockPreventionStateUnavailable {
		fmt.Fprintln(w, "idle_time_seconds: default")
	}
	fmt.Fprintln(w, "prevents: automatic-screen-saver-lock")
	fmt.Fprintln(w, "display_sleep_policy: separate")
	fmt.Fprintln(w, "manual_lock_password: unchanged")
}

func printCommandResults(w io.Writer, results []maccore.CommandResult) {
	for _, result := range results {
		fmt.Fprintf(w, "command: %s\n", result.Command)
		if result.Output != "" {
			fmt.Fprintf(w, "output: %s\n", result.Output)
		}
	}
}

func resolveExecutablePath() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if path == "" {
		return "", fmt.Errorf("empty executable path")
	}
	return path, nil
}
