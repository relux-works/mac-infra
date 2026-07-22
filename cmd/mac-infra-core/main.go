package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/relux-works/mac-infra/internal/maccore"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

var (
	inspectService         = maccore.InspectService
	inspectSleepPrevention = maccore.InspectSleepPrevention
	requestSudoCredentials = maccore.RequestSudoCredentials
	cleanupAnyConnect      = maccore.CleanupAnyConnect
	enableSleepPrevention  = maccore.EnableSleepPrevention
	disableSleepPrevention = maccore.DisableSleepPrevention
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
	case "install":
		return runInstall(args[1:], stdout, stderr)
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
	if err := fs.Parse(args); err != nil {
		return 2
	}

	path, err := resolveExecutablePath()
	if err != nil {
		fmt.Fprintf(stderr, "install failed: %v\n", err)
		return 1
	}
	cfg := maccore.DefaultServiceConfig()
	if err := maccore.InstallService(cfg, path, os.Getuid(), os.Getgid()); err != nil {
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

func runDaemon(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("_daemon", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfg := maccore.DefaultServiceConfig()
	socketPath := fs.String("socket", cfg.SocketPath, "Unix socket path")
	clientUID := fs.Int("client-uid", os.Getuid(), "client uid for socket ownership")
	clientGID := fs.Int("client-gid", os.Getgid(), "client gid for socket ownership")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg.SocketPath = *socketPath
	if err := maccore.RunDaemon(cfg, *clientUID, *clientGID); err != nil {
		fmt.Fprintf(stderr, "daemon failed: %v\n", err)
		return 1
	}
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mac-infra-core manages the privileged macOS maintenance daemon.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-infra-core install")
	fmt.Fprintln(w, "  mac-infra-core uninstall")
	fmt.Fprintln(w, "  mac-infra-core status")
	fmt.Fprintln(w, "  mac-infra-core request-permissions sudo")
	fmt.Fprintln(w, "  mac-infra-core anyconnect-cleanup [--apply] [--force]")
	fmt.Fprintln(w, "  mac-infra-core sleep-prevention enable|disable|status")
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

func printSleepPreventionStatus(w io.Writer, status maccore.SleepPreventionStatus) {
	fmt.Fprintf(w, "sleep_prevention: %s\n", status.State)
	fmt.Fprintf(w, "applies_to: %s\n", status.AppliesTo)
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
