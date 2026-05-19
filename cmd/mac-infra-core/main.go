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

	status, err := maccore.InspectService(maccore.DefaultServiceConfig())
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
	fmt.Fprintln(w, "  mac-infra-core version")
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
