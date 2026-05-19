package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/audioreset"
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
	case "diagnose":
		return runDiagnose(args[1:], stdout, stderr)
	case "reset":
		return runReset(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-audio-reset %s %s %s\n", Version, Commit, BuildDate)
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

func runDiagnose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	includeLogs := fs.Bool("logs", false, "include recent CoreAudio logs")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	steps := audioreset.PlanDiagnose(*includeLogs, audioreset.DefaultEnvironment())
	for _, step := range steps {
		fmt.Fprintf(stdout, "\n== %s ==\n", step.Description)
		if err := runLocalCommand(stdout, step.Command, 20*time.Second); err != nil {
			if step.Optional {
				fmt.Fprintf(stdout, "warning: %v\n", err)
				continue
			}
			fmt.Fprintf(stderr, "diagnose failed: %v\n", err)
			return 1
		}
	}
	return 0
}

func runReset(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dryRun := fs.Bool("dry-run", false, "print the reset plan without executing it")
	skipSimulators := fs.Bool("skip-simulators", false, "do not shut down booted iOS simulators")
	includeUSBAudio := fs.Bool("include-usbaudio", false, "also restart usbaudiod after coreaudiod")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	opts := audioreset.ResetOptions{
		SkipSimulators:  *skipSimulators,
		IncludeUSBAudio: *includeUSBAudio,
	}
	steps := audioreset.PlanReset(opts, audioreset.DefaultEnvironment())
	if *dryRun {
		fmt.Fprintln(stdout, "reset plan:")
		for _, step := range steps {
			switch step.Kind {
			case audioreset.StepRestartAudio:
				fmt.Fprintf(stdout, "  - %s\n", step.Description)
			default:
				fmt.Fprintf(stdout, "  - %s: %s\n", step.Description, step.Command.String())
			}
		}
		return 0
	}

	if !maccore.Available(maccore.DefaultServiceConfig()) {
		fmt.Fprintln(stderr, "reset failed: mac-infra-core is not installed or not reachable; run `mac-infra-core install` once")
		return 1
	}

	for _, step := range steps {
		if step.Kind == audioreset.StepRestartAudio {
			if err := restartViaCore(stdout, opts.IncludeUSBAudio); err != nil {
				fmt.Fprintf(stderr, "reset failed: %v\n", err)
				return 1
			}
			continue
		}

		fmt.Fprintf(stdout, "running: %s\n", step.Command.String())
		if err := runLocalCommand(stdout, step.Command, 20*time.Second); err != nil {
			if step.Optional {
				fmt.Fprintf(stdout, "warning: %v\n", err)
				continue
			}
			fmt.Fprintf(stderr, "reset failed: %v\n", err)
			return 1
		}
	}
	fmt.Fprintln(stdout, "audio reset completed")
	return 0
}

func restartViaCore(stdout io.Writer, includeUSBAudio bool) error {
	cfg := maccore.DefaultServiceConfig()
	status, err := maccore.InspectService(cfg)
	if err != nil {
		return err
	}
	if !status.Reachable {
		return fmt.Errorf("mac-infra-core is not installed or not reachable; run `mac-infra-core install` once")
	}

	fmt.Fprintln(stdout, "running: mac-infra-core restart_audio")
	resp, err := maccore.RestartAudio(cfg, includeUSBAudio)
	if err != nil {
		return err
	}
	for _, result := range resp.Commands {
		if result.Output == "" {
			fmt.Fprintf(stdout, "ok: %s\n", result.Command)
		} else {
			fmt.Fprintf(stdout, "ok: %s: %s\n", result.Command, strings.TrimSpace(result.Output))
		}
	}
	return nil
}

func runLocalCommand(stdout io.Writer, command audioreset.Command, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command.Name, command.Args...)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		_, _ = stdout.Write(out)
		if out[len(out)-1] != '\n' {
			fmt.Fprintln(stdout)
		}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timed out after %s", command.String(), timeout)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", command.String(), err)
	}
	return nil
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "mac-audio-reset diagnoses and resets macOS audio crackle without rebooting.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  mac-audio-reset diagnose [--logs]")
	fmt.Fprintln(w, "  mac-audio-reset reset [--dry-run] [--skip-simulators] [--include-usbaudio]")
	fmt.Fprintln(w, "  mac-audio-reset version")
}
