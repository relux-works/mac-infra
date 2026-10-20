// mac-netnone runs JVM tests in a dedicated network-denied Colima profile.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"syscall"

	"github.com/relux-works/mac-infra/internal/netnone"
)

var Version = "dev"
var Commit = "unknown"
var BuildDate = "unknown"

func main() {
	ctx, cancel := terminationContext()
	defer cancel()
	os.Exit(runWith(ctx, os.Args[1:], os.Stdout, os.Stderr, func(out, err io.Writer) *netnone.Engine { return netnone.New(&netnone.ExecRunner{}, out, err) }))
}
func terminationContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
}

func run(args []string, out, errOut io.Writer) int {
	return runWith(context.Background(), args, out, errOut, func(out, err io.Writer) *netnone.Engine { return netnone.New(&netnone.ExecRunner{}, out, err) })
}
func runWith(ctx context.Context, args []string, out, errOut io.Writer, makeEngine func(io.Writer, io.Writer) *netnone.Engine) int {
	if len(args) == 0 {
		fmt.Fprintln(errOut, "usage: mac-netnone prep|run|selftest|status|stop|version|help [flags]")
		return 2
	}
	action := args[0]
	if action == "help" || action == "--help" {
		fmt.Fprintln(out, "mac-netnone prep --repo DIR --task TASK [--toolchain-dockerfile FILE]\nmac-netnone run --repo DIR --task TASK --out DIR [--toolchain-dockerfile FILE]\nmac-netnone selftest\nmac-netnone status\nmac-netnone stop\nprep/run/selftest: --max-load N (default CPU count), --cpus 4 --memory 8 --disk 40\nExit: 0 passed, 1 test/operational failure, 2 usage, 3 refused. Paths must be absolute existing directories.")
		return 0
	}
	if action == "version" {
		fmt.Fprintf(out, "mac-netnone %s %s %s\n", Version, Commit, BuildDate)
		return 0
	}
	if action != "prep" && action != "run" && action != "selftest" && action != "status" && action != "stop" {
		fmt.Fprintln(errOut, "unknown command")
		return 2
	}
	o := netnone.DefaultOptions()
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(errOut)
	if action == "prep" || action == "run" {
		flags.StringVar(&o.Repo, "repo", "", "absolute source directory")
		flags.StringVar(&o.Task, "task", "", "Gradle task")
		flags.StringVar(&o.Toolchain, "toolchain-dockerfile", "", "absolute Dockerfile starting FROM the pinned base")
	}
	if action == "run" {
		flags.StringVar(&o.Out, "out", "", "absolute existing output directory")
	}
	if action == "prep" || action == "run" || action == "selftest" {
		flags.Float64Var(&o.MaxLoad, "max-load", 0, "maximum 5-minute load; default CPU count")
		flags.IntVar(&o.CPUs, "cpus", 4, "VM CPUs")
		flags.IntVar(&o.Memory, "memory", 8, "VM memory GiB")
		flags.IntVar(&o.Disk, "disk", 40, "VM disk GiB")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return 2
	}
	invalid := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "max-load" && (o.MaxLoad <= 0 || math.IsNaN(o.MaxLoad) || math.IsInf(o.MaxLoad, 0)) {
			invalid = true
		}
	})
	if invalid || o.CPUs <= 0 || o.Memory <= 0 || o.Disk <= 0 {
		fmt.Fprintln(errOut, "resource flags must be positive finite numbers")
		return 2
	}
	if (action == "prep" || action == "run") && (o.Repo == "" || o.Task == "") || action == "run" && o.Out == "" {
		fmt.Fprintln(errOut, "--repo and --task are required; run also requires --out")
		return 2
	}
	return makeEngine(out, errOut).Execute(ctx, action, o)
}
