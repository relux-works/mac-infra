package main

import (
	"context"
	"github.com/relux-works/mac-infra/internal/toolsecretprobe"
	"os"
)

var Version, Commit, BuildDate = "dev", "unknown", "unknown"

func main() {
	if len(os.Args) == 2 && os.Args[1] == toolsecretprobe.WorkerArgument {
		os.Exit(toolsecretprobe.Worker(os.Stdin, os.Stdout))
	}
	os.Exit(toolsecretprobe.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr, toolsecretprobe.Attempt))
}
