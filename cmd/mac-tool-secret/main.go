package main

import (
	"context"
	"github.com/relux-works/mac-infra/internal/toolsecret"
	"os"
)

var Version, Commit, BuildDate = "dev", "unknown", "unknown"

func main() {
	if len(os.Args) == 2 && os.Args[1] == toolsecret.WorkerArgument {
		os.Exit(toolsecret.Worker(os.Stdin, os.Stdout))
	}
	c := toolsecret.CLI{Backend: toolsecret.Native{}, Stdout: os.Stdout, Stderr: os.Stderr, StdinTTY: toolsecret.IsTerminal(os.Stdin), StdoutTTY: toolsecret.IsTerminal(os.Stdout)}
	os.Exit(c.Run(context.Background(), os.Args[1:]))
}
