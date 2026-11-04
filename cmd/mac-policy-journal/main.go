//go:build darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/relux-works/mac-infra/internal/policyjournal"
)

type paths []string

func (p *paths) String() string { return "explicit additional Claude homes" }
func (p *paths) Set(s string) error {
	if !filepath.IsAbs(s) || filepath.Clean(s) != s {
		return fmt.Errorf("home must be an absolute clean path")
	}
	*p = append(*p, s)
	return nil
}

func execute(ctx context.Context, args []string, out io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" {
		fmt.Fprintln(out, "mac-policy-journal run --user-root ABS --journal ABS --rescan 30s [--duration 0] [--home ABS ...]\nObserves ~/.claude and ~/.curator/environments/*/claude_code under user-root.\nAdditional CLAUDE_CONFIG_DIR homes require --home. Metadata only; notifications can coalesce.\nThe journal parent must already be private (0700). No policy contents are read.")
		fmt.Fprintln(out, "mac-policy-journal enable [--home ABS ...] | status | disable\nEnable creates a user LaunchAgent, never overwrites an existing plist. Disable retains its plist and journal.")
		return 0
	}
	if args[0] == "enable" || args[0] == "disable" || args[0] == "status" {
		return service(args, out)
	}
	if args[0] != "run" {
		fmt.Fprintln(out, "unsupported command")
		return 2
	}
	f := flag.NewFlagSet("run", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var root, journal string
	var extra paths
	var interval, duration time.Duration
	f.StringVar(&root, "user-root", "", "")
	f.StringVar(&journal, "journal", "", "")
	f.Var(&extra, "home", "")
	f.DurationVar(&interval, "rescan", 0, "")
	f.DurationVar(&duration, "duration", 0, "")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root || journal == "" || interval < time.Second || duration < 0 {
		fmt.Fprintln(out, "invalid options; use help")
		return 2
	}
	if info, e := os.Lstat(root); e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		fmt.Fprintln(out, "user root unavailable")
		return 1
	}
	log, e := policyjournal.OpenJournal(journal)
	if e != nil {
		fmt.Fprintln(out, "journal output refused")
		return 1
	}
	defer log.Close()
	if duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, duration)
		defer cancel()
	}
	o := &policyjournal.Observer{FS: policyjournal.OSMetadata{}, Writer: log}
	if e = policyjournal.Run(ctx, root, extra, interval, o); e != nil {
		fmt.Fprintln(out, "observer failed; coverage interrupted")
		return 1
	}
	if e = log.Sync(); e != nil {
		fmt.Fprintln(out, "journal sync failed")
		return 1
	}
	return 0
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(execute(ctx, os.Args[1:], os.Stderr))
}
