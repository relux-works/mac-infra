package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/browserfacade"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 2
	}
	switch args[0] {
	case "q":
		return runQuery(args[1:], stdout, stderr)
	case "grep":
		return runGrep(args[1:], stdout, stderr)
	case "m":
		return runMutation(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-browser-site %s %s %s\n", Version, Commit, BuildDate)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		return fail(stderr, browserfacadeError("UNKNOWN_COMMAND", "unknown command; available commands: q, grep, m, version"), 2)
	}
}

func runQuery(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("q", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	adapterPath := fs.String("adapter", "", "site adapter JSON")
	format := fs.String("format", "", "required output format: json or compact")
	timeout := fs.Duration("timeout", 2*time.Minute, "bounded browser query timeout (maximum 5m)")
	if err := fs.Parse(args); err != nil {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", err.Error()), 2)
	}
	if len(fs.Args()) != 1 || strings.TrimSpace(*adapterPath) == "" {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", "q requires --adapter FILE, --format json|compact, and one query"), 2)
	}
	if !validFormat(*format) || *timeout <= 0 || *timeout > 5*time.Minute {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", "format must be json or compact and timeout must be within (0,5m]"), 2)
	}
	adapter, err := loadAdapter(*adapterPath)
	if err != nil {
		return fail(stderr, err, 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results, err := (browserfacade.Facade{}).Query(ctx, adapter, fs.Args()[0])
	if err != nil {
		return fail(stderr, err, 1)
	}
	if err := browserfacade.RenderQuery(stdout, results, *format); err != nil {
		return fail(stderr, err, 1)
	}
	return 0
}

func runGrep(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("grep", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	adapterPath := fs.String("adapter", "", "site adapter JSON")
	format := fs.String("format", "", "required output format: json or compact")
	file := fs.String("file", "", "one cache JSONL basename")
	insensitive := fs.Bool("i", false, "case-insensitive regular expression")
	contextLines := fs.Int("C", 0, "context lines (maximum 5)")
	maxMatches := fs.Int("max-matches", 50, "maximum matches (1..100)")
	if err := fs.Parse(args); err != nil {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", err.Error()), 2)
	}
	if len(fs.Args()) != 1 || strings.TrimSpace(*adapterPath) == "" || !validFormat(*format) {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", "grep requires --adapter FILE, --format json|compact, and one pattern"), 2)
	}
	adapter, err := loadAdapter(*adapterPath)
	if err != nil {
		return fail(stderr, err, 2)
	}
	matches, err := (browserfacade.Cache{}).Grep(adapter.Name, browserfacade.GrepOptions{Pattern: fs.Args()[0], File: *file, Insensitive: *insensitive, Context: *contextLines, MaxMatches: *maxMatches})
	if err != nil {
		return fail(stderr, err, 1)
	}
	if err := browserfacade.RenderGrep(stdout, matches, *format); err != nil {
		return fail(stderr, err, 1)
	}
	return 0
}

func runMutation(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("m", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	adapterPath := fs.String("adapter", "", "site adapter JSON")
	format := fs.String("format", "", "required output format: json or compact")
	dryRun := fs.Bool("dry-run", false, "preview without dispatching a browser write")
	confirm := fs.Bool("confirm", false, "explicitly authorize declared browser mutations")
	timeout := fs.Duration("timeout", 30*time.Second, "bounded mutation timeout (maximum 2m)")
	if err := fs.Parse(args); err != nil {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", err.Error()), 2)
	}
	if len(fs.Args()) != 1 || strings.TrimSpace(*adapterPath) == "" || !validFormat(*format) || (*dryRun && *confirm) || *timeout <= 0 || *timeout > 2*time.Minute {
		return fail(stderr, browserfacadeError("ARGUMENT_INVALID", "m requires --adapter FILE, --format json|compact, exactly one query, one of --dry-run/--confirm, and timeout within (0,2m]"), 2)
	}
	adapter, err := loadAdapter(*adapterPath)
	if err != nil {
		return fail(stderr, err, 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	results, err := (browserfacade.Facade{}).Mutate(ctx, adapter, fs.Args()[0], *dryRun, *confirm)
	if err != nil {
		return fail(stderr, err, 1)
	}
	if err := browserfacade.RenderMutations(stdout, results, *format); err != nil {
		return fail(stderr, err, 1)
	}
	return 0
}

func loadAdapter(path string) (browserfacade.Adapter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return browserfacade.Adapter{}, browserfacadeError("ADAPTER_INVALID", "could not read adapter file")
	}
	return browserfacade.DecodeAdapter(data)
}

func fail(stderr io.Writer, err error, code int) int {
	decision, boundaryErr := browserfacade.EnforceOutbound(err.Error())
	if boundaryErr != nil {
		err = boundaryErr
		decision.Value = boundaryErr.Error()
	}
	payload := map[string]any{"ok": false, "error": map[string]string{"kind": browserfacade.ErrorCode(err), "message": decision.Value}}
	var buffer bytes.Buffer
	_ = json.NewEncoder(&buffer).Encode(payload)
	if writeErr := browserfacade.WriteOutbound(stderr, buffer.String()); writeErr != nil {
		fmt.Fprintln(stderr, `{"ok":false,"error":{"kind":"SENSITIVE_RESPONSE_UNKNOWN","message":"outbound secret boundary failed closed"}}`)
	}
	return code
}

func validFormat(format string) bool { return format == "json" || format == "compact" }

func browserfacadeError(code, message string) error {
	return &cliError{code: code, message: message}
}

type cliError struct {
	code    string
	message string
}

func (e *cliError) Error() string { return e.message }

func (e *cliError) ErrorCode() string { return e.code }

func usage(writer io.Writer) {
	fmt.Fprintln(writer, `mac-browser-site: bounded agent-facing facade over authenticated browser sessions

Usage:
  mac-browser-site q --adapter FILE --format json|compact 'schema()'
  mac-browser-site q --adapter FILE --format compact 'list(skip=0,take=20) { id title price }'
  mac-browser-site grep --adapter FILE --format compact [-i] [-C N] [--file CACHE.jsonl] PATTERN
  mac-browser-site m --adapter FILE --format compact --dry-run 'invoke(name=install)'
  mac-browser-site m --adapter FILE --format compact --confirm 'invoke(name=install)'

q reads live page data through exact-target, origin-guarded mac-chrome-session or
mac-safari-session transports. grep reads only the facade's private per-site
cache. m never writes without an adapter-declared mutation and --confirm.`)
}
