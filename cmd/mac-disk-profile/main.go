package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/diskprofile"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

type excludeFlags []string

func (f *excludeFlags) String() string {
	return strings.Join(*f, ",")
}

func (f *excludeFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 2
	}

	switch args[0] {
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "top":
		return runTop(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-disk-profile %s %s %s\n", Version, Commit, BuildDate)
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

func runScan(args []string, stdout, stderr io.Writer) int {
	opts, jsonPath, ok := parseScanFlags("scan", args, stderr)
	if !ok {
		return 2
	}
	result, err := scanWithTimeout(opts)
	if err != nil {
		fmt.Fprintf(stderr, "scan failed: %v\n", err)
		return 1
	}
	if jsonPath != "" {
		if err := diskprofile.WriteJSONArtifact(jsonPath, result); err != nil {
			fmt.Fprintf(stderr, "scan failed: write json: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "json: %s\n", jsonPath)
	}
	diskprofile.RenderScanText(stdout, result)
	return 0
}

func runTop(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("top", flag.ContinueOnError)
	fs.SetOutput(stderr)
	depth := fs.Int("depth", -1, "maximum traversal depth from root; negative means unlimited")
	limit := fs.Int("limit", diskprofile.DefaultLimit, "number of top entries to retain")
	maxRetainedEntries := fs.Int("max-retained-entries", diskprofile.DefaultMaxRetainedEntries, "maximum entries retained in the JSON hierarchy")
	files := fs.Bool("files", false, "print top files")
	dirs := fs.Bool("dirs", false, "print top directories")
	oneFileSystem := fs.Bool("one-file-system", false, "stay on the root filesystem device when possible")
	noDefaultExcludes := fs.Bool("no-default-excludes", false, "disable built-in generated-tree excludes")
	var excludes excludeFlags
	fs.Var(&excludes, "exclude", "additional exclude glob; can be repeated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) > 1 {
		fmt.Fprintln(stderr, "top accepts at most one path")
		return 2
	}

	result, err := scanWithTimeout(scanOptionsFromArgs(fs.Args(), *depth, *limit, *maxRetainedEntries, excludes, *noDefaultExcludes, *oneFileSystem))
	if err != nil {
		fmt.Fprintf(stderr, "top failed: %v\n", err)
		return 1
	}
	includeDirs := *dirs
	includeFiles := *files
	if !includeDirs && !includeFiles {
		includeDirs = true
		includeFiles = true
	}
	diskprofile.RenderTopText(stdout, result, includeDirs, includeFiles)
	return 0
}

func runExplain(args []string, stdout, stderr io.Writer) int {
	opts, jsonPath, ok := parseScanFlags("explain", args, stderr)
	if !ok {
		return 2
	}
	result, err := scanWithTimeout(opts)
	if err != nil {
		fmt.Fprintf(stderr, "explain failed: %v\n", err)
		return 1
	}
	if jsonPath != "" {
		if err := diskprofile.WriteJSONArtifact(jsonPath, result); err != nil {
			fmt.Fprintf(stderr, "explain failed: write json: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "json: %s\n", jsonPath)
	}
	diskprofile.RenderExplainText(stdout, result)
	return 0
}

func parseScanFlags(name string, args []string, stderr io.Writer) (diskprofile.ScanOptions, string, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	depth := fs.Int("depth", -1, "maximum traversal depth from root; negative means unlimited")
	limit := fs.Int("limit", diskprofile.DefaultLimit, "number of top entries to retain")
	maxRetainedEntries := fs.Int("max-retained-entries", diskprofile.DefaultMaxRetainedEntries, "maximum entries retained in the JSON hierarchy")
	jsonPath := fs.String("json", "", "write versioned JSON artifact to path")
	oneFileSystem := fs.Bool("one-file-system", false, "stay on the root filesystem device when possible")
	noDefaultExcludes := fs.Bool("no-default-excludes", false, "disable built-in generated-tree excludes")
	var excludes excludeFlags
	fs.Var(&excludes, "exclude", "additional exclude glob; can be repeated")
	if err := fs.Parse(args); err != nil {
		return diskprofile.ScanOptions{}, "", false
	}
	if len(fs.Args()) > 1 {
		fmt.Fprintf(stderr, "%s accepts at most one path\n", name)
		return diskprofile.ScanOptions{}, "", false
	}
	return scanOptionsFromArgs(fs.Args(), *depth, *limit, *maxRetainedEntries, excludes, *noDefaultExcludes, *oneFileSystem), *jsonPath, true
}

func scanOptionsFromArgs(args []string, depth, limit, maxRetainedEntries int, excludes []string, noDefaultExcludes, oneFileSystem bool) diskprofile.ScanOptions {
	root := ""
	if len(args) > 0 {
		root = args[0]
	}
	return diskprofile.ScanOptions{
		Root:                   root,
		MaxDepth:               depth,
		Limit:                  limit,
		MaxRetainedEntries:     maxRetainedEntries,
		Excludes:               append([]string(nil), excludes...),
		DisableDefaultExcludes: noDefaultExcludes,
		OneFileSystem:          oneFileSystem,
	}
}

func scanWithTimeout(opts diskprofile.ScanOptions) (diskprofile.ScanResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	return diskprofile.Scan(ctx, opts)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: mac-disk-profile <command> [options] [path]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  scan      scan a path and print top directories/files")
	fmt.Fprintln(w, "  top       print largest directories and files")
	fmt.Fprintln(w, "  explain   scan and print APFS/hidden-space caveats")
	fmt.Fprintln(w, "  version   print version")
}
