package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/safarictl"
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
	case "open-bg":
		return runOpenBackground(args[1:], stdout, stderr)
	case "close-window":
		return runCloseWindow(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "check-js":
		return runCheckJavaScript(args[1:], stdout, stderr)
	case "run-js":
		return runJavaScript(args[1:], stdout, stderr)
	case "snapshot":
		return runSnapshot(args[1:], stdout, stderr)
	case "fetch-file":
		return runFetchFile(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-safari-session %s %s %s\n", Version, Commit, BuildDate)
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

func runOpenBackground(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("open-bg", flag.ContinueOnError)
	fs.SetOutput(stderr)
	wait := fs.Duration("wait", 3*time.Second, "time to wait after opening the URL")
	minimize := fs.Bool("minimize", true, "minimize the Safari window after opening")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 1 {
		fmt.Fprintln(stderr, "open-bg requires exactly one URL")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait+15*time.Second)
	defer cancel()
	status, err := safarictl.New(*artifactDir).OpenBackground(ctx, fs.Args()[0], *wait, *minimize)
	if err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	printStatus(stdout, status)
	return 0
}

func runCloseWindow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("close-window", flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.Int64("id", 0, "exact Safari window id returned by open-bg")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || *windowID <= 0 {
		fmt.Fprintln(stderr, "close-window requires --id with a positive Safari window id")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := safarictl.New(*artifactDir).CloseWindow(ctx, *windowID); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	fmt.Fprintf(stdout, "closed-window-id: %d\n", *windowID)
	return 0
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "status does not accept positional arguments")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := safarictl.New(*artifactDir).Status(ctx)
	if err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	printStatus(stdout, status)
	return 0
}

func runCheckJavaScript(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("check-js", flag.ContinueOnError)
	fs.SetOutput(stderr)
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "check-js does not accept positional arguments")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result, err := safarictl.New(*artifactDir).CheckJavaScript(ctx)
	if err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	fmt.Fprintf(stdout, "javascript: ok\nreadyState: %s\n", strings.TrimSpace(result))
	return 0
}

func runJavaScript(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run-js", flag.ContinueOnError)
	fs.SetOutput(stderr)
	script := fs.String("script", "", "JavaScript source to run in Safari; target --window-id or the front document")
	file := fs.String("file", "", "path to JavaScript source file")
	outPath := fs.String("out", "", "write JavaScript result to PATH instead of stdout")
	windowID := fs.Int64("window-id", 0, "exact agent-created Safari window id returned by open-bg")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "run-js does not accept positional arguments")
		return 2
	}
	if *windowID < 0 {
		fmt.Fprintln(stderr, "run-js --window-id must be a positive Safari window id")
		return 2
	}
	source, ok := readJavaScriptInput(*script, *file, stderr)
	if !ok {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session := safarictl.New(*artifactDir)
	session.TargetWindowID = *windowID
	result, err := session.RunJavaScript(ctx, source)
	if err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	if strings.TrimSpace(*outPath) != "" {
		if err := writeTextArtifact(*outPath, result+"\n"); err != nil {
			fmt.Fprintf(stderr, "run-js failed: write output: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "out: %s\n", *outPath)
		return 0
	}
	fmt.Fprintln(stdout, result)
	return 0
}

func runSnapshot(args []string, stdout, stderr io.Writer) (code int) {
	fs := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pageURL := fs.String("url", "", "optional URL to open in background before snapshot")
	wait := fs.Duration("wait", 3*time.Second, "time to wait after opening --url")
	jsonPath := fs.String("json", "", "write snapshot JSON to PATH")
	textLimit := fs.Int("text-limit", 20000, "maximum body text characters")
	linkLimit := fs.Int("link-limit", 200, "maximum links to include")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "snapshot does not accept positional arguments; use --url")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait+60*time.Second)
	defer cancel()
	session := safarictl.New(*artifactDir)
	openedTarget := false
	defer func() {
		if !openedTarget {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if err := session.CloseTarget(cleanupCtx); err != nil {
			fmt.Fprintf(stderr, "snapshot cleanup failed: %s\n", safarictl.FormatAutomationError(err))
			if code == 0 {
				code = 1
			}
		}
	}()
	if strings.TrimSpace(*pageURL) != "" {
		if _, err := session.OpenBackground(ctx, *pageURL, *wait, true); err != nil {
			fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
			return 1
		}
		openedTarget = true
	}
	snapshot, err := session.Snapshot(ctx, *textLimit, *linkLimit)
	if err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "snapshot failed: encode json: %v\n", err)
		return 1
	}
	data = append(data, '\n')
	if strings.TrimSpace(*jsonPath) != "" {
		if err := writeBytesArtifact(*jsonPath, data); err != nil {
			fmt.Fprintf(stderr, "snapshot failed: write json: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "json: %s\n", *jsonPath)
		return 0
	}
	_, _ = stdout.Write(data)
	return 0
}

func runFetchFile(args []string, stdout, stderr io.Writer) (code int) {
	fs := flag.NewFlagSet("fetch-file", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pageURL := fs.String("page", "", "optional page URL to open in background before fetch")
	resourceURL := fs.String("resource", "", "resource URL/path to fetch in Safari page context")
	outPath := fs.String("out", "", "local output file path")
	metaPath := fs.String("meta", "", "optional metadata JSON output path")
	wait := fs.Duration("wait", 3*time.Second, "time to wait after opening --page")
	timeout := fs.Duration("timeout", 90*time.Second, "maximum time to wait for page-context fetch")
	chunkSize := fs.Int("chunk-size", 250000, "base64 chunk size kept in Safari page memory")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "fetch-file does not accept positional arguments")
		return 2
	}
	if strings.TrimSpace(*resourceURL) == "" || strings.TrimSpace(*outPath) == "" {
		fmt.Fprintln(stderr, "fetch-file requires --resource and --out")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait+*timeout+60*time.Second)
	defer cancel()
	session := safarictl.New(*artifactDir)
	openedTarget := false
	defer func() {
		if !openedTarget {
			return
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if err := session.CloseTarget(cleanupCtx); err != nil {
			fmt.Fprintf(stderr, "fetch-file cleanup failed: %s\n", safarictl.FormatAutomationError(err))
			if code == 0 {
				code = 1
			}
		}
	}()
	if strings.TrimSpace(*pageURL) != "" {
		if _, err := session.OpenBackground(ctx, *pageURL, *wait, true); err != nil {
			fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
			return 1
		}
		openedTarget = true
	}
	if err := session.StartFetch(ctx, *resourceURL, *chunkSize); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	meta, err := session.WaitForFetch(ctx, *timeout, 500*time.Millisecond)
	if err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}

	var encoded strings.Builder
	for i := 0; i < meta.ChunkCount; i++ {
		chunk, err := session.ReadFetchChunk(ctx, i, i == meta.ChunkCount-1)
		if err != nil {
			fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
			return 1
		}
		encoded.WriteString(chunk)
	}
	data, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		fmt.Fprintf(stderr, "fetch-file failed: decode base64: %v\n", err)
		return 1
	}
	if err := writeBytesArtifact(*outPath, data); err != nil {
		fmt.Fprintf(stderr, "fetch-file failed: write output: %v\n", err)
		return 1
	}
	meta.ActualBytesWritten = int64(len(data))
	if strings.TrimSpace(*metaPath) != "" {
		metaData, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "fetch-file failed: encode metadata: %v\n", err)
			return 1
		}
		metaData = append(metaData, '\n')
		if err := writeBytesArtifact(*metaPath, metaData); err != nil {
			fmt.Fprintf(stderr, "fetch-file failed: write metadata: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "meta: %s\n", *metaPath)
	}
	fmt.Fprintf(stdout, "saved: %s\n", *outPath)
	fmt.Fprintf(stdout, "bytes: %d\n", len(data))
	if meta.ContentType != "" {
		fmt.Fprintf(stdout, "content-type: %s\n", meta.ContentType)
	}
	if meta.ContentDisposition != "" {
		fmt.Fprintf(stdout, "content-disposition: %s\n", meta.ContentDisposition)
	}
	return 0
}

func readJavaScriptInput(script, file string, stderr io.Writer) (string, bool) {
	script = strings.TrimSpace(script)
	file = strings.TrimSpace(file)
	if (script == "" && file == "") || (script != "" && file != "") {
		fmt.Fprintln(stderr, "run-js requires exactly one of --script or --file")
		return "", false
	}
	if script != "" {
		return script, true
	}
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "run-js failed: read script file: %v\n", err)
		return "", false
	}
	return string(data), true
}

func printStatus(w io.Writer, status safarictl.PageStatus) {
	fmt.Fprintf(w, "title: %s\n", status.Title)
	fmt.Fprintf(w, "url: %s\n", status.URL)
	if status.ReadyState != "" {
		fmt.Fprintf(w, "readyState: %s\n", status.ReadyState)
	}
	if status.WindowID > 0 {
		fmt.Fprintf(w, "window-id: %d\n", status.WindowID)
	}
}

func writeTextArtifact(path string, content string) error {
	return writeBytesArtifact(path, []byte(content))
}

func writeBytesArtifact(path string, data []byte) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("path is required")
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	return os.WriteFile(path, data, 0o600)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: mac-safari-session <command> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  open-bg      open URL in Safari without activating it, then minimize")
	fmt.Fprintln(w, "  close-window close the exact Safari window returned by open-bg")
	fmt.Fprintln(w, "  status       print front Safari document title/url/readyState")
	fmt.Fprintln(w, "  check-js     verify Safari JavaScript-from-Apple-Events permission")
	fmt.Fprintln(w, "  run-js       run guarded JavaScript in the front document or exact --window-id")
	fmt.Fprintln(w, "  snapshot     capture DOM text and links from Safari page context")
	fmt.Fprintln(w, "  fetch-file   fetch authenticated resource in Safari page context and save it")
	fmt.Fprintln(w, "  version      print version")
}
