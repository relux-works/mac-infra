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
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
	"github.com/relux-works/mac-infra/internal/safarictl"
)

const heartbeatLifecycleTimeout = 11 * time.Minute

var (
	Version             = "dev"
	Commit              = "unknown"
	BuildDate           = "unknown"
	newSafariSession    = safarictl.New
	newHeartbeatManager = browsersession.NewHeartbeatManager
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
	case "focus":
		return runFocus(args[1:], stdout, stderr)
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
	case "heartbeat":
		return runHeartbeat(args[1:], stdout, stderr)
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
	status, err := newSafariSession(*artifactDir).OpenBackground(ctx, fs.Args()[0], *wait, *minimize)
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
	if err := newSafariSession(*artifactDir).CloseWindow(ctx, *windowID); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	fmt.Fprintf(stdout, "closed-window-id: %d\n", *windowID)
	return 0
}

func runFocus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("focus", flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.Int64("window-id", 0, "exact Safari window id to hand off visibly")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || *windowID <= 0 {
		fmt.Fprintln(stderr, "focus requires --window-id with a positive Safari window id")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := newSafariSession(*artifactDir).FocusWindow(ctx, *windowID); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	fmt.Fprintf(stdout, "focused-window-id: %d\n", *windowID)
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
	status, err := newSafariSession(*artifactDir).Status(ctx)
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
	result, err := newSafariSession(*artifactDir).CheckJavaScript(ctx)
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
	script := fs.String("script", "", "bounded JavaScript source to run in the exact Safari window")
	file := fs.String("file", "", "path to JavaScript source file")
	outPath := fs.String("out", "", "write JavaScript result to PATH instead of stdout")
	windowID := fs.Int64("window-id", 0, "exact Safari window id; execution uses that window's current tab")
	origin := fs.String("origin", "", "required expected location.origin guard")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "run-js does not accept positional arguments")
		return 2
	}
	if *windowID <= 0 || strings.TrimSpace(*origin) == "" {
		fmt.Fprintln(stderr, "run-js requires a positive --window-id and --origin; Safari is window-scoped and has no stable tab id")
		return 2
	}
	source, ok := readJavaScriptInput(*script, *file, stderr)
	if !ok {
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	session := newSafariSession(*artifactDir)
	session.TargetWindowID = *windowID
	session.ExpectedOrigin = strings.TrimSpace(*origin)
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
	windowID := fs.Int64("window-id", 0, "exact Safari window id when --url is omitted")
	origin := fs.String("origin", "", "required expected location.origin guard")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "snapshot does not accept positional arguments; use --url")
		return 2
	}
	if strings.TrimSpace(*origin) == "" || (strings.TrimSpace(*pageURL) == "" && *windowID <= 0) || (strings.TrimSpace(*pageURL) != "" && *windowID != 0) {
		fmt.Fprintln(stderr, "snapshot requires --origin and exactly one target: --url or a positive --window-id")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait+60*time.Second)
	defer cancel()
	session := newSafariSession(*artifactDir)
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
	} else {
		session.TargetWindowID = *windowID
	}
	session.ExpectedOrigin = strings.TrimSpace(*origin)
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
	windowID := fs.Int64("window-id", 0, "exact Safari window id when --page is omitted")
	origin := fs.String("origin", "", "required expected location.origin guard")
	artifactDir := fs.String("artifact-dir", safarictl.DefaultArtifactDir, "directory for temporary JavaScript files")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "fetch-file does not accept positional arguments")
		return 2
	}
	if strings.TrimSpace(*resourceURL) == "" || strings.TrimSpace(*outPath) == "" || strings.TrimSpace(*origin) == "" {
		fmt.Fprintln(stderr, "fetch-file requires --resource, --out, and --origin")
		return 2
	}
	if (strings.TrimSpace(*pageURL) == "" && *windowID <= 0) || (strings.TrimSpace(*pageURL) != "" && *windowID != 0) {
		fmt.Fprintln(stderr, "fetch-file requires exactly one target: --page or a positive --window-id")
		return 2
	}

	ctx, cancel := context.WithTimeout(context.Background(), *wait+*timeout+60*time.Second)
	defer cancel()
	session := newSafariSession(*artifactDir)
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
	} else {
		session.TargetWindowID = *windowID
	}
	session.ExpectedOrigin = strings.TrimSpace(*origin)
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
		if chunk == "" {
			fmt.Fprintf(stderr, "fetch-file failed: empty chunk %d of %d; Safari fetch state was lost\n", i+1, meta.ChunkCount)
			return 1
		}
		encoded.WriteString(chunk)
	}
	data, err := base64.StdEncoding.DecodeString(encoded.String())
	if err != nil {
		fmt.Fprintf(stderr, "fetch-file failed: decode base64: %v\n", err)
		return 1
	}
	if meta.Bytes < 0 || int64(len(data)) != meta.Bytes {
		fmt.Fprintf(stderr, "fetch-file failed: byte count mismatch: Safari reported %d bytes, decoded %d\n", meta.Bytes, len(data))
		return 1
	}
	meta.ActualBytesWritten = int64(len(data))
	if err := writeBytesArtifact(*outPath, data); err != nil {
		fmt.Fprintf(stderr, "fetch-file failed: write output: %v\n", err)
		return 1
	}
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

func runHeartbeat(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "heartbeat requires start, restart, status, stop, or list")
		return 2
	}
	switch args[0] {
	case "start":
		return heartbeatStart(args[1:], stdout, stderr)
	case "restart":
		return heartbeatRestart(args[1:], stdout, stderr)
	case "status":
		return heartbeatStatus(args[1:], stdout, stderr)
	case "stop":
		return heartbeatStop(args[1:], stdout, stderr)
	case "list":
		return heartbeatList(args[1:], stdout, stderr)
	case "run":
		return heartbeatRun(args[1:], stderr)
	default:
		fmt.Fprintf(stderr, "unknown heartbeat command %q\n", args[0])
		return 2
	}
}

func heartbeatStart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat start", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "stable Safari heartbeat name")
	windowID := fs.Int64("window-id", 0, "exact Safari window id; the current tab is guarded by origin")
	origin := fs.String("origin", "", "required canonical HTTPS location.origin")
	interval := fs.Duration("interval", 45*time.Second, "heartbeat interval (minimum 15s)")
	ttl := fs.Duration("ttl", 0, "required finite lifetime, for example 8h")
	deadlineValue := fs.String("deadline", "", "required RFC3339 expiry instead of --ttl")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "heartbeat start does not accept positional arguments")
		return 2
	}
	originValue := strings.TrimSpace(*origin)
	if *windowID <= 0 || strings.TrimSpace(*name) == "" || originValue == "" {
		fmt.Fprintln(stderr, "heartbeat start requires --name, a positive --window-id, and --origin")
		return 2
	}
	if browsersession.OriginOf(originValue) != originValue || !strings.HasPrefix(originValue, "https://") {
		fmt.Fprintln(stderr, "heartbeat start requires --origin as a canonical HTTPS origin without path, query, fragment, or credentials")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	deadline, err := manager.ResolveDeadline(*ttl, *deadlineValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cfg, err := manager.NewConfig(strings.TrimSpace(*name), browsersession.BrowserSafari, strconv.FormatInt(*windowID, 10), "", originValue, *interval, deadline)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Allow one bounded direct preflight and one bounded background preflight.
	// Browser Apple Events may serialize behind an existing long-running monitor.
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatLifecycleTimeout)
	defer cancel()
	if _, err := manager.Start(ctx, cfg, safariHeartbeatProbe); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	status, err := manager.Inspect(ctx, cfg.Name)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return printJSON(stdout, stderr, status)
}

func heartbeatRestart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat restart", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "existing Safari heartbeat name")
	ttl := fs.Duration("ttl", 0, "required new finite lifetime, for example 8h")
	deadlineValue := fs.String("deadline", "", "required RFC3339 expiry instead of --ttl")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*name) == "" {
		fmt.Fprintln(stderr, "heartbeat restart requires --name and accepts no positional arguments")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	nameValue := strings.TrimSpace(*name)
	if err := requireSafariHeartbeat(manager, nameValue); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	deadline, err := manager.ResolveDeadline(*ttl, *deadlineValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatLifecycleTimeout)
	defer cancel()
	if _, err := manager.Restart(ctx, nameValue, deadline, safariHeartbeatProbe); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	status, err := manager.Inspect(ctx, nameValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return printJSON(stdout, stderr, status)
}

func heartbeatStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "Safari heartbeat name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*name) == "" {
		fmt.Fprintln(stderr, "heartbeat status requires --name")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := requireSafariHeartbeat(manager, strings.TrimSpace(*name)); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := manager.Inspect(ctx, strings.TrimSpace(*name))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return printJSON(stdout, stderr, status)
}

func heartbeatList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "heartbeat list does not accept positional arguments")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	statuses, err := manager.List(ctx)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	safariStatuses := make([]browsersession.HeartbeatStatus, 0, len(statuses))
	for _, status := range statuses {
		if status.Browser == browsersession.BrowserSafari {
			safariStatuses = append(safariStatuses, status)
		}
	}
	return printJSON(stdout, stderr, safariStatuses)
}

func heartbeatStop(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat stop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "Safari heartbeat name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*name) == "" {
		fmt.Fprintln(stderr, "heartbeat stop requires --name")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	nameValue := strings.TrimSpace(*name)
	if err := requireSafariHeartbeat(manager, nameValue); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := manager.Stop(ctx, nameValue); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "stopped: %s\n", nameValue)
	return 0
}

func heartbeatRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "Safari heartbeat name")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*name) == "" {
		fmt.Fprintln(stderr, "heartbeat run requires --name")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	nameValue := strings.TrimSpace(*name)
	if err := requireSafariHeartbeat(manager, nameValue); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := manager.Run(context.Background(), nameValue, safariHeartbeatProbe); err != nil {
		fmt.Fprintln(stderr, safarictl.FormatAutomationError(err))
		return 1
	}
	return 0
}

func safariHeartbeatProbe(ctx context.Context, cfg browsersession.HeartbeatConfig) (browsersession.ExecutionResult, error) {
	if cfg.Browser != browsersession.BrowserSafari {
		return browsersession.ExecutionResult{}, fmt.Errorf("heartbeat %q belongs to %s, not Safari", cfg.Name, cfg.Browser)
	}
	windowID, err := strconv.ParseInt(cfg.WindowID, 10, 64)
	if err != nil || windowID <= 0 {
		return browsersession.ExecutionResult{}, fmt.Errorf("invalid Safari window id %q", cfg.WindowID)
	}
	session := newSafariSession(filepath.Join(filepath.Dir(cfg.StatePath), "safari-artifacts"))
	session.TargetWindowID = windowID
	session.ExpectedOrigin = cfg.Origin
	return session.RunJavaScriptResult(ctx, browsersession.HeartbeatJavaScript())
}

func requireSafariHeartbeat(manager browsersession.HeartbeatManager, name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := manager.Inspect(ctx, name)
	if err != nil {
		return err
	}
	if status.State == "not-configured" {
		return nil
	}
	if status.Browser != browsersession.BrowserSafari {
		return fmt.Errorf("heartbeat %q belongs to %s, not Safari", name, status.Browser)
	}
	return nil
}

func printJSON(stdout, stderr io.Writer, value any) int {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	_, _ = stdout.Write(append(data, '\n'))
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
	fmt.Fprintln(w, "  focus        explicitly show one Safari window for handoff")
	fmt.Fprintln(w, "  status       print front Safari document title/url/readyState")
	fmt.Fprintln(w, "  check-js     verify Safari JavaScript-from-Apple-Events permission")
	fmt.Fprintln(w, "  run-js       run guarded JavaScript in an exact window's current tab; --origin required")
	fmt.Fprintln(w, "  snapshot     capture DOM text and links from Safari page context")
	fmt.Fprintln(w, "  fetch-file   fetch authenticated resource in Safari page context and save it")
	fmt.Fprintln(w, "  heartbeat    start, restart, status, list, or stop expiring exact-window Safari keepalives")
	fmt.Fprintln(w, "  version      print version")
}
