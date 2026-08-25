package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/browserquery"
	"github.com/relux-works/mac-infra/internal/browsersession"
	"github.com/relux-works/mac-infra/internal/chromectl"
	"github.com/relux-works/mac-infra/internal/safarictl"
)

const heartbeatLifecycleTimeout = 11 * time.Minute

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"

	newChromeSession              = chromectl.New
	newSafariSession              = safarictl.New
	newHeartbeatManager           = browsersession.NewHeartbeatManager
	stdinReader         io.Reader = os.Stdin
	prepareRunJSOutput            = prepareAtomicOutputArtifact
	uploadChromeFiles             = func(ctx context.Context, windowID, tabID, origin string, request chromectl.UploadRequest) (chromectl.UploadResult, error) {
		return newChromeSession().UploadFiles(ctx, windowID, tabID, origin, request)
	}
)

type runJSOutputArtifact interface {
	Commit(string) error
	Abort()
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return 2
	}
	switch args[0] {
	case "list":
		return runList(args[1:], stdout, stderr)
	case "run-js":
		return runJS(args[1:], stdout, stderr)
	case "fetch-file":
		return runFetchFile(args[1:], stdout, stderr)
	case "trusted-input":
		return runTrustedInput(args[1:], stdout, stderr)
	case "upload":
		return runUpload(args[1:], stdout, stderr)
	case "slack-read":
		return runSlackRead(args[1:], stdout, stderr)
	case "extract":
		return runExtract(args[1:], stdout, stderr)
	case "focus":
		return runFocus(args[1:], stdout, stderr)
	case "close":
		return runClose(args[1:], stdout, stderr)
	case "heartbeat":
		return runHeartbeat(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "mac-chrome-session %s %s %s\n", Version, Commit, BuildDate)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

type slackReadOutput struct {
	Version int               `json:"version"`
	OK      bool              `json:"ok"`
	Method  string            `json:"method,omitempty"`
	Data    any               `json:"data,omitempty"`
	Error   *slackReadFailure `json:"error,omitempty"`
}

type slackReadFailure struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

func runSlackRead(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("slack-read", flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.String("window-id", "", "exact Chrome window id")
	tabID := fs.String("tab-id", "", "exact Chrome tab id")
	origin := fs.String("origin", "", "required https://app.slack.com origin")
	workspaceID := fs.String("workspace-id", "", "required Slack workspace id")
	requestStdin := fs.Bool("request-stdin", false, "read one versioned JSON request from stdin")
	if err := fs.Parse(args); err != nil {
		return printSlackReadError(stdout, "invalid-request", 2)
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*windowID) == "" || strings.TrimSpace(*tabID) == "" || strings.TrimSpace(*origin) == "" || strings.TrimSpace(*workspaceID) == "" || !*requestStdin {
		fmt.Fprintln(stderr, "slack-read requires --window-id, --tab-id, --origin, --workspace-id, and --request-stdin and accepts no positional arguments")
		return printSlackReadError(stdout, "invalid-request", 2)
	}
	request, err := chromectl.DecodeSlackReadRequest(stdinReader)
	if err != nil {
		return printSlackReadError(stdout, chromectl.SlackReadErrorKind(err), 2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := newChromeSession().SlackRead(ctx, strings.TrimSpace(*windowID), strings.TrimSpace(*tabID), strings.TrimSpace(*origin), strings.TrimSpace(*workspaceID), request)
	if err != nil {
		return printSlackReadError(stdout, chromectl.SlackReadErrorKind(err), 1)
	}
	return printJSON(stdout, stderr, slackReadOutput{Version: chromectl.SlackReadVersion, OK: true, Method: result.Method, Data: result.Data})
}

func printSlackReadError(stdout io.Writer, kind string, code int) int {
	value := slackReadOutput{
		Version: chromectl.SlackReadVersion,
		OK:      false,
		Error:   &slackReadFailure{Kind: kind, Message: chromectl.SlackReadErrorMessage(kind)},
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		_, _ = stdout.Write(append(data, '\n'))
	}
	return code
}

func runExtract(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.String("window-id", "", "exact Chrome window id")
	tabID := fs.String("tab-id", "", "exact Chrome tab id")
	origin := fs.String("origin", "", "required expected location.origin")
	templatePath := fs.String("template", "", "JSON extraction template")
	fields := fs.String("fields", "", "comma-separated projected fields; default all")
	skip := fs.Int("skip", 0, "matching items to skip")
	take := fs.Int("take", 20, "matching items to return; maximum 100")
	whereField := fs.String("where-field", "", "predicate field")
	whereOp := fs.String("where-op", "contains", "predicate operation: equals, contains, or prefix")
	whereValue := fs.String("where-value", "", "predicate value")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*windowID) == "" || strings.TrimSpace(*tabID) == "" || strings.TrimSpace(*origin) == "" || strings.TrimSpace(*templatePath) == "" {
		fmt.Fprintln(stderr, "extract requires --window-id, --tab-id, --origin, and --template and accepts no positional arguments")
		return 2
	}
	data, err := os.ReadFile(*templatePath)
	if err != nil {
		fmt.Fprintf(stderr, "extract failed: read template: %v\n", err)
		return 1
	}
	template, err := browserquery.DecodeTemplate(data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	query := browserquery.Query{Skip: *skip, Take: *take}
	if strings.TrimSpace(*fields) != "" {
		for _, field := range strings.Split(*fields, ",") {
			query.Fields = append(query.Fields, strings.TrimSpace(field))
		}
	}
	if strings.TrimSpace(*whereField) != "" || strings.TrimSpace(*whereValue) != "" {
		if strings.TrimSpace(*whereField) == "" {
			fmt.Fprintln(stderr, "extract predicate requires --where-field when --where-value is set")
			return 2
		}
		query.Predicate = &browserquery.Predicate{Field: strings.TrimSpace(*whereField), Op: strings.TrimSpace(*whereOp), Value: *whereValue}
	}
	source, err := browserquery.BuildJavaScript(template, query)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := newChromeSession().RunJavaScriptResult(ctx, strings.TrimSpace(*windowID), strings.TrimSpace(*tabID), strings.TrimSpace(*origin), source)
	if err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	if !json.Valid([]byte(result.Value)) {
		fmt.Fprintln(stderr, "extract failed: page returned invalid JSON")
		return 1
	}
	fmt.Fprintln(stdout, result.Value)
	return 0
}

func runList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 {
		fmt.Fprintln(stderr, "list does not accept positional arguments")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	tabs, err := newChromeSession().List(ctx)
	if err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	return printJSON(stdout, stderr, tabs)
}

func runJS(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run-js", flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.String("window-id", "", "exact Chrome window id")
	tabID := fs.String("tab-id", "", "exact Chrome tab id")
	origin := fs.String("origin", "", "expected location.origin guard; strongly recommended")
	script := fs.String("script", "", "bounded JavaScript source")
	file := fs.String("file", "", "path to bounded JavaScript source")
	outPath := fs.String("out", "", "atomically write JavaScript result to PATH with mode 0600 instead of stdout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	outRequested := false
	fs.Visit(func(f *flag.Flag) {
		outRequested = outRequested || f.Name == "out"
	})
	if len(fs.Args()) != 0 || strings.TrimSpace(*windowID) == "" || strings.TrimSpace(*tabID) == "" {
		fmt.Fprintln(stderr, "run-js requires --window-id and --tab-id and accepts no positional arguments")
		return 2
	}
	source, ok := readJavaScriptInput(*script, *file, stderr)
	if !ok {
		return 2
	}
	var output runJSOutputArtifact
	if outRequested {
		if strings.TrimSpace(*outPath) == "" {
			fmt.Fprintln(stderr, "run-js requires a non-empty --out PATH")
			return 2
		}
		var err error
		output, err = prepareRunJSOutput(*outPath)
		if err != nil {
			fmt.Fprintf(stderr, "run-js failed: prepare output: %v\n", err)
			return 1
		}
		defer output.Abort()
	}
	if strings.TrimSpace(*origin) == "" {
		fmt.Fprintln(stderr, "guard: unguarded (no --origin supplied)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := newChromeSession().RunJavaScript(ctx, *windowID, *tabID, *origin, source)
	if err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	if output != nil {
		if err := output.Commit(result + "\n"); err != nil {
			fmt.Fprintf(stderr, "run-js failed: write output: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "out: %s\n", *outPath)
		return 0
	}
	fmt.Fprintln(stdout, result)
	return 0
}

// fetchFileDiagnosticPrefix is the single constant prefix every fetch-file
// failure line carries. It is a literal, not a stage or format string.
const fetchFileDiagnosticPrefix = "fetch-file: "

// emitFetchFileDiagnostic is the only fetch-file failure output call site in this
// command. It takes the closed diagnostic type — never a free-form format
// string, stage label, path, or arbitrary error — so no child, page, request,
// URL, origin, path, query, source, stdout, or stderr byte can reach the
// operator's terminal or session transcript through a fetch-file failure.
func emitFetchFileDiagnostic(w io.Writer, diagnostic chromectl.FetchFileDiagnostic) int {
	fmt.Fprintln(w, fetchFileDiagnosticPrefix+diagnostic.Message())
	return diagnostic.ExitCode()
}

// emitFetchFileSuccess is the fixed success serializer. Success is not a
// diagnostic: it reports the destination the caller itself chose plus numeric
// and already-parsed bounded metadata, and nothing derived from the resource
// reference, response URL, or response headers.
func emitFetchFileSuccess(w io.Writer, destination string, meta chromectl.FetchFileMeta) int {
	fmt.Fprintf(w, "saved: %s\n", destination)
	fmt.Fprintf(w, "bytes: %d\n", meta.Bytes)
	fmt.Fprintf(w, "status: %d\n", meta.Status)
	if meta.ContentType != "" {
		fmt.Fprintf(w, "content-type: %s\n", meta.ContentType)
	}
	return 0
}

func runFetchFile(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fetch-file", flag.ContinueOnError)
	// The flag package would otherwise be a second fetch-file formatter and
	// would render a rejected flag (including the retired --resource) itself.
	fs.SetOutput(io.Discard)
	windowID := fs.String("window-id", "", "exact Chrome window id returned by list")
	tabID := fs.String("tab-id", "", "exact Chrome tab id returned by list")
	origin := fs.String("origin", "", "required canonical HTTPS location.origin guard")
	outPath := fs.String("out", "", "required atomic private output path")
	requestStdin := fs.Bool("request-stdin", false, "read one bounded versioned JSON request from stdin")
	if err := fs.Parse(args); err != nil {
		return emitFetchFileDiagnostic(stderr, chromectl.NewFetchFileDiagnostic(chromectl.FetchFileUsage))
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*windowID) == "" || strings.TrimSpace(*tabID) == "" || strings.TrimSpace(*origin) == "" || strings.TrimSpace(*outPath) == "" || !*requestStdin {
		return emitFetchFileDiagnostic(stderr, chromectl.NewFetchFileDiagnostic(chromectl.FetchFileUsage))
	}
	// The protected resource reference arrives only on private stdin: an argv
	// value is durable session/tool evidence and may land in shell history.
	request, err := chromectl.DecodeFetchFileRequest(stdinReader)
	if err != nil {
		return emitFetchFileDiagnostic(stderr, chromectl.NewFetchFileDiagnostic(chromectl.FetchFileRequestUnreadable))
	}
	if err := chromectl.ValidateFetchFileRequest(strings.TrimSpace(*origin), request); err != nil {
		return emitFetchFileDiagnostic(stderr, chromectl.NewFetchFileDiagnostic(chromectl.FetchFileRequestRefused))
	}
	output, err := prepareRunJSOutput(*outPath)
	if err != nil {
		// The filesystem error names the explicit output path and quotes the
		// underlying syscall text; only the fixed code crosses the boundary.
		return emitFetchFileDiagnostic(stderr, chromectl.NewFetchFileDiagnostic(chromectl.FetchFileOutputPrepare))
	}
	defer output.Abort()
	data, meta, err := newChromeSession().FetchFile(context.Background(), strings.TrimSpace(*windowID), strings.TrimSpace(*tabID), strings.TrimSpace(*origin), request)
	if err != nil {
		return emitFetchFileDiagnostic(stderr, chromectl.AsFetchFileDiagnostic(err))
	}
	if err := output.Commit(string(data)); err != nil {
		return emitFetchFileDiagnostic(stderr, chromectl.NewFetchFileDiagnostic(chromectl.FetchFileOutputWrite))
	}
	return emitFetchFileSuccess(stdout, *outPath, meta)
}

func runFocus(args []string, stdout, stderr io.Writer) int {
	windowID, tabID, origin, ok := parseAuthorizedChromeTarget("focus", args, stderr)
	if !ok {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := newChromeSession().Focus(ctx, windowID, tabID, origin); err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	fmt.Fprintf(stdout, "focused-window-id: %s\nfocused-tab-id: %s\norigin: %s\n", windowID, tabID, origin)
	return 0
}

func runTrustedInput(args []string, stdout, stderr io.Writer) int {
	windowID, tabID, origin, ok := parseAuthorizedChromeTarget("trusted-input", args, stderr)
	if !ok {
		return 2
	}
	fs := flag.NewFlagSet("trusted-input request", flag.ContinueOnError)
	fs.SetOutput(stderr)
	requestStdin := fs.Bool("request-stdin", false, "read one bounded versioned JSON request from stdin")
	if err := fs.Parse(argsAfterAuthorizedTarget(args)); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || !*requestStdin {
		fmt.Fprintln(stderr, "trusted-input requires --request-stdin and accepts no positional arguments")
		return 2
	}
	request, err := chromectl.DecodeTrustedInputRequest(stdinReader)
	if err != nil {
		fmt.Fprintf(stderr, "trusted-input refused: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.TimeoutMS+5000)*time.Millisecond)
	defer cancel()
	result, err := newChromeSession().TrustedInput(ctx, windowID, tabID, origin, request)
	if err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	return printJSON(stdout, stderr, result)
}

func runUpload(args []string, stdout, stderr io.Writer) int {
	windowID, tabID, origin, ok := parseAuthorizedChromeTarget("upload", args, stderr)
	if !ok {
		return 2
	}
	fs := flag.NewFlagSet("upload request", flag.ContinueOnError)
	fs.SetOutput(stderr)
	requestStdin := fs.Bool("request-stdin", false, "read one bounded versioned JSON request from private stdin")
	if err := fs.Parse(argsAfterAuthorizedTarget(args)); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || !*requestStdin {
		fmt.Fprintln(stderr, "upload requires --request-stdin and accepts no positional arguments")
		return 2
	}
	request, err := chromectl.DecodeUploadRequest(stdinReader)
	if err != nil {
		fmt.Fprintf(stderr, "upload refused: %v\n", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.TimeoutMS+10_000)*time.Millisecond)
	defer cancel()
	result, err := uploadChromeFiles(ctx, windowID, tabID, origin, request)
	if err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	return printJSON(stdout, stderr, result)
}

func parseAuthorizedChromeTarget(command string, args []string, stderr io.Writer) (string, string, string, bool) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.String("window-id", "", "exact Chrome window id returned by list")
	tabID := fs.String("tab-id", "", "exact Chrome tab id returned by list")
	origin := fs.String("origin", "", "required exact current origin returned by list")
	humanAuthorized := fs.Bool("human-authorized", false, "attest that the user explicitly authorized this visible interaction")
	requestStdin := fs.Bool("request-stdin", false, "trusted-input/upload only: read one bounded versioned JSON request from stdin")
	if err := fs.Parse(args); err != nil {
		return "", "", "", false
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*windowID) == "" || strings.TrimSpace(*tabID) == "" || strings.TrimSpace(*origin) == "" || !*humanAuthorized || (command == "focus" && *requestStdin) {
		fmt.Fprintf(stderr, "%s requires --window-id, --tab-id, --origin, and --human-authorized and accepts no positional arguments\n", command)
		return "", "", "", false
	}
	return strings.TrimSpace(*windowID), strings.TrimSpace(*tabID), strings.TrimSpace(*origin), true
}

func argsAfterAuthorizedTarget(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--window-id", "--tab-id", "--origin":
			i++
		case "--human-authorized":
		default:
			out = append(out, args[i])
		}
	}
	return out
}

func runClose(args []string, stdout, stderr io.Writer) int {
	windowID, tabID, ok := parseExactChromeTarget("close", args, stderr)
	if !ok {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := newChromeSession().Close(ctx, windowID, tabID); err != nil {
		fmt.Fprintln(stderr, chromectl.FormatAutomationError(err))
		return 1
	}
	fmt.Fprintf(stdout, "closed-window-id: %s\nclosed-tab-id: %s\n", windowID, tabID)
	return 0
}

func parseExactChromeTarget(command string, args []string, stderr io.Writer) (string, string, bool) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(stderr)
	windowID := fs.String("window-id", "", "exact Chrome window id")
	tabID := fs.String("tab-id", "", "exact Chrome tab id")
	if err := fs.Parse(args); err != nil {
		return "", "", false
	}
	if len(fs.Args()) != 0 || strings.TrimSpace(*windowID) == "" || strings.TrimSpace(*tabID) == "" {
		fmt.Fprintf(stderr, "%s requires --window-id and --tab-id and accepts no positional arguments\n", command)
		return "", "", false
	}
	return strings.TrimSpace(*windowID), strings.TrimSpace(*tabID), true
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
	name := fs.String("name", "", "stable heartbeat name")
	browser := fs.String("browser", "", "target browser: chrome or safari")
	windowID := fs.String("window-id", "", "exact browser window id")
	tabID := fs.String("tab-id", "", "exact Chrome tab id; omit for Safari")
	origin := fs.String("origin", "", "required expected location.origin")
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
	cfg, err := manager.NewConfig(*name, browsersession.Browser(strings.ToLower(strings.TrimSpace(*browser))), *windowID, *tabID, *origin, *interval, deadline)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// Allow one bounded direct preflight and one bounded background preflight.
	// Chrome can serialize Apple Events behind an existing long-running monitor.
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatLifecycleTimeout)
	defer cancel()
	if _, err := manager.Start(ctx, cfg, heartbeatProbe); err != nil {
		fmt.Fprintln(stderr, formatHeartbeatError(cfg.Browser, err))
		return 1
	}
	status, err := manager.Inspect(ctx, *name)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return printJSON(stdout, stderr, status)
}

func heartbeatRestart(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat restart", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "existing heartbeat name")
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
	deadline, err := manager.ResolveDeadline(*ttl, *deadlineValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatLifecycleTimeout)
	defer cancel()
	if _, err := manager.Restart(ctx, strings.TrimSpace(*name), deadline, heartbeatProbe); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	status, err := manager.Inspect(ctx, strings.TrimSpace(*name))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return printJSON(stdout, stderr, status)
}

func heartbeatStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "heartbeat name")
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := manager.Inspect(ctx, *name)
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
	return printJSON(stdout, stderr, statuses)
}

func heartbeatStop(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat stop", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "heartbeat name")
	all := fs.Bool("all", false, "stop every managed browser heartbeat")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if len(fs.Args()) != 0 || (*all == (strings.TrimSpace(*name) != "")) {
		fmt.Fprintln(stderr, "heartbeat stop requires exactly one of --name or --all")
		return 2
	}
	manager, err := newHeartbeatManager()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if *all {
		if err := manager.StopAll(ctx); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintln(stdout, "stopped: all managed browser heartbeats")
		return 0
	}
	if err := manager.Stop(ctx, *name); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "stopped: %s\n", *name)
	return 0
}

func heartbeatRun(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("heartbeat run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "heartbeat name")
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
	if err := manager.Run(context.Background(), *name, heartbeatProbe); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func heartbeatProbe(ctx context.Context, cfg browsersession.HeartbeatConfig) (browsersession.ExecutionResult, error) {
	switch cfg.Browser {
	case browsersession.BrowserChrome:
		return newChromeSession().RunJavaScriptResult(ctx, cfg.WindowID, cfg.TabID, cfg.Origin, browsersession.HeartbeatJavaScript())
	case browsersession.BrowserSafari:
		windowID, err := strconv.ParseInt(cfg.WindowID, 10, 64)
		if err != nil || windowID <= 0 {
			return browsersession.ExecutionResult{}, fmt.Errorf("invalid Safari window id %q", cfg.WindowID)
		}
		session := newSafariSession(filepath.Join(filepath.Dir(cfg.StatePath), "safari-artifacts"))
		session.TargetWindowID = windowID
		session.ExpectedOrigin = cfg.Origin
		return session.RunJavaScriptResult(ctx, browsersession.HeartbeatJavaScript())
	default:
		return browsersession.ExecutionResult{}, fmt.Errorf("unsupported heartbeat browser %q", cfg.Browser)
	}
}

func formatHeartbeatError(browser browsersession.Browser, err error) string {
	if browser == browsersession.BrowserSafari {
		return safarictl.FormatAutomationError(err)
	}
	return chromectl.FormatAutomationError(err)
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

type atomicOutputArtifact struct {
	finalPath string
	tempPath  string
	file      *os.File
}

func prepareAtomicOutputArtifact(path string) (runJSOutputArtifact, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("path is required")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.IsDir() {
			return nil, fmt.Errorf("path is a directory")
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect path: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	temporary, err := os.CreateTemp(dir, ".mac-chrome-session-run-js-*")
	if err != nil {
		return nil, fmt.Errorf("create temporary output: %w", err)
	}
	artifact := &atomicOutputArtifact{finalPath: path, tempPath: temporary.Name(), file: temporary}
	if err := temporary.Chmod(0o600); err != nil {
		artifact.Abort()
		return nil, fmt.Errorf("chmod temporary output: %w", err)
	}
	return artifact, nil
}

func (a *atomicOutputArtifact) Commit(content string) error {
	if a == nil || a.file == nil || a.tempPath == "" || a.finalPath == "" {
		return fmt.Errorf("output artifact is not prepared")
	}
	if _, err := io.WriteString(a.file, content); err != nil {
		return fmt.Errorf("write temporary output: %w", err)
	}
	if err := a.file.Sync(); err != nil {
		return fmt.Errorf("sync temporary output: %w", err)
	}
	if err := a.file.Close(); err != nil {
		a.file = nil
		return fmt.Errorf("close temporary output: %w", err)
	}
	a.file = nil
	if err := os.Rename(a.tempPath, a.finalPath); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	a.tempPath = ""
	return nil
}

func (a *atomicOutputArtifact) Abort() {
	if a == nil {
		return
	}
	if a.file != nil {
		_ = a.file.Close()
		a.file = nil
	}
	if a.tempPath != "" {
		_ = os.Remove(a.tempPath)
		a.tempPath = ""
	}
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

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: mac-chrome-session <command> [options]")
	fmt.Fprintln(w, "commands:")
	fmt.Fprintln(w, "  list                              list sanitized Chrome window/tab metadata")
	fmt.Fprintln(w, "  run-js                            run guarded JavaScript on exact Chrome IDs; optional atomic 0600 --out PATH")
	fmt.Fprintln(w, "  fetch-file                        bounded same-origin authenticated fetch to an atomic 0600 output path")
	fmt.Fprintln(w, "  trusted-input                     explicitly authorized exact-target trusted text and named autocomplete selection")
	fmt.Fprintln(w, "  upload                            explicitly authorized exact-target native file upload from private stdin")
	fmt.Fprintln(w, "  slack-read                        run one sealed allowlisted Slack read from stdin")
	fmt.Fprintln(w, "  extract                           run bounded template-based repeated-element extraction")
	fmt.Fprintln(w, "  focus                             explicitly authorized origin-guarded exact Chrome tab handoff")
	fmt.Fprintln(w, "  close                             close one exact Chrome tab when explicitly requested")
	fmt.Fprintln(w, "  heartbeat start|restart|status|stop|list  manage expiring Chrome/Safari silent heartbeats")
	fmt.Fprintln(w, "  version                           print version")
}
