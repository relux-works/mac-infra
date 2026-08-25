package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
	"github.com/relux-works/mac-infra/internal/safarictl"
)

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code = %d, stderr = %s", code, stderr.String())
	}
	for _, want := range []string{"mac-safari-session", "open-bg", "close-window", "fetch-file"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("stdout missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestCloseWindowRequiresPositiveID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"close-window"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires --id") {
		t.Fatalf("stderr missing required id message:\n%s", stderr.String())
	}
}

func TestRunJSProductionEntryRejectsSecretScriptAndFileWithoutExecution(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "executed")
	t.Setenv("MARKER", marker)
	fake := filepath.Join(t.TempDir(), "osascript")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\ntouch \"$MARKER\"\nexit 99\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newSafariSession
	newSafariSession = func(artifactDir string) *safarictl.Session {
		session := safarictl.New(artifactDir)
		session.OsaScriptPath = fake
		return session
	}
	defer func() { newSafariSession = oldNew }()
	secretFile := filepath.Join(t.TempDir(), "secret.js")
	if err := os.WriteFile(secretFile, []byte("indexedDB.databases()"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{"run-js", "--window-id", "123", "--origin", "https://example.com", "--script", "document.cookie"},
		{"run-js", "--window-id", "123", "--origin", "https://example.com", "--file", secretFile},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Fatalf("run(%v) unexpectedly passed", args)
		}
		if !strings.Contains(stderr.String(), "blocked token") {
			t.Fatalf("stderr missing safety refusal: %s", stderr.String())
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("secret payload reached osascript; marker err=%v", err)
	}
}

func TestRunJSRequiresExactWindowAndOriginBeforeSafari(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-js", "--window-id", "-1", "--script", "document.title"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "positive --window-id and --origin") {
		t.Fatalf("stderr missing window id explanation:\n%s", stderr.String())
	}
}

func TestRunJSHelpDocumentsWindowID(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"run-js", "--help"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "-window-id") || !strings.Contains(stderr.String(), "-origin") {
		t.Fatalf("stderr missing --window-id help:\n%s", stderr.String())
	}
}

func TestFetchFileRequiresResourceAndOutput(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"fetch-file", "--resource", "/api/file"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("run code = %d, want 2; stdout = %s stderr = %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "requires --resource, --out, and --origin") {
		t.Fatalf("stderr missing required flags message:\n%s", stderr.String())
	}
}

func TestFetchFileProductionEntryReassemblesCompleteFile(t *testing.T) {
	payload := []byte("complete authenticated PDF payload")
	installSafariFetchTestRuntime(t, safariFetchResponses(t, payload, int64(len(payload)), -1))
	outPath := filepath.Join(t.TempDir(), "document.pdf")
	metaPath := filepath.Join(t.TempDir(), "document.json")

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"fetch-file",
		"--window-id", "123",
		"--origin", "https://example.com",
		"--resource", "/api/private/document.pdf",
		"--out", outPath,
		"--meta", metaPath,
		"--chunk-size", "8",
		"--timeout", "1s",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("saved payload=%q, want %q", got, payload)
	}
	var meta safarictl.FetchMeta
	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(metaData, &meta); err != nil {
		t.Fatal(err)
	}
	if meta.Bytes != int64(len(payload)) || meta.ActualBytesWritten != int64(len(payload)) {
		t.Fatalf("metadata byte attestation=%#v, want %d", meta, len(payload))
	}
	if !strings.Contains(stdout.String(), "saved: "+outPath) || !strings.Contains(stdout.String(), "bytes: ") {
		t.Fatalf("stdout missing successful publication evidence: %s", stdout.String())
	}
}

func TestFetchFileProductionEntryRefusesIncompleteTransferWithoutPublishing(t *testing.T) {
	payload := []byte("complete authenticated PDF payload")
	cases := []struct {
		name          string
		reportedBytes int64
		missingChunk  int
		wantError     string
	}{
		{name: "browser-size-mismatch", reportedBytes: int64(len(payload) + 7), missingChunk: -1, wantError: "byte count mismatch"},
		{name: "missing-middle-chunk", reportedBytes: int64(len(payload)), missingChunk: 1, wantError: "empty chunk 2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installSafariFetchTestRuntime(t, safariFetchResponses(t, payload, tc.reportedBytes, tc.missingChunk))
			outPath := filepath.Join(t.TempDir(), "document.pdf")
			metaPath := filepath.Join(t.TempDir(), "document.json")
			const existing = "preserve-existing-output"
			if err := os.WriteFile(outPath, []byte(existing), 0o600); err != nil {
				t.Fatal(err)
			}

			var stdout, stderr bytes.Buffer
			code := run([]string{
				"fetch-file",
				"--window-id", "123",
				"--origin", "https://example.com",
				"--resource", "/api/private/document.pdf",
				"--out", outPath,
				"--meta", metaPath,
				"--chunk-size", "8",
				"--timeout", "1s",
			}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("run code=%d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.wantError) {
				t.Fatalf("stderr missing %q: %s", tc.wantError, stderr.String())
			}
			if strings.Contains(stdout.String(), "saved:") {
				t.Fatalf("failed transfer was reported as saved: %s", stdout.String())
			}
			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != existing {
				t.Fatalf("failed transfer replaced output with %q", got)
			}
			if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
				t.Fatalf("failed transfer published metadata; err=%v", err)
			}
		})
	}
}

func safariFetchResponses(t *testing.T, payload []byte, reportedBytes int64, missingChunk int) []string {
	t.Helper()
	const chunkSize = 8
	encoded := base64.StdEncoding.EncodeToString(payload)
	chunks := make([]string, 0, (len(encoded)+chunkSize-1)/chunkSize)
	for start := 0; start < len(encoded); start += chunkSize {
		end := start + chunkSize
		if end > len(encoded) {
			end = len(encoded)
		}
		chunks = append(chunks, encoded[start:end])
	}
	metaData, err := json.Marshal(safarictl.FetchMeta{
		State:       "done",
		Status:      200,
		OK:          true,
		ContentType: "application/pdf",
		Bytes:       reportedBytes,
		ChunkSize:   chunkSize,
		ChunkCount:  len(chunks),
	})
	if err != nil {
		t.Fatal(err)
	}
	responses := []string{
		guardedSafariCLIResult(t, "started"),
		guardedSafariCLIResult(t, string(metaData)),
	}
	for index, chunk := range chunks {
		if index == missingChunk {
			chunk = ""
		}
		responses = append(responses, guardedSafariCLIResult(t, chunk))
	}
	return responses
}

func installSafariFetchTestRuntime(t *testing.T, responses []string) {
	t.Helper()
	responseDir := t.TempDir()
	for index, response := range responses {
		path := filepath.Join(responseDir, strconv.Itoa(index+1))
		if err := os.WriteFile(path, []byte(response), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	statePath := filepath.Join(t.TempDir(), "call-count")
	t.Setenv("SAFARI_FETCH_TEST_RESPONSES", responseDir)
	t.Setenv("SAFARI_FETCH_TEST_STATE", statePath)
	fake := filepath.Join(t.TempDir(), "osascript")
	source := `#!/bin/sh
set -eu
count=0
if [ -f "$SAFARI_FETCH_TEST_STATE" ]; then
  count=$(/bin/cat "$SAFARI_FETCH_TEST_STATE")
fi
count=$((count + 1))
/usr/bin/printf '%s' "$count" > "$SAFARI_FETCH_TEST_STATE"
response="$SAFARI_FETCH_TEST_RESPONSES/$count"
if [ ! -f "$response" ]; then
  echo "unexpected Safari fetch call $count" >&2
  exit 91
fi
/bin/cat "$response"
`
	if err := os.WriteFile(fake, []byte(source), 0o700); err != nil {
		t.Fatal(err)
	}
	oldNew := newSafariSession
	newSafariSession = func(artifactDir string) *safarictl.Session {
		session := safarictl.New(artifactDir)
		session.OsaScriptPath = fake
		return session
	}
	t.Cleanup(func() { newSafariSession = oldNew })
}

func guardedSafariCLIResult(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(map[string]string{
		"__macBrowserSessionGuard": "works.relux.mac-infra/browser-session-guard/v1",
		"outcome":                  "ok",
		"origin":                   "https://example.com",
		"readyState":               "complete",
		"value":                    value,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type safariHeartbeatTestRuntime struct {
	manager browsersession.HeartbeatManager
	probes  *int
}

func installSafariHeartbeatTestRuntime(t *testing.T) safariHeartbeatTestRuntime {
	t.Helper()
	home := t.TempDir()
	fakeOsaScript := filepath.Join(t.TempDir(), "osascript")
	guardedResult := `{"__macBrowserSessionGuard":"works.relux.mac-infra/browser-session-guard/v1","outcome":"ok","origin":"https://lkfl2.nalog.ru","readyState":"complete","value":"{\"ok\":true}"}`
	if err := os.WriteFile(fakeOsaScript, []byte("#!/bin/sh\nprintf '%s\\n' '"+guardedResult+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	probes := 0
	manager := browsersession.HeartbeatManager{
		HomeDir:   home,
		Launchctl: "/bin/launchctl",
		UID:       os.Getuid(),
		Now:       time.Now,
		RunCommand: func(context.Context, string, ...string) error {
			return nil
		},
		WaitForFirstOutcome: func(_ context.Context, cfg browsersession.HeartbeatConfig) error {
			outcome, err := json.Marshal(browsersession.HeartbeatOutcome{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				Outcome:    "ok",
				Origin:     cfg.Origin,
				ReadyState: "complete",
			})
			if err != nil {
				return err
			}
			return os.WriteFile(cfg.LogPath, append(outcome, '\n'), 0o600)
		},
	}
	if err := os.MkdirAll(filepath.Dir(manager.LauncherPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manager.LauncherPath(), []byte("stable test launcher"), 0o700); err != nil {
		t.Fatal(err)
	}

	oldManager := newHeartbeatManager
	oldSafari := newSafariSession
	newHeartbeatManager = func() (browsersession.HeartbeatManager, error) { return manager, nil }
	newSafariSession = func(artifactDir string) *safarictl.Session {
		probes++
		session := safarictl.New(artifactDir)
		session.OsaScriptPath = fakeOsaScript
		return session
	}
	t.Cleanup(func() {
		newHeartbeatManager = oldManager
		newSafariSession = oldSafari
	})
	return safariHeartbeatTestRuntime{manager: manager, probes: &probes}
}

func TestSafariHeartbeatLifecycleThroughProductionEntry(t *testing.T) {
	runtime := installSafariHeartbeatTestRuntime(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"heartbeat", "start", "--name", "fns-safari", "--window-id", "55138", "--origin", "https://lkfl2.nalog.ru", "--interval", "15s", "--ttl", "1h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("start code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var started browsersession.HeartbeatStatus
	if err := json.Unmarshal(stdout.Bytes(), &started); err != nil {
		t.Fatalf("decode start status: %v; output=%s", err, stdout.String())
	}
	if started.State != "running" || started.Browser != browsersession.BrowserSafari || started.WindowID != "55138" || started.Origin != "https://lkfl2.nalog.ru" || started.TabID != "" {
		t.Fatalf("unexpected start status: %#v", started)
	}
	if started.Deadline == "" || started.Expired {
		t.Fatalf("start did not expose live deadline state: %#v", started)
	}
	if *runtime.probes != 1 {
		t.Fatalf("Safari probe calls=%d, want 1", *runtime.probes)
	}
	initialDeadline := started.Deadline

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"heartbeat", "restart", "--name", "fns-safari", "--ttl", "2h"}, &stdout, &stderr); code != 0 {
		t.Fatalf("restart code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var restarted browsersession.HeartbeatStatus
	if err := json.Unmarshal(stdout.Bytes(), &restarted); err != nil {
		t.Fatalf("decode restart status: %v; output=%s", err, stdout.String())
	}
	if restarted.Deadline == "" || restarted.Deadline == initialDeadline || restarted.MigrationRequired || restarted.Expired {
		t.Fatalf("restart did not publish a fresh deadline: %#v", restarted)
	}
	if *runtime.probes != 3 {
		t.Fatalf("Safari restart probe calls=%d, want initial plus two restart preflights", *runtime.probes)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"heartbeat", "status", "--name", "fns-safari"}, &stdout, &stderr); code != 0 {
		t.Fatalf("status code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var status browsersession.HeartbeatStatus
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil || status.State != "running" {
		t.Fatalf("status=%#v err=%v output=%s", status, err, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"heartbeat", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("list code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var statuses []browsersession.HeartbeatStatus
	if err := json.Unmarshal(stdout.Bytes(), &statuses); err != nil || len(statuses) != 1 || statuses[0].Name != "fns-safari" || statuses[0].Deadline != restarted.Deadline || statuses[0].Expired {
		t.Fatalf("statuses=%#v err=%v output=%s", statuses, err, stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"heartbeat", "stop", "--name", "fns-safari"}, &stdout, &stderr); code != 0 {
		t.Fatalf("stop code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := runtime.manager.Load("fns-safari"); !os.IsNotExist(err) {
		t.Fatalf("heartbeat state survived stop: %v", err)
	}
}

func TestSafariHeartbeatStartRejectsUnsafeTargetBeforeSafariDispatch(t *testing.T) {
	runtime := installSafariHeartbeatTestRuntime(t)
	cases := map[string][]string{
		"missing-window":   {"heartbeat", "start", "--name", "safe", "--origin", "https://lkfl2.nalog.ru", "--ttl", "1h"},
		"negative-window":  {"heartbeat", "start", "--name", "safe", "--window-id", "-1", "--origin", "https://lkfl2.nalog.ru", "--ttl", "1h"},
		"missing-origin":   {"heartbeat", "start", "--name", "safe", "--window-id", "55138", "--ttl", "1h"},
		"http-origin":      {"heartbeat", "start", "--name", "safe", "--window-id", "55138", "--origin", "http://lkfl2.nalog.ru", "--ttl", "1h"},
		"origin-with-path": {"heartbeat", "start", "--name", "safe", "--window-id", "55138", "--origin", "https://lkfl2.nalog.ru/cabinet", "--ttl", "1h"},
		"unsafe-name":      {"heartbeat", "start", "--name", "../safe", "--window-id", "55138", "--origin", "https://lkfl2.nalog.ru", "--ttl", "1h"},
		"short-interval":   {"heartbeat", "start", "--name", "safe", "--window-id", "55138", "--origin", "https://lkfl2.nalog.ru", "--interval", "14s", "--ttl", "1h"},
		"invented-tab-id":  {"heartbeat", "start", "--name", "safe", "--window-id", "55138", "--tab-id", "77", "--origin", "https://lkfl2.nalog.ru", "--ttl", "1h"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(args, &stdout, &stderr); code != 2 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
		})
	}
	if *runtime.probes != 0 {
		t.Fatalf("unsafe heartbeat target reached Safari %d times", *runtime.probes)
	}
}

func TestSafariHeartbeatStartProductionEntryRequiresFiniteDeadline(t *testing.T) {
	runtime := installSafariHeartbeatTestRuntime(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"heartbeat", "start", "--name", "deadline-gate", "--window-id", "55138", "--origin", "https://lkfl2.nalog.ru"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stderr.String(), "exactly one of a positive --ttl or --deadline") {
		t.Fatalf("missing deadline code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if *runtime.probes != 0 {
		t.Fatalf("missing deadline reached Safari %d times", *runtime.probes)
	}
}

func TestSafariHeartbeatLifecycleTimeoutPreservesSerializedAppleEventBudget(t *testing.T) {
	if heartbeatLifecycleTimeout != 11*time.Minute {
		t.Fatalf("heartbeat lifecycle timeout = %s, want 11m", heartbeatLifecycleTimeout)
	}
}

func TestSafariHeartbeatCommandsRefuseChromeNamespaceEntries(t *testing.T) {
	runtime := installSafariHeartbeatTestRuntime(t)
	cfg, err := runtime.manager.NewConfig("chrome-owned", browsersession.BrowserChrome, "1", "2", "https://example.com", 15*time.Second, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.manager.Start(context.Background(), cfg, func(context.Context, browsersession.HeartbeatConfig) (browsersession.ExecutionResult, error) {
		return browsersession.ExecutionResult{Origin: cfg.Origin, ReadyState: "complete"}, nil
	}); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{
		{"heartbeat", "status", "--name", "chrome-owned"},
		{"heartbeat", "stop", "--name", "chrome-owned"},
		{"heartbeat", "run", "--name", "chrome-owned"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code == 0 {
			t.Fatalf("run(%v) admitted Chrome heartbeat: stdout=%s stderr=%s", args, stdout.String(), stderr.String())
		}
		if !strings.Contains(stderr.String(), "belongs to chrome") {
			t.Fatalf("run(%v) returned nonspecific refusal: %s", args, stderr.String())
		}
	}
	if _, err := runtime.manager.Load("chrome-owned"); err != nil {
		t.Fatalf("Safari CLI changed Chrome heartbeat: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"heartbeat", "list"}, &stdout, &stderr); code != 0 {
		t.Fatalf("list code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "chrome-owned") {
		t.Fatalf("Safari list exposed Chrome entry: %s", stdout.String())
	}
}
