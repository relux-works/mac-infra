package safarictl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const DefaultArtifactDir = ".temp/mac-safari-session"

var ErrSensitiveJavaScript = errors.New("javascript appears to read browser secrets")

type Session struct {
	OsaScriptPath string
	ArtifactDir   string
}

type PageStatus struct {
	Title      string `json:"title"`
	URL        string `json:"url"`
	ReadyState string `json:"readyState,omitempty"`
}

type Snapshot struct {
	Title      string         `json:"title"`
	URL        string         `json:"url"`
	ReadyState string         `json:"readyState"`
	Text       string         `json:"text"`
	Links      []SnapshotLink `json:"links"`
	CapturedAt string         `json:"capturedAt"`
}

type SnapshotLink struct {
	Text string `json:"text"`
	Href string `json:"href"`
}

type FetchMeta struct {
	State              string            `json:"state"`
	Endpoint           string            `json:"endpoint,omitempty"`
	URL                string            `json:"url,omitempty"`
	Status             int               `json:"status,omitempty"`
	OK                 bool              `json:"ok,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	ContentType        string            `json:"contentType,omitempty"`
	ContentDisposition string            `json:"contentDisposition,omitempty"`
	Bytes              int64             `json:"bytes,omitempty"`
	ChunkSize          int               `json:"chunkSize,omitempty"`
	ChunkCount         int               `json:"chunkCount,omitempty"`
	Message            string            `json:"message,omitempty"`
	Stack              string            `json:"stack,omitempty"`
	StartedAt          string            `json:"startedAt,omitempty"`
	FinishedAt         string            `json:"finishedAt,omitempty"`
	ActualBytesWritten int64             `json:"actualBytesWritten,omitempty"`
}

func New(artifactDir string) Session {
	if strings.TrimSpace(artifactDir) == "" {
		artifactDir = DefaultArtifactDir
	}
	return Session{
		OsaScriptPath: "/usr/bin/osascript",
		ArtifactDir:   artifactDir,
	}
}

func (s Session) CheckJavaScript(ctx context.Context) (string, error) {
	return s.RunJavaScript(ctx, "document.readyState;")
}

func (s Session) OpenBackground(ctx context.Context, targetURL string, wait time.Duration, minimize bool) (PageStatus, error) {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return PageStatus{}, errors.New("url is required")
	}
	if wait < 0 {
		wait = 0
	}
	script := openBackgroundAppleScript(minimize, wait)
	out, err := s.runAppleScript(ctx, script, targetURL)
	if err != nil {
		return PageStatus{}, err
	}
	return decodePageStatusLines(out), nil
}

func (s Session) Status(ctx context.Context) (PageStatus, error) {
	out, err := s.runAppleScript(ctx, statusAppleScript())
	if err != nil {
		return PageStatus{}, err
	}
	return decodePageStatusLines(out), nil
}

func (s Session) RunJavaScript(ctx context.Context, source string) (string, error) {
	if err := GuardJavaScript(source); err != nil {
		return "", err
	}
	jsPath, cleanup, err := s.writeTempJavaScript(source)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return s.runAppleScript(ctx, runJavaScriptAppleScript(), jsPath)
}

func (s Session) Snapshot(ctx context.Context, textLimit, linkLimit int) (Snapshot, error) {
	if textLimit <= 0 {
		textLimit = 20000
	}
	if linkLimit <= 0 {
		linkLimit = 200
	}
	out, err := s.RunJavaScript(ctx, SnapshotJavaScript(textLimit, linkLimit))
	if err != nil {
		return Snapshot{}, err
	}
	var snapshot Snapshot
	if err := json.Unmarshal([]byte(out), &snapshot); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot json: %w", err)
	}
	return snapshot, nil
}

func (s Session) StartFetch(ctx context.Context, resourceURL string, chunkSize int) error {
	if strings.TrimSpace(resourceURL) == "" {
		return errors.New("resource url is required")
	}
	if chunkSize <= 0 {
		chunkSize = 250000
	}
	out, err := s.RunJavaScript(ctx, StartFetchJavaScript(resourceURL, chunkSize))
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "started" {
		return fmt.Errorf("unexpected fetch start result: %q", out)
	}
	return nil
}

func (s Session) PollFetch(ctx context.Context) (FetchMeta, error) {
	out, err := s.RunJavaScript(ctx, PollFetchJavaScript())
	if err != nil {
		return FetchMeta{}, err
	}
	var meta FetchMeta
	if err := json.Unmarshal([]byte(out), &meta); err != nil {
		return FetchMeta{}, fmt.Errorf("decode fetch metadata: %w", err)
	}
	meta.Headers = SanitizeHeaders(meta.Headers)
	return meta, nil
}

func (s Session) ReadFetchChunk(ctx context.Context, index int, clearAfter bool) (string, error) {
	if index < 0 {
		return "", errors.New("chunk index must be non-negative")
	}
	return s.RunJavaScript(ctx, ReadFetchChunkJavaScript(index, clearAfter))
}

func (s Session) WaitForFetch(ctx context.Context, timeout time.Duration, interval time.Duration) (FetchMeta, error) {
	if timeout <= 0 {
		timeout = 90 * time.Second
	}
	if interval <= 0 {
		interval = 500 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var last FetchMeta
	for {
		meta, err := s.PollFetch(ctx)
		if err != nil {
			return meta, err
		}
		last = meta
		switch meta.State {
		case "done":
			return meta, nil
		case "error":
			return meta, fmt.Errorf("safari fetch failed: %s", meta.Message)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return last, fmt.Errorf("timed out waiting for Safari fetch; last state=%q", last.State)
		case <-timer.C:
		}
	}
}

func GuardJavaScript(source string) error {
	lower := strings.ToLower(source)
	blocked := []string{
		"document.cookie",
		"cookiestore",
		"localstorage",
		"sessionstorage",
	}
	for _, needle := range blocked {
		if strings.Contains(lower, needle) {
			return fmt.Errorf("%w: blocked token %q; do not export cookies or browser storage", ErrSensitiveJavaScript, needle)
		}
	}
	return nil
}

func SanitizeHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" {
			continue
		}
		if isSensitiveHeader(normalized) {
			continue
		}
		out[normalized] = value
	}
	return out
}

func SnapshotJavaScript(textLimit, linkLimit int) string {
	return fmt.Sprintf(`(() => {
  const norm = (value) => String(value || "").replace(/\s+/g, " ").trim();
  const text = (document.body ? document.body.innerText : document.documentElement.innerText || "").slice(0, %d);
  const links = Array.from(document.querySelectorAll("a"))
    .slice(0, %d)
    .map((a) => ({ text: norm(a.innerText || a.getAttribute("aria-label") || a.title), href: a.href || "" }))
    .filter((row) => row.text || row.href);
  return JSON.stringify({
    title: document.title || "",
    url: location.href,
    readyState: document.readyState,
    text,
    links,
    capturedAt: new Date().toISOString()
  });
})();`, textLimit, linkLimit)
}

func StartFetchJavaScript(resourceURL string, chunkSize int) string {
	resourceJSON, _ := json.Marshal(resourceURL)
	return fmt.Sprintf(`(() => {
  const endpoint = %s;
  const chunkSize = %d;
  window.__macSafariSessionFetchJob = { state: "running", endpoint, startedAt: new Date().toISOString() };
  (async () => {
    try {
      const response = await fetch(endpoint, { credentials: "include" });
      const headers = {};
      response.headers.forEach((value, key) => { headers[key] = value; });
      if (!response.ok) throw new Error("download failed " + response.status + " " + response.statusText);
      const blob = await response.blob();
      const dataUrl = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result || ""));
        reader.onerror = () => reject(reader.error || new Error("FileReader failed"));
        reader.readAsDataURL(blob);
      });
      const base64 = dataUrl.split(",")[1] || "";
      const chunks = [];
      for (let i = 0; i < base64.length; i += chunkSize) {
        chunks.push(base64.slice(i, i + chunkSize));
      }
      window.__macSafariSessionFetchJob = {
        state: "done",
        endpoint,
        url: response.url,
        status: response.status,
        ok: response.ok,
        headers,
        contentType: response.headers.get("content-type") || "",
        contentDisposition: response.headers.get("content-disposition") || "",
        bytes: blob.size,
        chunkSize,
        chunkCount: chunks.length,
        chunks,
        startedAt: window.__macSafariSessionFetchJob.startedAt,
        finishedAt: new Date().toISOString()
      };
    } catch (error) {
      window.__macSafariSessionFetchJob = {
        state: "error",
        endpoint,
        message: String(error && error.message || error),
        stack: String(error && error.stack || ""),
        startedAt: window.__macSafariSessionFetchJob && window.__macSafariSessionFetchJob.startedAt || "",
        finishedAt: new Date().toISOString()
      };
    }
  })();
  return "started";
})();`, string(resourceJSON), chunkSize)
}

func PollFetchJavaScript() string {
	return `(() => {
  const job = window.__macSafariSessionFetchJob || null;
  if (!job) return JSON.stringify({ state: "missing" });
  const { chunks, ...meta } = job;
  if (chunks) meta.chunkCount = chunks.length;
  return JSON.stringify(meta);
})();`
}

func ReadFetchChunkJavaScript(index int, clearAfter bool) string {
	clear := "false"
	if clearAfter {
		clear = "true"
	}
	return fmt.Sprintf(`(() => {
  const job = window.__macSafariSessionFetchJob || null;
  if (!job || !job.chunks) return "";
  const chunk = job.chunks[%d] || "";
  if (%s) window.__macSafariSessionFetchJob = null;
  return chunk;
})();`, index, clear)
}

func FormatAutomationError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "not allowed to send javascript") ||
		strings.Contains(lower, "allow javascript from apple events") ||
		strings.Contains(lower, "errormessage") && strings.Contains(lower, "javascript") {
		return msg + "\n\nSafari blocked JavaScript automation. Enable Safari -> Develop -> Allow JavaScript from Apple Events, then rerun the command."
	}
	if errors.Is(err, ErrSensitiveJavaScript) {
		return msg
	}
	return msg
}

func (s Session) writeTempJavaScript(source string) (string, func(), error) {
	dir := s.ArtifactDir
	if strings.TrimSpace(dir) == "" {
		dir = DefaultArtifactDir
	}
	jsDir := filepath.Join(dir, "js")
	if err := os.MkdirAll(jsDir, 0o700); err != nil {
		return "", func() {}, err
	}
	file, err := os.CreateTemp(jsDir, "script-*.js")
	if err != nil {
		return "", func() {}, err
	}
	path := file.Name()
	if _, err := file.WriteString(source); err != nil {
		_ = file.Close()
		return "", func() { _ = os.Remove(path) }, err
	}
	if err := file.Close(); err != nil {
		return "", func() { _ = os.Remove(path) }, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

func (s Session) runAppleScript(ctx context.Context, script string, args ...string) (string, error) {
	osascriptPath := strings.TrimSpace(s.OsaScriptPath)
	if osascriptPath == "" {
		osascriptPath = "/usr/bin/osascript"
	}
	cmdArgs := []string{"-e", script}
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.CommandContext(ctx, osascriptPath, cmdArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" {
			detail = err.Error()
		}
		return "", fmt.Errorf("osascript failed: %s", detail)
	}
	return strings.TrimRight(stdout.String(), "\n"), nil
}

func isSensitiveHeader(name string) bool {
	switch name {
	case "set-cookie", "cookie", "authorization", "proxy-authorization", "x-auth-token", "x-csrf-token":
		return true
	default:
		return false
	}
}

func openBackgroundAppleScript(minimize bool, wait time.Duration) string {
	minimizeScript := ""
	if minimize {
		minimizeScript = "if (count of windows) > 0 then set miniaturized of front window to true\n"
	}
	delayScript := ""
	if wait > 0 {
		delayScript = fmt.Sprintf("delay %.3f\n", wait.Seconds())
	}
	return `on run argv
  set targetURL to item 1 of argv
  tell application "Safari"
    launch
    make new document with properties {URL:targetURL}
` + delayScript + minimizeScript + `    set pageTitle to ""
    set pageURL to ""
    set pageReadyState to ""
    try
      set pageTitle to name of front document
      set pageURL to URL of front document
      set pageReadyState to do JavaScript "document.readyState" in front document
    end try
    return pageTitle & linefeed & pageURL & linefeed & pageReadyState
  end tell
end run
`
}

func statusAppleScript() string {
	return `tell application "Safari"
  if (count of documents) = 0 then error "Safari has no open documents"
  set pageTitle to name of front document
  set pageURL to URL of front document
  set pageReadyState to ""
  try
    set pageReadyState to do JavaScript "document.readyState" in front document
  end try
  return pageTitle & linefeed & pageURL & linefeed & pageReadyState
end tell
`
}

func runJavaScriptAppleScript() string {
	return `on run argv
  set jsPath to item 1 of argv
  set jsSource to do shell script "/bin/cat " & quoted form of jsPath
  tell application "Safari"
    if (count of documents) = 0 then error "Safari has no open documents"
    return do JavaScript jsSource in front document
  end tell
end run`
}

func decodePageStatusLines(raw string) PageStatus {
	lines := strings.SplitN(raw, "\n", 3)
	status := PageStatus{}
	if len(lines) > 0 {
		status.Title = lines[0]
	}
	if len(lines) > 1 {
		status.URL = lines[1]
	}
	if len(lines) > 2 {
		status.ReadyState = strings.TrimSpace(lines[2])
	}
	return status
}
