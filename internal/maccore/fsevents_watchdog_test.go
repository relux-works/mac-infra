package maccore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/fsevents"
)

func watchdogTestConfig(t *testing.T) FSEventsWatchdogConfig {
	t.Helper()
	dir := t.TempDir()
	return FSEventsWatchdogConfig{
		Label:      "works.relux.test-fseventsd-watchdog",
		PlistPath:  filepath.Join(dir, "LaunchAgents", "watchdog.plist"),
		StatePath:  filepath.Join(dir, "state", "fseventsd-watchdog.json"),
		BinaryPath: "/usr/local/bin/mac-infra-core",
		UID:        501,
	}
}

// The plist runs the fixed check verb with only the state path, a positive
// StartInterval, and no restart or threshold arguments (those live in the
// state file so the agent cannot be repurposed by editing argv).
func TestRenderFSEventsWatchdogLaunchAgent(t *testing.T) {
	cfg := watchdogTestConfig(t)
	settings := DefaultFSEventsWatchdogSettings()
	plist := string(RenderFSEventsWatchdogLaunchAgent(cfg, settings))
	for _, want := range []string{
		"<string>works.relux.test-fseventsd-watchdog</string>",
		"<string>/usr/local/bin/mac-infra-core</string>",
		"<string>_fseventsd-check</string>",
		"<string>--state</string>",
		"<string>" + cfg.StatePath + "</string>",
		"<key>StartInterval</key>",
		"<integer>600</integer>",
		"<key>RunAtLoad</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
	for _, forbidden := range []string{"--auto-restart", "--threshold", "KeepAlive", "renice", "taskpolicy"} {
		if strings.Contains(plist, forbidden) {
			t.Fatalf("plist must not contain %q:\n%s", forbidden, plist)
		}
	}
}

// Enable validates settings before touching the filesystem, writes state and
// plist, and bootstraps; a second enable re-bootstraps instead of failing.
func TestEnableFSEventsWatchdogWritesStateAndIsIdempotent(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", "missing")

	bad := DefaultFSEventsWatchdogSettings()
	bad.Interval = 10 * time.Second
	if _, err := EnableFSEventsWatchdog(cfg, bad); err == nil || !strings.Contains(err.Error(), "interval") {
		t.Fatalf("short interval must be refused, err = %v", err)
	}
	if _, err := os.Stat(cfg.StatePath); !os.IsNotExist(err) {
		t.Fatalf("refused enable must not write state")
	}
	bad = DefaultFSEventsWatchdogSettings()
	bad.RSSThresholdBytes = 0
	if _, err := EnableFSEventsWatchdog(cfg, bad); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("zero threshold must be refused, err = %v", err)
	}

	settings := DefaultFSEventsWatchdogSettings()
	settings.AutoRestart = true
	results, err := EnableFSEventsWatchdog(cfg, settings)
	if err != nil {
		t.Fatalf("enable err = %v", err)
	}
	if len(results) != 1 || !strings.Contains(results[0].Command, "bootstrap gui/501 "+cfg.PlistPath) {
		t.Fatalf("results = %+v", results)
	}
	if _, err := os.Stat(cfg.PlistPath); err != nil {
		t.Fatalf("plist not written: %v", err)
	}
	var state fseventsWatchdogStateFile
	if err := readJSONState(cfg.StatePath, &state); err != nil {
		t.Fatalf("state not written: %v", err)
	}
	if !state.Settings.AutoRestart || state.Settings.RSSThresholdBytes != fsevents.DefaultRSSCriticalBytes || state.Settings.EnabledAt.IsZero() {
		t.Fatalf("settings = %+v", state.Settings)
	}
	info, _ := os.Stat(cfg.StatePath)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state perm = %o, want 0600", info.Mode().Perm())
	}

	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", "enabled")
	settings.Interval = 5 * time.Minute
	results, err = EnableFSEventsWatchdog(cfg, settings)
	if err != nil {
		t.Fatalf("re-enable err = %v", err)
	}
	calls := readCommandLog(t, logPath)
	if !strings.Contains(calls, "bootout gui/501/"+cfg.Label) || strings.Count(calls, "bootstrap") != 2 {
		t.Fatalf("re-enable must bootout then bootstrap: %q", calls)
	}
	plist, _ := os.ReadFile(cfg.PlistPath)
	if !strings.Contains(string(plist), "<integer>300</integer>") {
		t.Fatalf("plist interval not updated:\n%s", plist)
	}
}

// Disable without a plist or agent is a clean no-op and keeps the state
// file (it carries the last check for status).
func TestDisableFSEventsWatchdogWithoutPlist(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_BOOTOUT", "missing")
	if err := writeJSONState(cfg.StatePath, fseventsWatchdogStateFile{Settings: DefaultFSEventsWatchdogSettings()}); err != nil {
		t.Fatal(err)
	}

	results, err := DisableFSEventsWatchdog(cfg)

	if err != nil || len(results) != 0 {
		t.Fatalf("results = %+v err = %v", results, err)
	}
	if _, err := os.Stat(cfg.StatePath); err != nil {
		t.Fatalf("disable must keep the state file: %v", err)
	}
}

func seedWatchdogState(t *testing.T, cfg FSEventsWatchdogConfig, settings FSEventsWatchdogSettings, last *FSEventsWatchdogCheck) {
	t.Helper()
	if err := writeJSONState(cfg.StatePath, fseventsWatchdogStateFile{Settings: settings, LastCheck: last}); err != nil {
		t.Fatal(err)
	}
}

// A check without a state file refuses instead of inventing thresholds.
func TestRunFSEventsWatchdogCheckRequiresState(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)

	_, err := RunFSEventsWatchdogCheck(cfg, DefaultServiceConfig(), time.Now())

	if err == nil || !strings.Contains(err.Error(), "watchdog state") {
		t.Fatalf("err = %v", err)
	}
	if calls := bytesReadOrEmpty(logPath); len(calls) != 0 {
		t.Fatalf("no command may run without state: %q", calls)
	}
}

// Under the threshold: no notification, no restart, check persisted.
func TestRunFSEventsWatchdogCheckUnderThresholdIsQuiet(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakePS(t, logPath, psLine(368, 1024, fsevents.DaemonPath))
	settings := DefaultFSEventsWatchdogSettings()
	settings.AutoRestart = true
	seedWatchdogState(t, cfg, settings, nil)

	check, err := RunFSEventsWatchdogCheck(cfg, DefaultServiceConfig(), time.Now())

	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if check.OverLimit || check.Notified || check.Restarted || !check.Found || check.PID != 368 {
		t.Fatalf("check = %+v", check)
	}
	if calls := readCommandLog(t, logPath); strings.Contains(calls, "osascript") || strings.Contains(calls, "launchctl") {
		t.Fatalf("quiet check must not notify or restart: %q", calls)
	}
	var state fseventsWatchdogStateFile
	if err := readJSONState(cfg.StatePath, &state); err != nil || state.LastCheck == nil || state.LastCheck.PID != 368 {
		t.Fatalf("last check not persisted: %+v err=%v", state, err)
	}
}

// Over the threshold without auto-restart: notify once, respect the cooldown
// on the next tick, and never contact the root daemon.
func TestRunFSEventsWatchdogCheckNotifiesWithCooldownAndNoRestart(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	eightGB := int64(8 * 1024 * 1024 * 1024)
	withFakePS(t, logPath, psLine(368, eightGB/1024, fsevents.DaemonPath))
	settings := DefaultFSEventsWatchdogSettings()
	seedWatchdogState(t, cfg, settings, nil)
	unreachable := ServiceConfig{Label: "x", PlistPath: "/nonexistent", SocketPath: filepath.Join(t.TempDir(), "missing.sock")}
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	check, err := RunFSEventsWatchdogCheck(cfg, unreachable, now)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !check.OverLimit || !check.Notified || check.Restarted || check.Error != "" {
		t.Fatalf("check = %+v", check)
	}
	calls := readCommandLog(t, logPath)
	if !strings.Contains(calls, "/usr/bin/osascript -e display notification") || !strings.Contains(calls, "fseventsd-restart") {
		t.Fatalf("notification missing or lacks the manual restart hint: %q", calls)
	}

	second, err := RunFSEventsWatchdogCheck(cfg, unreachable, now.Add(settings.Interval))
	if err != nil {
		t.Fatalf("second err = %v", err)
	}
	if second.Notified || !second.OverLimit || !second.LastNotify.Equal(now) {
		t.Fatalf("second tick must respect cooldown: %+v", second)
	}
	if strings.Count(readCommandLog(t, logPath), "osascript") != 1 {
		t.Fatalf("notification sent twice within cooldown: %q", readCommandLog(t, logPath))
	}

	third, err := RunFSEventsWatchdogCheck(cfg, unreachable, now.Add(settings.Interval*watchdogNotifyCooldownMult))
	if err != nil {
		t.Fatalf("third err = %v", err)
	}
	if !third.Notified {
		t.Fatalf("notification must resume after the cooldown: %+v", third)
	}
}

// With auto-restart but an unreachable root daemon the check records the
// restart failure instead of pretending it restarted anything.
func TestRunFSEventsWatchdogCheckAutoRestartUnreachableDaemonIsRecorded(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	eightGB := int64(8 * 1024 * 1024 * 1024)
	withFakePS(t, logPath, psLine(368, eightGB/1024, fsevents.DaemonPath))
	settings := DefaultFSEventsWatchdogSettings()
	settings.AutoRestart = true
	seedWatchdogState(t, cfg, settings, nil)
	unreachable := ServiceConfig{Label: "x", PlistPath: "/nonexistent", SocketPath: filepath.Join(t.TempDir(), "missing.sock")}

	check, err := RunFSEventsWatchdogCheck(cfg, unreachable, time.Now())

	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if check.Restarted || !strings.Contains(check.Error, "restart:") || !check.Notified {
		t.Fatalf("check = %+v", check)
	}
	if !check.LastRestart.IsZero() {
		t.Fatalf("failed restart must not stamp LastRestart: %+v", check)
	}
}

// A notification failure is recorded and does not abort the check.
func TestRunFSEventsWatchdogCheckNotificationFailureIsRecorded(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	eightGB := int64(8 * 1024 * 1024 * 1024)
	withFakePS(t, logPath, psLine(368, eightGB/1024, fsevents.DaemonPath))
	t.Setenv("MAC_INFRA_TEST_OSASCRIPT_FAIL", "1")
	seedWatchdogState(t, cfg, DefaultFSEventsWatchdogSettings(), nil)

	check, err := RunFSEventsWatchdogCheck(cfg, DefaultServiceConfig(), time.Now())

	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if check.Notified || !strings.HasPrefix(check.Error, "notify:") || !check.OverLimit {
		t.Fatalf("check = %+v", check)
	}
}

// Status reports disabled when no agent is loaded but still surfaces the
// persisted settings and last check.
func TestInspectFSEventsWatchdogReportsStateFile(t *testing.T) {
	cfg := watchdogTestConfig(t)
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", "missing")
	last := &FSEventsWatchdogCheck{CheckedAt: time.Now(), Found: true, PID: 368, RSSBytes: 1024}
	seedWatchdogState(t, cfg, DefaultFSEventsWatchdogSettings(), last)

	status, err := InspectFSEventsWatchdog(cfg)

	if err != nil || status.State != FSEventsWatchdogDisabled {
		t.Fatalf("status = %+v err = %v", status, err)
	}
	if status.Settings == nil || status.LastCheck == nil || status.LastCheck.PID != 368 {
		t.Fatalf("status must carry settings and last check: %+v", status)
	}
	if status.UserDomain != "gui/501" {
		t.Fatalf("user domain = %q", status.UserDomain)
	}
}
