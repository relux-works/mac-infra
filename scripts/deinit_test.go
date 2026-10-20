package scripts_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/mac-infra/internal/browsersession"
)

// With fake service CLIs, deinit orders cleanup before removing tools (including
// mac-netnone). This checks script orchestration, not live LaunchAgent cleanup.
// Real service CLIs must not run here: label-addressed launchctl bootout can unload the live fseventsd watchdog.
func TestDeinitStopsManagedHeartbeatsBeforeRemovingCLI(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("deinit LaunchAgent contract is macOS-specific")
	}
	projectRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	binDir := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	netnoneCLI := fakeTool(t, binDir, "mac-netnone", "exit 99")
	cli := fakeTool(t, binDir, "mac-chrome-session", `set -eu
 test -x "$BIN_DIR/mac-chrome-session"
 test -x "$BIN_DIR/mac-netnone"
 printf '%s\n' "$*" >> "$HOME/deinit-calls"
 case "$*" in
  'heartbeat stop --name deinit-test')
   rm -f "$HOME/Library/LaunchAgents/works.relux.mac-infra-browser-heartbeat.deinit-test.plist"
   rm -f "$HOME/Library/Application Support/mac-infra/browser-session/deinit-test.json"
   rm -f "$HOME/Library/Application Support/mac-infra/browser-session/deinit-test.log"
   rm -f "$HOME/Library/Application Support/mac-infra/browser-session/bin/mac-browser-session-test" ;;
  'heartbeat stop --all') ;;
  *) exit 99 ;;
 esac`)
	coreCLI := fakeTool(t, binDir, "mac-infra-core", `set -eu
 test -x "$BIN_DIR/mac-infra-core"
 test -x "$BIN_DIR/mac-netnone"
 printf '%s\n' "$*" >> "$HOME/deinit-calls"
 case "$*" in
  'idle-lock-prevention disable'|'display-sleep-prevention disable') ;;
  'fseventsd-watchdog disable')
   rm -f "$HOME/Library/LaunchAgents/works.relux.mac-infra-fseventsd-watchdog.plist" ;;
  *) exit 99 ;;
 esac`)
	watchdogPlist := filepath.Join(home, "Library", "LaunchAgents", "works.relux.mac-infra-fseventsd-watchdog.plist")
	if err := os.MkdirAll(filepath.Dir(watchdogPlist), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watchdogPlist, []byte("plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(home, browsersession.DefaultStateDir)
	pinned := filepath.Join(stateDir, "bin", "mac-browser-session-test")
	stableLauncher := filepath.Join(stateDir, "bin", browsersession.HeartbeatLauncherName)
	plist := filepath.Join(home, "Library", "LaunchAgents", browsersession.HeartbeatLabelPrefix+"deinit-test.plist")
	state := filepath.Join(stateDir, "deinit-test.json")
	logPath := filepath.Join(stateDir, "deinit-test.log")
	for _, dir := range []string{filepath.Dir(pinned), filepath.Dir(plist)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(pinned, []byte("pinned"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stableLauncher, []byte("stable launcher"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("plist"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := browsersession.HeartbeatConfig{
		Name:       "deinit-test",
		Browser:    browsersession.BrowserChrome,
		WindowID:   "1",
		TabID:      "2",
		Origin:     "https://example.com",
		Interval:   15 * time.Second,
		Executable: pinned,
		Label:      browsersession.HeartbeatLabelPrefix + "deinit-test",
		PlistPath:  plist,
		LogPath:    logPath,
		StatePath:  state,
		UID:        os.Getuid(),
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("/bin/bash", filepath.Join(projectRoot, "scripts", "deinit.sh"))
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "HOME="+home, "BIN_DIR="+binDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("deinit failed: %v\n%s", err, output)
	}
	for _, path := range []string{plist, state, logPath, pinned, stableLauncher, cli, coreCLI, netnoneCLI, watchdogPlist} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed artifact survived deinit: %s (err=%v)\n%s", path, err, output)
		}
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("browser state directory survived deinit: %s (err=%v)", stateDir, err)
	}
	calls, err := os.ReadFile(filepath.Join(home, "deinit-calls"))
	if err != nil || string(calls) != "heartbeat stop --name deinit-test\nheartbeat stop --all\nidle-lock-prevention disable\ndisplay-sleep-prevention disable\nfseventsd-watchdog disable\n" {
		t.Fatalf("cleanup calls/order: %q (%v)", calls, err)
	}
	if !strings.Contains(string(output), "managed browser heartbeats") {
		t.Fatalf("deinit output does not report browser heartbeat cleanup:\n%s", output)
	}
}

func TestSetupBuildsAndInstallsChromeSessionCLI(t *testing.T) {
	projectRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(projectRoot, "scripts", "setup.sh"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	for _, want := range []string{
		`-o "$STAGE_DIR/mac-safari-session" ./cmd/mac-safari-session`,
		`SAFARI_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.safari-session"'`,
		`/usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.safari-session --requirements "=$SAFARI_DESIGNATED_REQUIREMENT" "$STAGE_DIR/mac-safari-session"`,
		`/usr/bin/codesign --verify --strict "$STAGE_DIR/mac-safari-session"`,
		`/usr/bin/codesign -d -r- "$STAGE_DIR/mac-safari-session"`,
		`if [[ "$SAFARI_OBSERVED_REQUIREMENT" != *"$SAFARI_DESIGNATED_REQUIREMENT"* ]]`,
		`ln -sf "$BUILD_DIR/mac-safari-session" "$BIN_DIR/mac-safari-session"`,
		`-o "$STAGE_DIR/mac-chrome-session" ./cmd/mac-chrome-session`,
		`CHROME_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.browser-session"'`,
		`/usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.browser-session --requirements "=$CHROME_DESIGNATED_REQUIREMENT" "$STAGE_DIR/mac-chrome-session"`,
		`/usr/bin/codesign --verify --strict "$STAGE_DIR/mac-chrome-session"`,
		`/usr/bin/codesign -d -r- "$STAGE_DIR/mac-chrome-session"`,
		`if [[ "$CHROME_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]`,
		`HEARTBEAT_LAUNCHER="$HEARTBEAT_LAUNCHER_DIR/mac-browser-heartbeat-launcher"`,
		`HEARTBEAT_LAUNCHER_TMP="$(mktemp "$HEARTBEAT_LAUNCHER_DIR/.mac-browser-heartbeat-launcher.XXXXXX")"`,
		`mv -f "$HEARTBEAT_LAUNCHER_TMP" "$HEARTBEAT_LAUNCHER"`,
		`/usr/bin/codesign --verify --strict "$HEARTBEAT_LAUNCHER"`,
		`/usr/bin/codesign -d -r- "$HEARTBEAT_LAUNCHER"`,
		`if [[ "$HEARTBEAT_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]`,
		`ln -sf "$BUILD_DIR/mac-chrome-session" "$BIN_DIR/mac-chrome-session"`,
		`$BIN_DIR/mac-chrome-session -> $BUILD_DIR/mac-chrome-session`,
		`-o "$STAGE_DIR/mac-browser-site" ./cmd/mac-browser-site`,
		`ln -sf "$BUILD_DIR/mac-browser-site" "$BIN_DIR/mac-browser-site"`,
		`$BIN_DIR/mac-browser-site -> $BUILD_DIR/mac-browser-site`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("setup.sh missing %q", want)
		}
	}
}

// Static install contract: mac-netnone uses the common version flags, is linked
// and reported during setup, and its link is included in deinit's removal list.
func TestSetupInstallsAndDeinitRemovesNetnone(t *testing.T) {
	setup, err := os.ReadFile("setup.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`go -C "$PROJECT_ROOT" build -trimpath -ldflags "$LDFLAGS" -o "$STAGE_DIR/mac-netnone" ./cmd/mac-netnone`,
		`ln -sf "$BUILD_DIR/mac-netnone" "$BIN_DIR/mac-netnone"`,
		`echo "  $BIN_DIR/mac-netnone -> $BUILD_DIR/mac-netnone"`,
	} {
		if !strings.Contains(string(setup), want) {
			t.Fatalf("setup missing %q", want)
		}
	}
	deinit, err := os.ReadFile("deinit.sh")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range strings.Split(string(deinit), "\n") {
		if strings.HasPrefix(line, "rm -f ") && strings.Contains(line, `"$BIN_DIR/mac-netnone"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("deinit removal list omits mac-netnone")
	}
}

// Missing heartbeat CLI refuses deinit before deleting the installed netnone
// link or the heartbeat plist. The fake-backed success case is the control.
func TestDeinitRefusesMissingHeartbeatCLI(t *testing.T) {
	home := t.TempDir()
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatal(err)
	}
	netnone := fakeTool(t, binDir, "mac-netnone", "exit 99")
	plist := filepath.Join(home, "Library/LaunchAgents/works.relux.mac-infra-browser-heartbeat.missing.plist")
	if err := os.MkdirAll(filepath.Dir(plist), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plist, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", "deinit.sh")
	cmd.Env = append(os.Environ(), "HOME="+home, "BIN_DIR="+binDir)
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "refusing to strand LaunchAgents") {
		t.Fatalf("wrong refusal: %v %s", err, output)
	}
	for _, path := range []string{netnone, plist} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("refusal removed %s: %v", path, err)
		}
	}
}
