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
	cli := filepath.Join(binDir, "mac-chrome-session")
	build := exec.Command("go", "build", "-o", cli, "./cmd/mac-chrome-session")
	build.Dir = projectRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build mac-chrome-session: %v\n%s", err, output)
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
	for _, path := range []string{plist, state, logPath, pinned, stableLauncher, cli} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("managed artifact survived deinit: %s (err=%v)\n%s", path, err, output)
		}
	}
	if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
		t.Fatalf("browser state directory survived deinit: %s (err=%v)", stateDir, err)
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
		`-o "$BUILD_DIR/mac-safari-session" ./cmd/mac-safari-session`,
		`SAFARI_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.safari-session"'`,
		`/usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.safari-session --requirements "=$SAFARI_DESIGNATED_REQUIREMENT" "$BUILD_DIR/mac-safari-session"`,
		`/usr/bin/codesign --verify --strict "$BUILD_DIR/mac-safari-session"`,
		`/usr/bin/codesign -d -r- "$BUILD_DIR/mac-safari-session"`,
		`if [[ "$SAFARI_OBSERVED_REQUIREMENT" != *"$SAFARI_DESIGNATED_REQUIREMENT"* ]]`,
		`ln -sf "$BUILD_DIR/mac-safari-session" "$BIN_DIR/mac-safari-session"`,
		`-o "$BUILD_DIR/mac-chrome-session" ./cmd/mac-chrome-session`,
		`CHROME_DESIGNATED_REQUIREMENT='designated => identifier "works.relux.mac-infra.browser-session"'`,
		`/usr/bin/codesign --force --sign - --identifier works.relux.mac-infra.browser-session --requirements "=$CHROME_DESIGNATED_REQUIREMENT" "$BUILD_DIR/mac-chrome-session"`,
		`/usr/bin/codesign --verify --strict "$BUILD_DIR/mac-chrome-session"`,
		`/usr/bin/codesign -d -r- "$BUILD_DIR/mac-chrome-session"`,
		`if [[ "$CHROME_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]`,
		`HEARTBEAT_LAUNCHER="$HEARTBEAT_LAUNCHER_DIR/mac-browser-heartbeat-launcher"`,
		`HEARTBEAT_LAUNCHER_TMP="$(mktemp "$HEARTBEAT_LAUNCHER_DIR/.mac-browser-heartbeat-launcher.XXXXXX")"`,
		`mv -f "$HEARTBEAT_LAUNCHER_TMP" "$HEARTBEAT_LAUNCHER"`,
		`/usr/bin/codesign --verify --strict "$HEARTBEAT_LAUNCHER"`,
		`/usr/bin/codesign -d -r- "$HEARTBEAT_LAUNCHER"`,
		`if [[ "$HEARTBEAT_OBSERVED_REQUIREMENT" != *"$CHROME_DESIGNATED_REQUIREMENT"* ]]`,
		`ln -sf "$BUILD_DIR/mac-chrome-session" "$BIN_DIR/mac-chrome-session"`,
		`$BIN_DIR/mac-chrome-session -> $BUILD_DIR/mac-chrome-session`,
		`-o "$BUILD_DIR/mac-browser-site" ./cmd/mac-browser-site`,
		`ln -sf "$BUILD_DIR/mac-browser-site" "$BIN_DIR/mac-browser-site"`,
		`$BIN_DIR/mac-browser-site -> $BUILD_DIR/mac-browser-site`,
	} {
		if !strings.Contains(source, want) {
			t.Fatalf("setup.sh missing %q", want)
		}
	}
}
