package maccore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderDisplaySleepLaunchAgentUsesFixedCaffeinateAssertion(t *testing.T) {
	cfg := DisplaySleepPreventionConfig{
		Label:     "works.relux.test-display-sleep",
		PlistPath: "/tmp/test.plist",
		UID:       501,
	}
	plist := string(RenderDisplaySleepLaunchAgent(cfg))

	for _, want := range []string{
		"<string>works.relux.test-display-sleep</string>",
		"<string>/usr/bin/caffeinate</string>",
		"<string>-d</string>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
	} {
		if !strings.Contains(plist, want) {
			t.Fatalf("plist missing %q:\n%s", want, plist)
		}
	}
	if strings.Contains(plist, "pmset") || strings.Contains(plist, "<string>-i</string>") || strings.Contains(plist, "<string>-s</string>") {
		t.Fatalf("plist contains unrelated sleep assertions:\n%s", plist)
	}
}

func TestInspectDisplaySleepPreventionReportsLaunchAgentState(t *testing.T) {
	tests := []struct {
		name      string
		printMode string
		wantState DisplaySleepPreventionState
		wantError string
	}{
		{name: "enabled", printMode: "enabled", wantState: DisplaySleepPreventionStateEnabled},
		{name: "disabled", printMode: "missing", wantState: DisplaySleepPreventionStateDisabled},
		{name: "unavailable", printMode: "failure", wantState: DisplaySleepPreventionStateUnavailable, wantError: "inspect display sleep LaunchAgent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "commands.log")
			withFakeCoreCommand(t, logPath)
			t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", tt.printMode)
			cfg := DisplaySleepPreventionConfig{Label: "works.relux.test-display", PlistPath: "/tmp/display.plist", UID: 501}

			status, err := inspectDisplaySleepPrevention(cfg)

			if status.State != tt.wantState {
				t.Fatalf("status.State = %q, want %q", status.State, tt.wantState)
			}
			if status.AppliesTo != DisplaySleepPreventionAppliesTo || status.UserDomain != "gui/501" {
				t.Fatalf("status = %#v", status)
			}
			if tt.wantError == "" && err != nil {
				t.Fatalf("error = %v", err)
			}
			if tt.wantError != "" && (err == nil || !strings.Contains(err.Error(), tt.wantError)) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestDisplaySleepPreventionEnableInstallsPersistentUserLaunchAgent(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	plistPath := filepath.Join(dir, "LaunchAgents", "display.plist")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", "missing")
	cfg := DisplaySleepPreventionConfig{Label: "works.relux.test-display", PlistPath: plistPath, UID: 501}

	results, err := enableDisplaySleepPrevention(cfg)

	if err != nil {
		t.Fatalf("enable error = %v", err)
	}
	if len(results) != 1 || results[0].Command != "/bin/launchctl bootstrap gui/501 "+plistPath {
		t.Fatalf("results = %#v", results)
	}
	raw, err := os.ReadFile(plistPath)
	if err != nil {
		t.Fatalf("read installed plist: %v", err)
	}
	if !strings.Contains(string(raw), "/usr/bin/caffeinate") || !strings.Contains(string(raw), "<string>-d</string>") {
		t.Fatalf("installed plist = %s", raw)
	}
	wantCalls := "/bin/launchctl print gui/501/works.relux.test-display\n" +
		"/bin/launchctl bootstrap gui/501 " + plistPath + "\n"
	if calls := readCommandLog(t, logPath); calls != wantCalls {
		t.Fatalf("calls = %q, want %q", calls, wantCalls)
	}
}

func TestDisplaySleepPreventionEnableIsIdempotentWhenLoaded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	plistPath := filepath.Join(dir, "display.plist")
	if err := os.WriteFile(plistPath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_PRINT", "enabled")
	cfg := DisplaySleepPreventionConfig{Label: "works.relux.test-display", PlistPath: plistPath, UID: 501}

	results, err := enableDisplaySleepPrevention(cfg)

	if err != nil || results != nil {
		t.Fatalf("results = %#v error = %v", results, err)
	}
	if calls := readCommandLog(t, logPath); calls != "/bin/launchctl print gui/501/works.relux.test-display\n" {
		t.Fatalf("calls = %q", calls)
	}
}

func TestDisplaySleepPreventionDisableBootsOutAndRemovesPlist(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	plistPath := filepath.Join(dir, "display.plist")
	if err := os.WriteFile(plistPath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	withFakeCoreCommand(t, logPath)
	cfg := DisplaySleepPreventionConfig{Label: "works.relux.test-display", PlistPath: plistPath, UID: 501}

	results, err := disableDisplaySleepPrevention(cfg)

	if err != nil {
		t.Fatalf("disable error = %v", err)
	}
	if len(results) != 1 || results[0].Command != "/bin/launchctl bootout gui/501/works.relux.test-display" {
		t.Fatalf("results = %#v", results)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Fatalf("plist still exists: %v", err)
	}
}

func TestDisplaySleepPreventionDisableRemovesStalePlistWhenNotLoaded(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	plistPath := filepath.Join(dir, "display.plist")
	if err := os.WriteFile(plistPath, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_LAUNCHCTL_BOOTOUT", "missing")
	cfg := DisplaySleepPreventionConfig{Label: "works.relux.test-display", PlistPath: plistPath, UID: 501}

	results, err := disableDisplaySleepPrevention(cfg)

	if err != nil || len(results) != 0 {
		t.Fatalf("results = %#v error = %v", results, err)
	}
	if _, err := os.Stat(plistPath); !os.IsNotExist(err) {
		t.Fatalf("stale plist still exists: %v", err)
	}
}
