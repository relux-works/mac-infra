package maccore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testScreenSaverPlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>idleTime</key><integer>3600</integer>
<key>showClock</key><true/>
</dict></plist>`

func TestParseScreenSaverIdleTime(t *testing.T) {
	tests := []struct {
		name        string
		output      string
		wantSeconds int
		wantPresent bool
		wantError   string
	}{
		{name: "present", output: testScreenSaverPlist, wantSeconds: 3600, wantPresent: true},
		{name: "disabled", output: `<plist><dict><key>idleTime</key><integer>0</integer></dict></plist>`, wantSeconds: 0, wantPresent: true},
		{name: "absent", output: `<plist><dict><key>showClock</key><true/></dict></plist>`, wantSeconds: -1},
		{name: "malformed", output: `<plist><dict><key>idleTime</key><string>never</string></dict></plist>`, wantSeconds: -1, wantError: "malformed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seconds, present, err := ParseScreenSaverIdleTime(tt.output)
			if seconds != tt.wantSeconds || present != tt.wantPresent {
				t.Fatalf("got seconds=%d present=%v, want seconds=%d present=%v", seconds, present, tt.wantSeconds, tt.wantPresent)
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

func TestIdleLockPreventionEnableAndDisableRestoreCapturedIdleTime(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	cfg := IdleLockPreventionConfig{StatePath: filepath.Join(dir, "idle-lock.json")}
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_SCREENSAVER_OUTPUT", testScreenSaverPlist)

	if _, err := applyIdleLockPrevention(cfg, true); err != nil {
		t.Fatalf("enable error = %v", err)
	}
	if _, err := applyIdleLockPrevention(cfg, false); err != nil {
		t.Fatalf("disable error = %v", err)
	}
	if _, err := os.Stat(cfg.StatePath); !os.IsNotExist(err) {
		t.Fatalf("saved state still exists after restore: %v", err)
	}

	wantCalls := strings.Join([]string{
		"/usr/bin/defaults -currentHost export com.apple.screensaver -",
		"/usr/bin/defaults -currentHost write com.apple.screensaver idleTime -int 0",
		"/usr/bin/defaults -currentHost write com.apple.screensaver idleTime -int 3600",
		"",
	}, "\n")
	if calls := readCommandLog(t, logPath); calls != wantCalls {
		t.Fatalf("calls = %q, want %q", calls, wantCalls)
	}
}

func TestIdleLockPreventionRestoresMissingIdleTimeByDeletingKey(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	cfg := IdleLockPreventionConfig{StatePath: filepath.Join(dir, "idle-lock.json")}
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_SCREENSAVER_OUTPUT", `<plist><dict><key>showClock</key><true/></dict></plist>`)

	if _, err := applyIdleLockPrevention(cfg, true); err != nil {
		t.Fatalf("enable error = %v", err)
	}
	if _, err := applyIdleLockPrevention(cfg, false); err != nil {
		t.Fatalf("disable error = %v", err)
	}
	if calls := readCommandLog(t, logPath); !strings.Contains(calls, "/usr/bin/defaults -currentHost delete com.apple.screensaver idleTime") {
		t.Fatalf("missing idleTime was not restored by deleting the key:\n%s", calls)
	}
}

func TestIdleLockPreventionDisableWithoutSnapshotIsNoOpWhenAlreadyDisabled(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_SCREENSAVER_OUTPUT", testScreenSaverPlist)
	cfg := IdleLockPreventionConfig{StatePath: filepath.Join(dir, "missing.json")}

	results, err := applyIdleLockPrevention(cfg, false)
	if err != nil {
		t.Fatalf("error = %v, want already-disabled no-op", err)
	}
	if results != nil {
		t.Fatalf("results = %#v, want nil", results)
	}
	if calls := readCommandLog(t, logPath); calls != "/usr/bin/defaults -currentHost export com.apple.screensaver -\n" {
		t.Fatalf("calls = %q", calls)
	}
}

func TestIdleLockPreventionDisableWithoutSnapshotRefusesUnknownRestore(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_SCREENSAVER_OUTPUT", `<plist><dict><key>idleTime</key><integer>0</integer></dict></plist>`)
	cfg := IdleLockPreventionConfig{StatePath: filepath.Join(dir, "missing.json")}

	results, err := applyIdleLockPrevention(cfg, false)
	if err == nil || !strings.Contains(err.Error(), "refusing to invent restore values") {
		t.Fatalf("error = %v, want safe refusal", err)
	}
	if results != nil {
		t.Fatalf("results = %#v, want nil", results)
	}
}
