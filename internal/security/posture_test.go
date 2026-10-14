package security

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Exact known enabled/disabled responses are paired controls. Unknown,
// localized, custom-configuration and transitional responses remain unavailable.
func TestPostureStrictProtectionStates(t *testing.T) {
	for _, tc := range []struct {
		name, path        string
		args              []string
		enabled, disabled string
	}{
		{"sip", "/usr/bin/csrutil", []string{"status"}, "System Integrity Protection status: enabled.", "System Integrity Protection status: disabled."},
		{"gatekeeper", "/usr/sbin/spctl", []string{"--status"}, "assessments enabled", "assessments disabled"},
		{"filevault", "/usr/bin/fdesetup", []string{"status"}, "FileVault is On.", "FileVault is Off."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			known := map[string]string{tc.enabled: "enabled", tc.disabled: "disabled"}
			key := tc.path + " " + strings.Join(tc.args, " ")
			for _, out := range []string{tc.enabled, tc.disabled} {
				c := postureState(context.Background(), checksOutput(key, out+"\n"), tc.name, tc.path, tc.args, known)
				if c.Status != "ok" || c.Data["state"] != known[out] {
					t.Fatalf("state %#v", c)
				}
				if (len(c.Findings) > 0) != (out == tc.disabled) {
					t.Fatalf("disabled finding %#v", c)
				}
			}
			for _, out := range []string{"", tc.enabled + "\nsecret-extra", "activé", "System Integrity Protection status: unknown (Custom Configuration).", "Encryption in progress: Percent completed = 42"} {
				c := postureState(context.Background(), checksOutput(key, out), tc.name, tc.path, tc.args, known)
				if c.Status != "unavailable" || c.Data != nil {
					t.Fatal("accepted unknown protection response")
				}
			}
			r := checksOutput(key, tc.enabled)
			r.errs[key] = errors.New("private-token")
			c := postureState(context.Background(), r, tc.name, tc.path, tc.args, known)
			b, _ := json.Marshal(c)
			if c.Status != "unavailable" || strings.Contains(string(b), "private-token") {
				t.Fatal("failed command trusted or leaked")
			}
		})
	}
}
func checksUpdateRunner(value string) *checksFixtureRunner {
	r := checksOutput("", "")
	for _, key := range updatePreferenceNames {
		domain := "/Library/Preferences/com.apple.SoftwareUpdate"
		if key == "AutoUpdate" {
			domain = "/Library/Preferences/com.apple.commerce"
		}
		r.output["/usr/bin/defaults read "+domain+" "+key] = value
	}
	return r
}

// Explicit preferences alone drive the result: missing, malformed and failed
// keys stay unknown, including when a failed read contains a valid-looking 1.
func TestPostureUpdatePreferencesDoNotInventDefaults(t *testing.T) {
	r := checksUpdateRunner("1")
	c := softwareUpdatePosture(context.Background(), r)
	if c.Status != "ok" || len(c.Findings) != 0 {
		t.Fatalf("enabled preferences %#v", c)
	}
	for _, value := range []string{"0", "", "true", "2", "1\n0"} {
		r := checksUpdateRunner(value)
		c := softwareUpdatePosture(context.Background(), r)
		if value == "0" {
			if c.Status != "ok" || len(c.Findings) != 6 {
				t.Fatalf("disabled preferences %#v", c)
			}
		} else {
			if c.Status != "unavailable" {
				t.Fatalf("unknown preferences %#v", c)
			}
		}
	}
	key := "/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled"
	r = checksUpdateRunner("1")
	r.errs[key] = errors.New("secret-password")
	c = softwareUpdatePosture(context.Background(), r)
	states := c.Data["preferences"].(map[string]string)
	b, _ := json.Marshal(c)
	if c.Status != "partial" || states["AutomaticCheckEnabled"] != "unknown" || states["AutomaticDownload"] != "enabled" || strings.Contains(string(b), "secret-password") {
		t.Fatalf("partial preferences %#v", c)
	}
}

// An installed numeric version is reported with partial coverage, never as
// freshness or a clean-host verdict; malformed and failed versions are refused.
func TestPostureXProtectVersionIsLimitedEvidence(t *testing.T) {
	key := "/usr/bin/defaults read /Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info CFBundleShortVersionString"
	for _, version := range []string{"5292", "1.2.3", "1.2.3.4"} {
		c := xprotectPosture(context.Background(), checksOutput(key, version+"\n"))
		if c.Status != "partial" || c.Data["version"] != version || len(c.Findings) != 1 {
			t.Fatalf("version %#v", c)
		}
	}
	for _, version := range []string{"", "latest", "1.2 secret", "1.2\nsecret", "1.2.3.4.5", "-1", strings.Repeat("1", 65)} {
		c := xprotectPosture(context.Background(), checksOutput(key, version))
		if c.Status != "unavailable" || c.Data != nil {
			t.Fatal("accepted malformed version")
		}
	}
	r := checksOutput(key, "5292")
	r.errs[key] = errors.New("secret token")
	c := xprotectPosture(context.Background(), r)
	if c.Status != "unavailable" {
		t.Fatal("trusted failed version read")
	}
}

// The public collectors issue only the selected fixed read-only command
// vocabulary, retain per-check timing and command exit evidence, and return
// explicit checks even when all evidence is missing.
func TestSecurityCollectorsFixedCommandsAndAbsentEvidence(t *testing.T) {
	r := checksOutput("", "")
	exposure := Exposure(context.Background(), r)
	posture := Posture(context.Background(), r)
	if len(exposure) != 5 || len(posture) != 5 || len(r.calls) != 15 {
		t.Fatalf("unexpected coverage checks=%d/%d calls=%d", len(exposure), len(posture), len(r.calls))
	}
	for _, c := range append(exposure, posture...) {
		if c.Status == "ok" {
			t.Fatalf("missing output established known state: %s", c.Name)
		}
		expectedCommands := 1
		if c.Name == "software_update" {
			expectedCommands = 6
		}
		if c.StartedAt.IsZero() || c.FinishedAt.IsZero() || c.StartedAt.After(c.FinishedAt) || len(c.Commands) != expectedCommands {
			t.Fatalf("missing observation metadata for %s", c.Name)
		}
		for _, command := range c.Commands {
			if command.ExitCode == nil || *command.ExitCode != 0 {
				t.Fatalf("missing successful fixture exit code for %s", c.Name)
			}
		}
	}
}
