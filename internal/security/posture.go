package security

import (
	"context"
	"regexp"
	"strings"
)

// Posture reads protection state and explicit update preferences. It does not
// infer update freshness or a clean host from installed protection components.
func Posture(ctx context.Context, r Runner) []Check {
	return []Check{
		Observe(ctx, r, func(ctx context.Context, r Runner) Check {
			return postureState(ctx, r, "sip", "/usr/bin/csrutil", []string{"status"}, map[string]string{"System Integrity Protection status: enabled.": "enabled", "System Integrity Protection status: disabled.": "disabled"})
		}),
		Observe(ctx, r, func(ctx context.Context, r Runner) Check {
			return postureState(ctx, r, "gatekeeper", "/usr/sbin/spctl", []string{"--status"}, map[string]string{"assessments enabled": "enabled", "assessments disabled": "disabled"})
		}),
		Observe(ctx, r, func(ctx context.Context, r Runner) Check {
			return postureState(ctx, r, "filevault", "/usr/bin/fdesetup", []string{"status"}, map[string]string{"FileVault is On.": "enabled", "FileVault is Off.": "disabled"})
		}),
		Observe(ctx, r, softwareUpdatePosture), Observe(ctx, r, xprotectPosture),
	}
}
func postureState(ctx context.Context, r Runner, name, path string, args []string, known map[string]string) Check {
	b, e := r.Run(ctx, path, args...)
	if e != nil {
		return securityUnavailable(name, "Protection state could not be read.", false)
	}
	state, ok := known[strings.TrimSpace(string(b))]
	if !ok {
		return securityUnavailable(name, "Protection state output was not recognized.", false)
	}
	c := securityResult(name, "ok")
	c.Data = map[string]any{"state": state}
	if state == "disabled" {
		c.Findings = append(c.Findings, Finding{Check: name, Severity: "warning", Code: name + "_disabled", Detail: "The protection reports disabled."})
	}
	return c
}

var updatePreferenceNames = []string{"AutomaticCheckEnabled", "AutomaticDownload", "ConfigDataInstall", "CriticalUpdateInstall", "AutomaticallyInstallMacOSUpdates", "AutoUpdate"}

func softwareUpdatePosture(ctx context.Context, r Runner) Check {
	const name = "software_update"
	c := securityResult(name, "ok")
	states := map[string]string{}
	known := 0
	for _, key := range updatePreferenceNames {
		domain := "/Library/Preferences/com.apple.SoftwareUpdate"
		if key == "AutoUpdate" {
			domain = "/Library/Preferences/com.apple.commerce"
		}
		b, e := r.Run(ctx, "/usr/bin/defaults", "read", domain, key)
		states[key] = "unknown"
		if e != nil {
			continue
		}
		switch strings.TrimSpace(string(b)) {
		case "1":
			states[key] = "enabled"
			known++
		case "0":
			states[key] = "disabled"
			known++
		}
		if states[key] == "disabled" {
			c.Findings = append(c.Findings, Finding{Check: name, Severity: "warning", Code: "automatic_update_preference_disabled", Detail: "An explicit automatic update preference reports disabled: " + key + "."})
		}
	}
	if known < len(updatePreferenceNames) {
		c.Status = "partial"
		if known == 0 {
			c.Status = "unavailable"
		}
		c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "update_preferences_unknown", Detail: "Missing or unrecognized update preferences remain unknown; system defaults and update freshness are not inferred."})
	}
	c.Data = map[string]any{"preferences": states, "coverage": "explicit system preferences only; effective managed policy and installed update freshness are not established"}
	return c
}

var xprotectVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)

func xprotectPosture(ctx context.Context, r Runner) Check {
	const name = "xprotect"
	b, e := r.Run(ctx, "/usr/bin/defaults", "read", "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info", "CFBundleShortVersionString")
	if e != nil {
		return securityUnavailable(name, "XProtect component version could not be read at the supported system path.", false)
	}
	version := strings.TrimSpace(string(b))
	if len(version) > 64 || !xprotectVersionPattern.MatchString(version) {
		return securityUnavailable(name, "XProtect component version output was not recognized.", false)
	}
	c := securityResult(name, "partial")
	c.Data = map[string]any{"version": version, "coverage": "installed component version only; currency, activation, and detection results are not established"}
	c.Findings = append(c.Findings, Finding{Check: name, Severity: "info", Code: "xprotect_version_only", Detail: "An installed XProtect version does not establish current signatures, successful protection, or the absence of malware."})
	return c
}
