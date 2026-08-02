package maccore

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type DisplaySleepPreventionState string

const (
	displaySleepLaunchAgentLabel                                       = "works.relux.mac-infra-display-sleep-prevention"
	displaySleepCaffeinatePath                                         = "/usr/bin/caffeinate"
	launchctlPath                                                      = "/bin/launchctl"
	DisplaySleepPreventionAppliesTo                                    = "AC,battery"
	DisplaySleepPreventionStateEnabled     DisplaySleepPreventionState = "enabled"
	DisplaySleepPreventionStateDisabled    DisplaySleepPreventionState = "disabled"
	DisplaySleepPreventionStateUnavailable DisplaySleepPreventionState = "unavailable"
)

type DisplaySleepPreventionConfig struct {
	Label     string
	PlistPath string
	UID       int
}

type DisplaySleepPreventionStatus struct {
	State      DisplaySleepPreventionState
	AppliesTo  string
	Label      string
	PlistPath  string
	UserDomain string
}

func DefaultDisplaySleepPreventionConfig() (DisplaySleepPreventionConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return DisplaySleepPreventionConfig{}, fmt.Errorf("resolve user home: %w", err)
	}
	return DisplaySleepPreventionConfig{
		Label:     displaySleepLaunchAgentLabel,
		PlistPath: filepath.Join(home, "Library", "LaunchAgents", displaySleepLaunchAgentLabel+".plist"),
		UID:       os.Getuid(),
	}, nil
}

func InspectDisplaySleepPrevention() (DisplaySleepPreventionStatus, error) {
	cfg, err := DefaultDisplaySleepPreventionConfig()
	if err != nil {
		return unavailableDisplaySleepPreventionStatus(DisplaySleepPreventionConfig{}), err
	}
	return inspectDisplaySleepPrevention(cfg)
}

func EnableDisplaySleepPrevention() ([]CommandResult, error) {
	cfg, err := DefaultDisplaySleepPreventionConfig()
	if err != nil {
		return nil, err
	}
	return enableDisplaySleepPrevention(cfg)
}

func DisableDisplaySleepPrevention() ([]CommandResult, error) {
	cfg, err := DefaultDisplaySleepPreventionConfig()
	if err != nil {
		return nil, err
	}
	return disableDisplaySleepPrevention(cfg)
}

func inspectDisplaySleepPrevention(cfg DisplaySleepPreventionConfig) (DisplaySleepPreventionStatus, error) {
	if err := validateDisplaySleepPreventionConfig(cfg); err != nil {
		return unavailableDisplaySleepPreventionStatus(cfg), err
	}
	status := DisplaySleepPreventionStatus{
		State:      DisplaySleepPreventionStateDisabled,
		AppliesTo:  DisplaySleepPreventionAppliesTo,
		Label:      cfg.Label,
		PlistPath:  cfg.PlistPath,
		UserDomain: launchctlUserDomain(cfg),
	}
	_, err := runCoreCommand(launchctlPath, "print", launchctlServiceTarget(cfg))
	if err == nil {
		status.State = DisplaySleepPreventionStateEnabled
		return status, nil
	}
	if isLaunchctlServiceMissing(err) {
		return status, nil
	}
	status.State = DisplaySleepPreventionStateUnavailable
	return status, fmt.Errorf("inspect display sleep LaunchAgent: %w", err)
}

func enableDisplaySleepPrevention(cfg DisplaySleepPreventionConfig) ([]CommandResult, error) {
	status, err := inspectDisplaySleepPrevention(cfg)
	if err != nil {
		return nil, err
	}
	if status.State == DisplaySleepPreventionStateEnabled {
		if _, statErr := os.Stat(cfg.PlistPath); statErr == nil {
			return nil, nil
		} else if !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("inspect display sleep LaunchAgent plist: %w", statErr)
		}
	}

	plist := RenderDisplaySleepLaunchAgent(cfg)
	if err := writeFileAtomically(cfg.PlistPath, plist, 0o755, 0o644); err != nil {
		return nil, fmt.Errorf("install display sleep LaunchAgent plist: %w", err)
	}
	if status.State == DisplaySleepPreventionStateEnabled {
		return nil, nil
	}
	result, err := runCoreCommand(launchctlPath, "bootstrap", launchctlUserDomain(cfg), cfg.PlistPath)
	return []CommandResult{result}, err
}

func disableDisplaySleepPrevention(cfg DisplaySleepPreventionConfig) ([]CommandResult, error) {
	if err := validateDisplaySleepPreventionConfig(cfg); err != nil {
		return nil, err
	}
	results := []CommandResult{}
	result, err := runCoreCommand(launchctlPath, "bootout", launchctlServiceTarget(cfg))
	if err != nil && !isLaunchctlServiceMissing(err) {
		return []CommandResult{result}, err
	}
	if err == nil {
		results = append(results, result)
	}
	if err := os.Remove(cfg.PlistPath); err != nil && !os.IsNotExist(err) {
		return results, fmt.Errorf("remove display sleep LaunchAgent plist: %w", err)
	}
	return results, nil
}

func RenderDisplaySleepLaunchAgent(cfg DisplaySleepPreventionConfig) []byte {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	builder.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	builder.WriteString(`<plist version="1.0">` + "\n")
	builder.WriteString(`<dict>` + "\n")
	builder.WriteString(`  <key>Label</key>` + "\n")
	builder.WriteString(`  <string>` + plistEscape(cfg.Label) + `</string>` + "\n")
	builder.WriteString(`  <key>ProgramArguments</key>` + "\n")
	builder.WriteString(`  <array>` + "\n")
	builder.WriteString(`    <string>` + displaySleepCaffeinatePath + `</string>` + "\n")
	builder.WriteString(`    <string>-d</string>` + "\n")
	builder.WriteString(`  </array>` + "\n")
	builder.WriteString(`  <key>RunAtLoad</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`  <key>KeepAlive</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`</dict>` + "\n")
	builder.WriteString(`</plist>` + "\n")
	return []byte(builder.String())
}

func launchctlUserDomain(cfg DisplaySleepPreventionConfig) string {
	return "gui/" + strconv.Itoa(cfg.UID)
}

func launchctlServiceTarget(cfg DisplaySleepPreventionConfig) string {
	return launchctlUserDomain(cfg) + "/" + cfg.Label
}

func validateDisplaySleepPreventionConfig(cfg DisplaySleepPreventionConfig) error {
	if cfg.Label == "" || cfg.PlistPath == "" || cfg.UID < 0 {
		return fmt.Errorf("invalid display sleep prevention config")
	}
	return nil
}

func isLaunchctlServiceMissing(err error) bool {
	switch exitCode(err) {
	case 3, 113:
		return true
	default:
		return false
	}
}

func unavailableDisplaySleepPreventionStatus(cfg DisplaySleepPreventionConfig) DisplaySleepPreventionStatus {
	userDomain := ""
	if cfg.UID >= 0 {
		userDomain = launchctlUserDomain(cfg)
	}
	return DisplaySleepPreventionStatus{
		State:      DisplaySleepPreventionStateUnavailable,
		AppliesTo:  DisplaySleepPreventionAppliesTo,
		Label:      cfg.Label,
		PlistPath:  cfg.PlistPath,
		UserDomain: userDomain,
	}
}
