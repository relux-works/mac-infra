package maccore

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/relux-works/mac-infra/internal/fsevents"
	"github.com/relux-works/mac-infra/internal/loadprofile"
)

// The watchdog is a current-user LaunchAgent that runs `mac-infra-core
// _fseventsd-check` on a fixed interval. It notifies when fseventsd RSS
// crosses the threshold and, only when the user opted in, restarts it
// through the root daemon. It never renices or throttles fseventsd.

const (
	fseventsWatchdogLabel      = "works.relux.mac-infra-fseventsd-watchdog"
	fseventsWatchdogCheckVerb  = "_fseventsd-check"
	osascriptPath              = "/usr/bin/osascript"
	DefaultWatchdogInterval    = 10 * time.Minute
	minWatchdogInterval        = time.Minute
	FSEventsWatchdogStateName  = "fseventsd-watchdog.json"
	FSEventsWatchdogStateDirs  = "mac-infra"
	watchdogNotifyCooldownMult = 6 // re-notify at most once per 6 intervals while still over threshold
)

type FSEventsWatchdogState string

const (
	FSEventsWatchdogEnabled     FSEventsWatchdogState = "enabled"
	FSEventsWatchdogDisabled    FSEventsWatchdogState = "disabled"
	FSEventsWatchdogUnavailable FSEventsWatchdogState = "unavailable"
)

type FSEventsWatchdogConfig struct {
	Label      string
	PlistPath  string
	StatePath  string
	BinaryPath string
	UID        int
}

// FSEventsWatchdogSettings is what the user chose at enable time; the check
// mode reads it back from the state file so the plist stays fixed.
type FSEventsWatchdogSettings struct {
	RSSThresholdBytes int64         `json:"rss_threshold_bytes"`
	Interval          time.Duration `json:"interval_ns"`
	AutoRestart       bool          `json:"auto_restart"`
	EnabledAt         time.Time     `json:"enabled_at"`
}

type FSEventsWatchdogCheck struct {
	CheckedAt   time.Time `json:"checked_at"`
	Found       bool      `json:"found"`
	PID         int       `json:"pid,omitempty"`
	RSSBytes    int64     `json:"rss_bytes"`
	CPU         float64   `json:"cpu"`
	OverLimit   bool      `json:"over_limit"`
	Notified    bool      `json:"notified"`
	Restarted   bool      `json:"restarted"`
	Error       string    `json:"error,omitempty"`
	LastNotify  time.Time `json:"last_notify,omitempty"`
	LastRestart time.Time `json:"last_restart,omitempty"`
}

type fseventsWatchdogStateFile struct {
	Settings  FSEventsWatchdogSettings `json:"settings"`
	LastCheck *FSEventsWatchdogCheck   `json:"last_check,omitempty"`
}

type FSEventsWatchdogStatus struct {
	State      FSEventsWatchdogState
	Label      string
	PlistPath  string
	StatePath  string
	UserDomain string
	Settings   *FSEventsWatchdogSettings
	LastCheck  *FSEventsWatchdogCheck
}

func DefaultFSEventsWatchdogConfig(binaryPath string) (FSEventsWatchdogConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return FSEventsWatchdogConfig{}, fmt.Errorf("resolve user home: %w", err)
	}
	return FSEventsWatchdogConfig{
		Label:      fseventsWatchdogLabel,
		PlistPath:  filepath.Join(home, "Library", "LaunchAgents", fseventsWatchdogLabel+".plist"),
		StatePath:  filepath.Join(home, "Library", "Application Support", FSEventsWatchdogStateDirs, FSEventsWatchdogStateName),
		BinaryPath: binaryPath,
		UID:        os.Getuid(),
	}, nil
}

func validateFSEventsWatchdogConfig(cfg FSEventsWatchdogConfig) error {
	if cfg.Label == "" || cfg.PlistPath == "" || cfg.StatePath == "" || cfg.UID < 0 {
		return fmt.Errorf("invalid fseventsd watchdog config")
	}
	return nil
}

func validateFSEventsWatchdogSettings(settings FSEventsWatchdogSettings) error {
	if settings.RSSThresholdBytes <= 0 {
		return fmt.Errorf("rss threshold must be positive")
	}
	if settings.Interval < minWatchdogInterval {
		return fmt.Errorf("interval must be at least %s", minWatchdogInterval)
	}
	return nil
}

func InspectFSEventsWatchdog(cfg FSEventsWatchdogConfig) (FSEventsWatchdogStatus, error) {
	status := FSEventsWatchdogStatus{
		State:     FSEventsWatchdogDisabled,
		Label:     cfg.Label,
		PlistPath: cfg.PlistPath,
		StatePath: cfg.StatePath,
	}
	if err := validateFSEventsWatchdogConfig(cfg); err != nil {
		status.State = FSEventsWatchdogUnavailable
		return status, err
	}
	status.UserDomain = "gui/" + strconv.Itoa(cfg.UID)

	var state fseventsWatchdogStateFile
	if err := readJSONState(cfg.StatePath, &state); err == nil {
		settings := state.Settings
		status.Settings = &settings
		status.LastCheck = state.LastCheck
	} else if !os.IsNotExist(err) {
		status.State = FSEventsWatchdogUnavailable
		return status, fmt.Errorf("read fseventsd watchdog state: %w", err)
	}

	_, err := runCoreCommand(launchctlPath, "print", status.UserDomain+"/"+cfg.Label)
	if err == nil {
		status.State = FSEventsWatchdogEnabled
		return status, nil
	}
	if isLaunchctlServiceMissing(err) {
		return status, nil
	}
	status.State = FSEventsWatchdogUnavailable
	return status, fmt.Errorf("inspect fseventsd watchdog LaunchAgent: %w", err)
}

// EnableFSEventsWatchdog writes the settings, renders the plist, and
// bootstraps the agent. Re-enabling with new settings re-bootstraps so the
// interval in the plist matches the state file.
func EnableFSEventsWatchdog(cfg FSEventsWatchdogConfig, settings FSEventsWatchdogSettings) ([]CommandResult, error) {
	if err := validateFSEventsWatchdogConfig(cfg); err != nil {
		return nil, err
	}
	if err := validateFSEventsWatchdogSettings(settings); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.BinaryPath) == "" {
		return nil, fmt.Errorf("fseventsd watchdog needs the mac-infra-core binary path")
	}
	status, err := InspectFSEventsWatchdog(cfg)
	if err != nil {
		return nil, err
	}

	var state fseventsWatchdogStateFile
	_ = readJSONState(cfg.StatePath, &state)
	if settings.EnabledAt.IsZero() {
		settings.EnabledAt = time.Now()
	}
	state.Settings = settings
	if err := writeJSONState(cfg.StatePath, state); err != nil {
		return nil, fmt.Errorf("write fseventsd watchdog state: %w", err)
	}
	if err := writeFileAtomically(cfg.PlistPath, RenderFSEventsWatchdogLaunchAgent(cfg, settings), 0o755, 0o644); err != nil {
		return nil, fmt.Errorf("install fseventsd watchdog LaunchAgent plist: %w", err)
	}

	var results []CommandResult
	if status.State == FSEventsWatchdogEnabled {
		result, err := runCoreCommand(launchctlPath, "bootout", status.UserDomain+"/"+cfg.Label)
		if err != nil && !isLaunchctlServiceMissing(err) {
			return []CommandResult{result}, err
		}
		results = append(results, result)
	}
	result, err := runCoreCommand(launchctlPath, "bootstrap", "gui/"+strconv.Itoa(cfg.UID), cfg.PlistPath)
	results = append(results, result)
	return results, err
}

func DisableFSEventsWatchdog(cfg FSEventsWatchdogConfig) ([]CommandResult, error) {
	if err := validateFSEventsWatchdogConfig(cfg); err != nil {
		return nil, err
	}
	results := []CommandResult{}
	result, err := runCoreCommand(launchctlPath, "bootout", "gui/"+strconv.Itoa(cfg.UID)+"/"+cfg.Label)
	if err != nil && !isLaunchctlServiceMissing(err) {
		return []CommandResult{result}, err
	}
	if err == nil {
		results = append(results, result)
	}
	if err := os.Remove(cfg.PlistPath); err != nil && !os.IsNotExist(err) {
		return results, fmt.Errorf("remove fseventsd watchdog LaunchAgent plist: %w", err)
	}
	// The state file is kept: it holds the last check for `status` and the
	// settings a later enable can reuse.
	return results, nil
}

// RunFSEventsWatchdogCheck is one LaunchAgent tick. It reads settings from
// the state file (never from argv, so the plist cannot drift), inspects
// fseventsd, notifies with a cooldown, optionally restarts through the root
// daemon, and records the outcome.
func RunFSEventsWatchdogCheck(cfg FSEventsWatchdogConfig, serviceCfg ServiceConfig, now time.Time) (FSEventsWatchdogCheck, error) {
	if err := validateFSEventsWatchdogConfig(cfg); err != nil {
		return FSEventsWatchdogCheck{}, err
	}
	var state fseventsWatchdogStateFile
	if err := readJSONState(cfg.StatePath, &state); err != nil {
		return FSEventsWatchdogCheck{}, fmt.Errorf("read fseventsd watchdog state: %w", err)
	}
	if err := validateFSEventsWatchdogSettings(state.Settings); err != nil {
		return FSEventsWatchdogCheck{}, fmt.Errorf("fseventsd watchdog state: %w", err)
	}
	check := FSEventsWatchdogCheck{CheckedAt: now}
	if state.LastCheck != nil {
		check.LastNotify = state.LastCheck.LastNotify
		check.LastRestart = state.LastCheck.LastRestart
	}

	daemon, _, err := InspectFSEventsDaemon()
	if err != nil {
		check.Error = err.Error()
		return check, persistWatchdogCheck(cfg, state, check)
	}
	check.Found = daemon.Found
	check.PID = daemon.PID
	check.RSSBytes = daemon.RSSBytes
	check.CPU = daemon.CPU
	check.OverLimit = daemon.Found && daemon.RSSBytes >= state.Settings.RSSThresholdBytes
	if !check.OverLimit {
		return check, persistWatchdogCheck(cfg, state, check)
	}

	cooldown := state.Settings.Interval * watchdogNotifyCooldownMult
	if check.LastNotify.IsZero() || now.Sub(check.LastNotify) >= cooldown {
		message := fmt.Sprintf("fseventsd rss %s (pid %d) is over %s.",
			loadprofile.FormatBytes(daemon.RSSBytes), daemon.PID, loadprofile.FormatBytes(state.Settings.RSSThresholdBytes))
		if state.Settings.AutoRestart {
			message += " Restarting through mac-infra-core."
		} else {
			message += " Run: mac-infra-core fseventsd-restart"
		}
		if _, err := runCoreCommand(osascriptPath, "-e", notificationScript(message, "mac-infra fseventsd watchdog")); err != nil {
			check.Error = "notify: " + err.Error()
		} else {
			check.Notified = true
			check.LastNotify = now
		}
	}

	if state.Settings.AutoRestart {
		if _, err := RestartFSEvents(serviceCfg, false, state.Settings.RSSThresholdBytes); err != nil {
			check.Error = strings.TrimSpace(check.Error + " restart: " + err.Error())
		} else {
			check.Restarted = true
			check.LastRestart = now
		}
	}
	return check, persistWatchdogCheck(cfg, state, check)
}

func persistWatchdogCheck(cfg FSEventsWatchdogConfig, state fseventsWatchdogStateFile, check FSEventsWatchdogCheck) error {
	copyCheck := check
	state.LastCheck = &copyCheck
	if err := writeJSONState(cfg.StatePath, state); err != nil {
		return fmt.Errorf("write fseventsd watchdog state: %w", err)
	}
	return nil
}

func notificationScript(message, title string) string {
	escape := func(value string) string {
		return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value)
	}
	return fmt.Sprintf(`display notification "%s" with title "%s"`, escape(message), escape(title))
}

func RenderFSEventsWatchdogLaunchAgent(cfg FSEventsWatchdogConfig, settings FSEventsWatchdogSettings) []byte {
	var builder strings.Builder
	builder.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	builder.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	builder.WriteString(`<plist version="1.0">` + "\n")
	builder.WriteString(`<dict>` + "\n")
	builder.WriteString(`  <key>Label</key>` + "\n")
	builder.WriteString(`  <string>` + plistEscape(cfg.Label) + `</string>` + "\n")
	builder.WriteString(`  <key>ProgramArguments</key>` + "\n")
	builder.WriteString(`  <array>` + "\n")
	for _, value := range []string{cfg.BinaryPath, fseventsWatchdogCheckVerb, "--state", cfg.StatePath} {
		builder.WriteString(`    <string>` + plistEscape(value) + `</string>` + "\n")
	}
	builder.WriteString(`  </array>` + "\n")
	builder.WriteString(`  <key>StartInterval</key>` + "\n")
	builder.WriteString(`  <integer>` + strconv.Itoa(int(settings.Interval/time.Second)) + `</integer>` + "\n")
	builder.WriteString(`  <key>RunAtLoad</key>` + "\n")
	builder.WriteString(`  <true/>` + "\n")
	builder.WriteString(`  <key>ProcessType</key>` + "\n")
	builder.WriteString(`  <string>Background</string>` + "\n")
	builder.WriteString(`</dict>` + "\n")
	builder.WriteString(`</plist>` + "\n")
	return []byte(builder.String())
}

// DefaultFSEventsWatchdogSettings mirrors the diagnostics critical threshold.
func DefaultFSEventsWatchdogSettings() FSEventsWatchdogSettings {
	return FSEventsWatchdogSettings{
		RSSThresholdBytes: fsevents.DefaultRSSCriticalBytes,
		Interval:          DefaultWatchdogInterval,
	}
}
