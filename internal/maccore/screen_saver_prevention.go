package maccore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type IdleLockPreventionState string

const (
	defaultsPath                                               = "/usr/bin/defaults"
	screenSaverDomain                                          = "com.apple.screensaver"
	screenSaverSnapshotVersion                                 = 1
	IdleLockPreventionStateEnabled     IdleLockPreventionState = "enabled"
	IdleLockPreventionStateDisabled    IdleLockPreventionState = "disabled"
	IdleLockPreventionStateUnavailable IdleLockPreventionState = "unavailable"
)

var screenSaverIdleTimePattern = regexp.MustCompile(`(?s)<key>\s*idleTime\s*</key>\s*<integer>\s*([0-9]+)\s*</integer>`)

type IdleLockPreventionConfig struct {
	StatePath string
}

type IdleLockPreventionStatus struct {
	State           IdleLockPreventionState
	IdleTimePresent bool
	IdleTimeSeconds int
}

type idleLockSnapshot struct {
	Version         int  `json:"version"`
	IdleTimePresent bool `json:"idle_time_present"`
	IdleTimeSeconds int  `json:"idle_time_seconds,omitempty"`
}

func DefaultIdleLockPreventionConfig() (IdleLockPreventionConfig, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return IdleLockPreventionConfig{}, fmt.Errorf("resolve user config directory: %w", err)
	}
	return IdleLockPreventionConfig{
		StatePath: filepath.Join(configDir, "mac-infra", "idle-lock-prevention.json"),
	}, nil
}

func InspectIdleLockPrevention() (IdleLockPreventionStatus, error) {
	cfg, err := DefaultIdleLockPreventionConfig()
	if err != nil {
		return unavailableIdleLockPreventionStatus(), err
	}
	return inspectIdleLockPrevention(cfg)
}

func EnableIdleLockPrevention() ([]CommandResult, error) {
	cfg, err := DefaultIdleLockPreventionConfig()
	if err != nil {
		return nil, err
	}
	return applyIdleLockPrevention(cfg, true)
}

func DisableIdleLockPrevention() ([]CommandResult, error) {
	cfg, err := DefaultIdleLockPreventionConfig()
	if err != nil {
		return nil, err
	}
	return applyIdleLockPrevention(cfg, false)
}

func inspectIdleLockPrevention(_ IdleLockPreventionConfig) (IdleLockPreventionStatus, error) {
	idleTime, present, _, err := readScreenSaverIdleTime()
	if err != nil {
		return unavailableIdleLockPreventionStatus(), fmt.Errorf("read idle lock prevention status: %w", err)
	}
	status := IdleLockPreventionStatus{
		State:           IdleLockPreventionStateDisabled,
		IdleTimePresent: present,
		IdleTimeSeconds: idleTime,
	}
	if present && idleTime == 0 {
		status.State = IdleLockPreventionStateEnabled
	}
	return status, nil
}

func ParseScreenSaverIdleTime(output string) (int, bool, error) {
	match := screenSaverIdleTimePattern.FindStringSubmatch(output)
	if len(match) == 0 {
		if strings.Contains(output, "<key>idleTime</key>") {
			return -1, false, fmt.Errorf("malformed screen saver idleTime value")
		}
		return -1, false, nil
	}
	idleTime, err := strconv.Atoi(match[1])
	if err != nil || idleTime < 0 {
		return -1, false, fmt.Errorf("malformed screen saver idleTime value %q", match[1])
	}
	return idleTime, true, nil
}

func readScreenSaverIdleTime() (int, bool, CommandResult, error) {
	result, err := runCoreCommand(defaultsPath, "-currentHost", "export", screenSaverDomain, "-")
	if err != nil {
		return -1, false, result, err
	}
	idleTime, present, err := ParseScreenSaverIdleTime(result.Output)
	return idleTime, present, result, err
}

func applyIdleLockPrevention(cfg IdleLockPreventionConfig, enable bool) ([]CommandResult, error) {
	if cfg.StatePath == "" {
		return nil, fmt.Errorf("empty idle lock prevention state path")
	}
	var snapshot idleLockSnapshot
	if enable {
		if err := readJSONState(cfg.StatePath, &snapshot); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("read saved idle lock settings: %w", err)
			}
			idleTime, present, _, inspectErr := readScreenSaverIdleTime()
			if inspectErr != nil {
				return nil, fmt.Errorf("read idle lock trigger settings: %w", inspectErr)
			}
			snapshot = idleLockSnapshot{
				Version:         screenSaverSnapshotVersion,
				IdleTimePresent: present,
				IdleTimeSeconds: idleTime,
			}
			if err := writeJSONState(cfg.StatePath, snapshot); err != nil {
				return nil, fmt.Errorf("save idle lock settings: %w", err)
			}
		} else if err := validateIdleLockSnapshot(snapshot); err != nil {
			return nil, fmt.Errorf("read saved idle lock settings: %w", err)
		}
	} else {
		if err := readJSONState(cfg.StatePath, &snapshot); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				status, inspectErr := inspectIdleLockPrevention(cfg)
				if inspectErr != nil {
					return nil, inspectErr
				}
				if status.State == IdleLockPreventionStateDisabled {
					return nil, nil
				}
				return nil, fmt.Errorf("no saved idle lock settings; refusing to invent restore values")
			}
			return nil, fmt.Errorf("read saved idle lock settings: %w", err)
		}
		if err := validateIdleLockSnapshot(snapshot); err != nil {
			return nil, fmt.Errorf("read saved idle lock settings: %w", err)
		}
	}

	plan := idleLockCommandPlan(enable, snapshot)
	result, err := runCoreCommand(plan.Path, plan.Args...)
	results := []CommandResult{result}
	if err != nil {
		return results, err
	}
	if !enable {
		if err := os.Remove(cfg.StatePath); err != nil {
			return results, fmt.Errorf("remove saved idle lock settings: %w", err)
		}
	}
	return results, nil
}

func idleLockCommandPlan(enable bool, snapshot idleLockSnapshot) commandPlan {
	if enable {
		return commandPlan{
			Path: defaultsPath,
			Args: []string{"-currentHost", "write", screenSaverDomain, "idleTime", "-int", "0"},
		}
	}
	if snapshot.IdleTimePresent {
		return commandPlan{
			Path: defaultsPath,
			Args: []string{"-currentHost", "write", screenSaverDomain, "idleTime", "-int", strconv.Itoa(snapshot.IdleTimeSeconds)},
		}
	}
	return commandPlan{
		Path: defaultsPath,
		Args: []string{"-currentHost", "delete", screenSaverDomain, "idleTime"},
	}
}

func validateIdleLockSnapshot(snapshot idleLockSnapshot) error {
	if snapshot.Version != screenSaverSnapshotVersion {
		return fmt.Errorf("unsupported idle lock snapshot version %d", snapshot.Version)
	}
	if snapshot.IdleTimePresent && snapshot.IdleTimeSeconds < 0 {
		return fmt.Errorf("idle lock snapshot contains negative idleTime")
	}
	return nil
}

func unavailableIdleLockPreventionStatus() IdleLockPreventionStatus {
	return IdleLockPreventionStatus{
		State:           IdleLockPreventionStateUnavailable,
		IdleTimeSeconds: -1,
	}
}
