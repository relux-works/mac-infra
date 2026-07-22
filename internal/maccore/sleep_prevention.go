package maccore

import (
	"fmt"
	"strings"
)

type SleepPreventionState string

const (
	pmsetPath                                            = "/usr/bin/pmset"
	SleepPreventionAppliesTo                             = "AC,battery"
	SleepPreventionStateEnabled     SleepPreventionState = "enabled"
	SleepPreventionStateDisabled    SleepPreventionState = "disabled"
	SleepPreventionStateUnavailable SleepPreventionState = "unavailable"
)

type SleepPreventionStatus struct {
	State     SleepPreventionState
	AppliesTo string
}

type commandPlan struct {
	Path string
	Args []string
}

func InspectSleepPrevention() (SleepPreventionStatus, error) {
	result, err := runCoreCommand(pmsetPath, "-g")
	if err != nil {
		return unavailableSleepPreventionStatus(), fmt.Errorf("read sleep prevention status: %w", err)
	}

	status, err := ParseSleepPreventionStatus(result.Output)
	if err != nil {
		return status, fmt.Errorf("read sleep prevention status: %w", err)
	}
	return status, nil
}

func ParseSleepPreventionStatus(output string) (SleepPreventionStatus, error) {
	status := unavailableSleepPreventionStatus()
	inSystemWideSection := false
	foundSystemWideSection := false
	foundValue := false
	foundRawValue := ""

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "System-wide power settings:" {
			foundSystemWideSection = true
			inSystemWideSection = true
			continue
		}
		if inSystemWideSection && strings.HasSuffix(trimmed, ":") {
			inSystemWideSection = false
		}
		if !inSystemWideSection {
			continue
		}

		fields := strings.Fields(trimmed)
		if len(fields) == 0 || fields[0] != "SleepDisabled" {
			continue
		}
		if len(fields) != 2 || (fields[1] != "0" && fields[1] != "1") {
			return status, fmt.Errorf("malformed system-wide SleepDisabled line %q", trimmed)
		}
		if foundValue {
			if fields[1] != foundRawValue {
				return status, fmt.Errorf("inconsistent system-wide SleepDisabled values %s and %s", foundRawValue, fields[1])
			}
			return status, fmt.Errorf("duplicate system-wide SleepDisabled value %s", fields[1])
		}
		foundValue = true
		foundRawValue = fields[1]
	}

	if !foundSystemWideSection {
		return status, fmt.Errorf("missing System-wide power settings section")
	}
	if !foundValue {
		return status, fmt.Errorf("missing system-wide SleepDisabled value")
	}

	if foundRawValue == "1" {
		status.State = SleepPreventionStateEnabled
	} else {
		status.State = SleepPreventionStateDisabled
	}
	return status, nil
}

func applySleepPrevention(action Action) ([]CommandResult, error) {
	plan, err := sleepPreventionCommandPlan(action)
	if err != nil {
		return nil, err
	}
	result, err := runCoreCommand(plan.Path, plan.Args...)
	return []CommandResult{result}, err
}

func sleepPreventionCommandPlan(action Action) (commandPlan, error) {
	switch action {
	case ActionSleepPreventionEnable:
		return commandPlan{Path: pmsetPath, Args: []string{"-a", "disablesleep", "1"}}, nil
	case ActionSleepPreventionDisable:
		return commandPlan{Path: pmsetPath, Args: []string{"-a", "disablesleep", "0"}}, nil
	default:
		return commandPlan{}, fmt.Errorf("unsupported sleep-prevention action %q", action)
	}
}

func unavailableSleepPreventionStatus() SleepPreventionStatus {
	return SleepPreventionStatus{
		State:     SleepPreventionStateUnavailable,
		AppliesTo: SleepPreventionAppliesTo,
	}
}
