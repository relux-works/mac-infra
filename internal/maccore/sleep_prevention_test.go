package maccore

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSleepPreventionCommandPlansAreFixed(t *testing.T) {
	tests := []struct {
		name     string
		action   Action
		wantArgs []string
	}{
		{
			name:     "enable",
			action:   ActionSleepPreventionEnable,
			wantArgs: []string{"-a", "disablesleep", "1"},
		},
		{
			name:     "disable",
			action:   ActionSleepPreventionDisable,
			wantArgs: []string{"-a", "disablesleep", "0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan, err := sleepPreventionCommandPlan(tt.action)
			if err != nil {
				t.Fatalf("sleepPreventionCommandPlan error = %v", err)
			}
			if plan.Path != "/usr/bin/pmset" {
				t.Fatalf("plan.Path = %q, want /usr/bin/pmset", plan.Path)
			}
			if !reflect.DeepEqual(plan.Args, tt.wantArgs) {
				t.Fatalf("plan.Args = %#v, want %#v", plan.Args, tt.wantArgs)
			}
		})
	}
}

func TestSleepPreventionCommandPlanRejectsOtherActions(t *testing.T) {
	_, err := sleepPreventionCommandPlan(Action("sleep_prevention_set_arbitrary"))
	if err == nil {
		t.Fatal("sleepPreventionCommandPlan error = nil, want unsupported action")
	}
}

func TestApplySleepPreventionRejectsOtherActionsWithoutExecuting(t *testing.T) {
	results, err := applySleepPrevention(Action("sleep_prevention_set_arbitrary"))
	if err == nil {
		t.Fatal("applySleepPrevention error = nil, want unsupported action")
	}
	if results != nil {
		t.Fatalf("results = %#v, want nil", results)
	}
}

func TestParseSleepPreventionStatus(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantState SleepPreventionState
		wantError string
	}{
		{
			name: "enabled",
			output: "System-wide power settings:\n" +
				" SleepDisabled\t\t1\n" +
				"Currently in use:\n" +
				" sleep 1\n",
			wantState: SleepPreventionStateEnabled,
		},
		{
			name: "disabled",
			output: "System-wide power settings:\n" +
				"  SleepDisabled  0  \n" +
				"Currently in use:\n",
			wantState: SleepPreventionStateDisabled,
		},
		{
			name:      "missing section",
			output:    "Currently in use:\n SleepDisabled 1\n",
			wantState: SleepPreventionStateUnavailable,
			wantError: "missing System-wide power settings section",
		},
		{
			name:      "missing value",
			output:    "System-wide power settings:\nCurrently in use:\n sleep 1\n",
			wantState: SleepPreventionStateUnavailable,
			wantError: "missing system-wide SleepDisabled value",
		},
		{
			name:      "malformed value",
			output:    "System-wide power settings:\n SleepDisabled yes\nCurrently in use:\n",
			wantState: SleepPreventionStateUnavailable,
			wantError: `malformed system-wide SleepDisabled line "SleepDisabled yes"`,
		},
		{
			name: "inconsistent values",
			output: "System-wide power settings:\n" +
				" SleepDisabled 1\n" +
				" SleepDisabled 0\n" +
				"Currently in use:\n",
			wantState: SleepPreventionStateUnavailable,
			wantError: "inconsistent system-wide SleepDisabled values 1 and 0",
		},
		{
			name: "duplicate value",
			output: "System-wide power settings:\n" +
				" SleepDisabled 1\n" +
				" SleepDisabled 1\n" +
				"Currently in use:\n",
			wantState: SleepPreventionStateUnavailable,
			wantError: "duplicate system-wide SleepDisabled value 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := ParseSleepPreventionStatus(tt.output)
			if status.State != tt.wantState {
				t.Fatalf("status.State = %q, want %q", status.State, tt.wantState)
			}
			if status.AppliesTo != SleepPreventionAppliesTo {
				t.Fatalf("status.AppliesTo = %q, want %q", status.AppliesTo, SleepPreventionAppliesTo)
			}
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("ParseSleepPreventionStatus error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("ParseSleepPreventionStatus error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestInspectSleepPreventionRunsAbsoluteReadOnlyCommand(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PMSET_OUTPUT", "System-wide power settings:\n SleepDisabled 1\nCurrently in use:")

	status, err := InspectSleepPrevention()

	if err != nil {
		t.Fatalf("InspectSleepPrevention error = %v", err)
	}
	if status.State != SleepPreventionStateEnabled {
		t.Fatalf("status.State = %q, want %q", status.State, SleepPreventionStateEnabled)
	}
	if calls := readCommandLog(t, logPath); calls != "/usr/bin/pmset -g\n" {
		t.Fatalf("calls = %q, want only /usr/bin/pmset -g", calls)
	}
}

func TestInspectSleepPreventionReportsCommandFailureAsUnavailable(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PMSET_FAIL_COMMAND", "/usr/bin/pmset -g")
	t.Setenv("MAC_INFRA_TEST_PMSET_FAILURE", "read denied")

	status, err := InspectSleepPrevention()

	if err == nil || !strings.Contains(err.Error(), "read denied") {
		t.Fatalf("InspectSleepPrevention error = %v, want command failure", err)
	}
	if status.State != SleepPreventionStateUnavailable {
		t.Fatalf("status.State = %q, want %q", status.State, SleepPreventionStateUnavailable)
	}
	if status.AppliesTo != SleepPreventionAppliesTo {
		t.Fatalf("status.AppliesTo = %q, want %q", status.AppliesTo, SleepPreventionAppliesTo)
	}
}

func TestInspectSleepPreventionReportsMalformedOutputAsUnavailable(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "commands.log")
	withFakeCoreCommand(t, logPath)
	t.Setenv("MAC_INFRA_TEST_PMSET_OUTPUT", "System-wide power settings:\nCurrently in use:")

	status, err := InspectSleepPrevention()

	if err == nil || !strings.Contains(err.Error(), "missing system-wide SleepDisabled value") {
		t.Fatalf("InspectSleepPrevention error = %v, want parser failure", err)
	}
	if status.State != SleepPreventionStateUnavailable {
		t.Fatalf("status.State = %q, want %q", status.State, SleepPreventionStateUnavailable)
	}
	if status.AppliesTo != SleepPreventionAppliesTo {
		t.Fatalf("status.AppliesTo = %q, want %q", status.AppliesTo, SleepPreventionAppliesTo)
	}
}
