package audioreset

import (
	"errors"
	"testing"
)

func TestPlanResetUsesUserSimctlBeforeCoreRestart(t *testing.T) {
	env := Environment{
		PathExists: func(path string) bool { return path == xcodeSimctlPath },
		LookPath:   func(string) (string, error) { return "", errors.New("not found") },
	}

	steps := PlanReset(ResetOptions{}, env)

	if len(steps) != 2 {
		t.Fatalf("len(steps) = %d, want 2", len(steps))
	}
	if steps[0].Kind != StepShutdownSimulators {
		t.Fatalf("first step = %s, want %s", steps[0].Kind, StepShutdownSimulators)
	}
	if got := steps[0].Command.String(); got != "/Applications/Xcode.app/Contents/Developer/usr/bin/simctl shutdown all" {
		t.Fatalf("simctl command = %q", got)
	}
	if steps[1].Kind != StepRestartAudio || steps[1].CoreAction != "restart_audio" {
		t.Fatalf("second step = %#v, want core restart", steps[1])
	}
}

func TestPlanResetCanSkipSimulators(t *testing.T) {
	steps := PlanReset(ResetOptions{SkipSimulators: true}, Environment{
		PathExists: func(string) bool { return true },
	})

	if len(steps) != 1 {
		t.Fatalf("len(steps) = %d, want 1", len(steps))
	}
	if steps[0].Kind != StepRestartAudio {
		t.Fatalf("step = %s, want %s", steps[0].Kind, StepRestartAudio)
	}
}

func TestSimctlCommandFallsBackToXcrunWithSubcommand(t *testing.T) {
	env := Environment{
		PathExists: func(string) bool { return false },
		LookPath: func(name string) (string, error) {
			if name == "xcrun" {
				return "/usr/bin/xcrun", nil
			}
			return "", errors.New("not found")
		},
	}

	got, ok := SimctlCommand(env, "list", "devices", "booted")
	if !ok {
		t.Fatal("SimctlCommand ok = false, want true")
	}
	if got.String() != "/usr/bin/xcrun simctl list devices booted" {
		t.Fatalf("SimctlCommand = %q, want xcrun simctl command", got.String())
	}
}

func TestCommandStringQuotesUnsafeArgs(t *testing.T) {
	cmd := Command{Name: "/usr/bin/log", Args: []string{"show", "--predicate", `eventMessage CONTAINS[c] "HALIO"`}}

	got := cmd.String()
	want := `/usr/bin/log show --predicate "eventMessage CONTAINS[c] \"HALIO\""`
	if got != want {
		t.Fatalf("Command.String() = %q, want %q", got, want)
	}
}
