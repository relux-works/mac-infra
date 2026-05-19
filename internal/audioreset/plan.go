package audioreset

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

const xcodeSimctlPath = "/Applications/Xcode.app/Contents/Developer/usr/bin/simctl"

type Command struct {
	Name string
	Args []string
}

func (c Command) String() string {
	parts := []string{c.Name}
	parts = append(parts, c.Args...)
	for i, part := range parts {
		parts[i] = shellQuote(part)
	}
	return strings.Join(parts, " ")
}

type StepKind string

const (
	StepShutdownSimulators StepKind = "shutdown_simulators"
	StepRestartAudio       StepKind = "restart_audio"
	StepCollectDiagnostic  StepKind = "collect_diagnostic"
)

type Step struct {
	Kind        StepKind
	Description string
	Command     Command
	Optional    bool
	CoreAction  string
}

type ResetOptions struct {
	SkipSimulators  bool
	IncludeUSBAudio bool
}

type Environment struct {
	PathExists func(string) bool
	LookPath   func(string) (string, error)
}

func DefaultEnvironment() Environment {
	return Environment{
		PathExists: func(path string) bool {
			_, err := os.Stat(path)
			return err == nil
		},
		LookPath: exec.LookPath,
	}
}

func PlanReset(opts ResetOptions, env Environment) []Step {
	env = normalizeEnvironment(env)
	var steps []Step
	if !opts.SkipSimulators {
		if simctl, ok := SimctlCommand(env, "shutdown", "all"); ok {
			steps = append(steps, Step{
				Kind:        StepShutdownSimulators,
				Description: "shut down booted iOS simulators",
				Command:     simctl,
				Optional:    true,
			})
		}
	}

	description := "restart CoreAudio via mac-infra-core"
	if opts.IncludeUSBAudio {
		description = "restart CoreAudio and usbaudiod via mac-infra-core"
	}
	steps = append(steps, Step{
		Kind:        StepRestartAudio,
		Description: description,
		CoreAction:  "restart_audio",
	})
	return steps
}

func PlanDiagnose(includeLogs bool, env Environment) []Step {
	env = normalizeEnvironment(env)
	steps := []Step{
		{
			Kind:        StepCollectDiagnostic,
			Description: "audio devices",
			Command:     Command{Name: "/usr/sbin/system_profiler", Args: []string{"SPAudioDataType", "-detailLevel", "mini"}},
		},
		{
			Kind:        StepCollectDiagnostic,
			Description: "power assertions",
			Command:     Command{Name: "/usr/bin/pmset", Args: []string{"-g", "assertions"}},
		},
		{
			Kind:        StepCollectDiagnostic,
			Description: "audio and simulator processes",
			Command:     Command{Name: "/bin/ps", Args: []string{"-axo", "pid,ppid,pcpu,pmem,rss,etime,command"}},
		},
	}

	if simctl, ok := SimctlCommand(env, "list", "devices", "booted"); ok {
		steps = append(steps, Step{
			Kind:        StepCollectDiagnostic,
			Description: "booted simulators",
			Command:     simctl,
			Optional:    true,
		})
	}

	if includeLogs {
		steps = append(steps, Step{
			Kind:        StepCollectDiagnostic,
			Description: "recent CoreAudio underrun logs",
			Command: Command{
				Name: "/usr/bin/log",
				Args: []string{
					"show",
					"--last", "20m",
					"--style", "compact",
					"--predicate", `process == "audioanalyticsd" || process == "coreaudiod" || eventMessage CONTAINS[c] "HALIO" || eventMessage CONTAINS[c] "SafetyViolation"`,
				},
			},
			Optional: true,
		})
	}

	return steps
}

func SimctlCommand(env Environment, args ...string) (Command, bool) {
	env = normalizeEnvironment(env)
	if env.PathExists(xcodeSimctlPath) {
		return Command{Name: xcodeSimctlPath, Args: append([]string(nil), args...)}, true
	}
	if path, err := env.LookPath("xcrun"); err == nil && path != "" {
		commandArgs := append([]string{"simctl"}, args...)
		return Command{Name: path, Args: commandArgs}, true
	}
	return Command{}, false
}

func normalizeEnvironment(env Environment) Environment {
	if env.PathExists == nil {
		env.PathExists = DefaultEnvironment().PathExists
	}
	if env.LookPath == nil {
		env.LookPath = DefaultEnvironment().LookPath
	}
	return env
}

func IsOptionalCommandFailure(err error) bool {
	return errors.Is(err, exec.ErrNotFound)
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	if strings.IndexFunc(value, func(r rune) bool {
		return !(r == '/' || r == '.' || r == '_' || r == '-' || r == ':' || r == '+' ||
			(r >= '0' && r <= '9') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z'))
	}) == -1 {
		return value
	}
	return strconv.Quote(value)
}
