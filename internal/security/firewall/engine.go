package firewall

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// RollbackTimeout bounds the undo commands and the readback that follow a
// failed apply, independent of the apply's own deadline.
const RollbackTimeout = 2 * time.Minute

const (
	OutcomeStatus         = "status"
	OutcomePlanned        = "planned"
	OutcomeNoChange       = "no_change"
	OutcomeApplied        = "applied"
	OutcomeRefused        = "refused"
	OutcomeRolledBack     = "rolled_back"
	OutcomeRollbackFailed = "rollback_failed"
	OutcomeEnforced       = "enforced"
)

type CommandResult struct {
	Argv   []string `json:"argv"`
	Output string   `json:"output,omitempty"`
	Error  string   `json:"error,omitempty"`
}

type Report struct {
	Outcome   string          `json:"outcome"`
	Error     string          `json:"error,omitempty"`
	Before    *State          `json:"before,omitempty"`
	Plan      *Plan           `json:"plan,omitempty"`
	Commands  []CommandResult `json:"commands,omitempty"`
	Rollback  []CommandResult `json:"rollback,omitempty"`
	After     *State          `json:"after,omitempty"`
	Drift     string          `json:"drift,omitempty"`
	Listeners []Listener      `json:"listeners,omitempty"`
	// ListenerError reports a failed listener inspection in a status; the
	// firewall state in Before is still valid.
	ListenerError string `json:"listener_error,omitempty"`
}

type Engine struct {
	Runner   Runner
	Resolver Resolver
}

// Plan observes and plans without running a mutating command.
func (e Engine) Plan(ctx context.Context, cfg Config) Report {
	before, err := Observe(ctx, e.Runner)
	if err != nil {
		return Report{Outcome: OutcomeRefused, Error: err.Error()}
	}
	plan, err := BuildPlan(ctx, cfg, before, e.Resolver, true)
	if err != nil {
		return Report{Outcome: OutcomeRefused, Error: err.Error(), Before: &before}
	}
	return Report{Outcome: OutcomePlanned, Before: &before, Plan: &plan}
}

// Apply validates the whole plan before the first mutation, then applies it
// and verifies by readback that nothing remains to do. On any failure the
// steps already started are undone in reverse and the state is read back:
// rolled_back means it matches the pre-apply state (except that the firewall
// stays on); rollback_failed reports the remaining drift.
func (e Engine) Apply(ctx context.Context, cfg Config, beforeMutation func(Plan) error) Report {
	report := e.Plan(ctx, cfg)
	if report.Outcome != OutcomePlanned {
		return report
	}
	if len(report.Plan.Steps) == 0 {
		report.Outcome = OutcomeNoChange
		report.After = report.Before
		return report
	}
	if beforeMutation != nil {
		if err := beforeMutation(*report.Plan); err != nil {
			report.Outcome = OutcomeRefused
			report.Error = err.Error()
			return report
		}
	}
	var started []Step
	var failure error
	for _, step := range report.Plan.Steps {
		started = append(started, step)
		for _, argv := range step.Argv {
			result, err := e.run(ctx, argv)
			report.Commands = append(report.Commands, result)
			if err != nil {
				failure = fmt.Errorf("step %s %s: %w", step.Kind, step.Target, err)
				break
			}
		}
		if failure != nil {
			break
		}
	}
	if failure == nil {
		after, err := Observe(ctx, e.Runner)
		if err != nil {
			failure = fmt.Errorf("readback: %w", err)
		} else if residual, err := BuildPlan(ctx, cfg, after, e.Resolver, false); err != nil {
			failure = fmt.Errorf("readback plan: %w", err)
		} else if len(residual.Steps) > 0 {
			failure = fmt.Errorf("readback still differs from the config: %s", describeSteps(residual.Steps))
		} else if err := e.reverifyAllowed(ctx, report.Plan.Steps); err != nil {
			failure = err
		} else {
			report.Outcome = OutcomeApplied
			report.After = &after
			return report
		}
	}
	report.Error = failure.Error()
	// Recovery gets its own budget: an apply that ran out of time must still
	// be able to undo what it changed.
	recovery, cancel := context.WithTimeout(context.WithoutCancel(ctx), RollbackTimeout)
	defer cancel()
	for i := len(started) - 1; i >= 0; i-- {
		for _, argv := range started[i].Undo {
			// Best effort: a failing undo must not stop the remaining ones.
			result, _ := e.run(recovery, argv)
			report.Rollback = append(report.Rollback, result)
		}
	}
	after, err := Observe(recovery, e.Runner)
	if err != nil {
		report.Outcome = OutcomeRollbackFailed
		report.Drift = "readback after rollback failed: " + err.Error()
		return report
	}
	report.After = &after
	if after.comparable() != report.Before.comparable() {
		report.Outcome = OutcomeRollbackFailed
		report.Drift = fmt.Sprintf("before: %s; after: %s", report.Before.comparable(), after.comparable())
		return report
	}
	report.Outcome = OutcomeRolledBack
	return report
}

// reverifyAllowed closes most of the window between the signature check and
// socketfilterfw recording the app: the bytes it now points at must still
// carry the same Apple-anchored identity.
func (e Engine) reverifyAllowed(ctx context.Context, steps []Step) error {
	for _, step := range steps {
		if step.Identity == nil {
			continue
		}
		identity, err := e.Resolver.VerifySigned(ctx, step.Target)
		if err != nil {
			return fmt.Errorf("re-verify %s after apply: %w", step.Target, err)
		}
		if identity != *step.Identity {
			return fmt.Errorf("re-verify %s after apply: signing identity changed from %s/%s to %s/%s",
				step.Target, step.Identity.Identifier, step.Identity.TeamID, identity.Identifier, identity.TeamID)
		}
	}
	return nil
}

// EnforceOn turns the firewall back on if something turned it off. It is
// the only unattended action and it only tightens.
func (e Engine) EnforceOn(ctx context.Context) (Report, bool) {
	out, err := e.Runner.Run(ctx, SocketFilterFW, "--getglobalstate")
	if err != nil {
		return Report{Outcome: OutcomeRefused, Error: "read firewall state: " + err.Error()}, true
	}
	enabled, _, err := parseGlobalState(string(out))
	if err != nil {
		return Report{Outcome: OutcomeRefused, Error: err.Error()}, true
	}
	if enabled {
		return Report{Outcome: OutcomeNoChange}, false
	}
	report := Report{Outcome: OutcomeEnforced}
	result, err := e.run(ctx, fw("--setglobalstate", "on"))
	report.Commands = append(report.Commands, result)
	if err != nil {
		report.Outcome = OutcomeRefused
		report.Error = err.Error()
		return report, true
	}
	out, err = e.Runner.Run(ctx, SocketFilterFW, "--getglobalstate")
	if err == nil {
		enabled, _, err = parseGlobalState(string(out))
	}
	if err != nil || !enabled {
		report.Outcome = OutcomeRefused
		report.Error = "firewall did not read back as enabled"
	}
	return report, true
}

func (e Engine) run(ctx context.Context, argv []string) (CommandResult, error) {
	result := CommandResult{Argv: argv}
	out, err := e.Runner.Run(ctx, argv[0], argv[1:]...)
	result.Output = strings.TrimSpace(string(out))
	if err != nil {
		result.Error = err.Error()
	}
	return result, err
}

func describeSteps(steps []Step) string {
	parts := make([]string, 0, len(steps))
	for _, step := range steps {
		parts = append(parts, strings.TrimSpace(step.Kind+" "+step.Target))
	}
	return strings.Join(parts, ", ")
}
