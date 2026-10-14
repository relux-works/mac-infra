package security

import (
	"context"
	"errors"
	"os/exec"
	"time"
)

type CommandEvidence struct {
	Path       string    `json:"path"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   *int      `json:"exit_code"`
	Status     string    `json:"status"`
}
type observedRunner struct {
	Runner
	commands []CommandEvidence
}

func (r *observedRunner) Run(ctx context.Context, path string, args ...string) ([]byte, error) {
	e := CommandEvidence{Path: path, StartedAt: time.Now().UTC(), Status: "ok"}
	data, err := r.Runner.Run(ctx, path, args...)
	e.FinishedAt = time.Now().UTC()
	if err == nil {
		code := 0
		e.ExitCode = &code
	} else {
		e.Status = "unavailable"
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code := exit.ExitCode()
			e.ExitCode = &code
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			e.Status = "interrupted"
		}
		if errors.Is(err, ErrOutputLimit) {
			e.Status = "output_limit"
		}
	}
	r.commands = append(r.commands, e)
	return data, err
}
func Observe(ctx context.Context, r Runner, fn func(context.Context, Runner) Check) Check {
	start := time.Now().UTC()
	obs := &observedRunner{Runner: r, commands: []CommandEvidence{}}
	c := fn(ctx, obs)
	c.StartedAt = start
	c.FinishedAt = time.Now().UTC()
	c.Commands = obs.commands
	return c
}
