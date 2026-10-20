// Package netnone plans dedicated Colima runs with network-denied test containers.
package netnone

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Command struct {
	Name      string
	Args, Env []string
	Dir       string
	Stdin     io.Reader
	Timeout   time.Duration
}
type Result struct {
	Stdout, Stderr []byte
	ExitCode       int
}
type Runner interface {
	Run(context.Context, Command) (Result, error)
}

// ExecRunner resolves a fixed vocabulary once, never uses a host shell, and
// bounds both capture and execution. Nonzero process exits remain in Result.
type ExecRunner struct {
	once      sync.Once
	paths     map[string]string
	lookupErr error
}

func (r *ExecRunner) resolve() {
	r.paths = map[string]string{"sysctl": "/usr/sbin/sysctl"}
	for _, name := range []string{"colima", "docker"} {
		p, err := exec.LookPath(name)
		if err != nil {
			r.lookupErr = errors.Join(r.lookupErr, err)
			continue
		}
		p, err = filepath.Abs(p)
		if err != nil {
			r.lookupErr = errors.Join(r.lookupErr, err)
			continue
		}
		r.paths[name] = p
	}
}

var ErrOutputLimit = errors.New("command output limit reached")

type cappedBuffer struct {
	data     []byte
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	const max = 8 << 20
	n := len(p)
	if len(p) > max-len(b.data) {
		p = p[:max-len(b.data)]
		b.exceeded = true
	}
	b.data = append(b.data, p...)
	return n, nil
}
func (r *ExecRunner) Run(ctx context.Context, c Command) (Result, error) {
	r.once.Do(r.resolve)
	p, ok := r.paths[c.Name]
	if !ok {
		return Result{}, fmt.Errorf("unavailable command %q: %w", c.Name, r.lookupErr)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p, c.Args...)
	cmd.Env = c.Env
	cmd.Dir = c.Dir
	cmd.Stdin = c.Stdin
	cmd.WaitDelay = 2 * time.Second
	var stdout, stderr cappedBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{Stdout: stdout.data, Stderr: stderr.data}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if stdout.exceeded || stderr.exceeded {
		return result, ErrOutputLimit
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.ExitCode = exit.ExitCode()
		return result, nil
	}
	return result, err
}
func privateEnv(env []string, home, state string) []string {
	result := []string{}
	for _, e := range env {
		key, _, _ := strings.Cut(e, "=")
		if strings.HasPrefix(key, "DOCKER_") || key == "COLIMA_PROFILE" || key == "COLIMA_HOME" || key == "LIMA_HOME" {
			continue
		}
		result = append(result, e)
	}
	root := filepath.Join(home, ".colima-netnone")
	return append(result, "COLIMA_HOME="+root, "LIMA_HOME="+filepath.Join(root, "_lima"), "DOCKER_HOST=unix://"+filepath.Join(root, "netnone/docker.sock"), "DOCKER_CONFIG="+filepath.Join(state, "docker-config"))
}
